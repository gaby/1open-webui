import json
import logging
import sys
import traceback
from typing import TYPE_CHECKING

from loguru import logger
from open_webui.env import (
    _LEVEL_MAP,
    AUDIT_LOG_ENQUEUE,
    AUDIT_LOG_FILE_RETENTION,
    AUDIT_LOG_FILE_ROTATION_SIZE,
    AUDIT_LOG_LEVEL,
    AUDIT_LOG_STRICT,
    AUDIT_LOGS_FILE_PATH,
    AUDIT_UVICORN_LOGGER_NAMES,
    ENABLE_AUDIT_LOGS_FILE,
    ENABLE_AUDIT_STDOUT,
    ENABLE_OTEL,
    ENABLE_OTEL_LOGS,
    GLOBAL_LOG_LEVEL,
    LOG_FORMAT,
    LOGURU_DIAGNOSE,
)
from open_webui.utils.json_codec import JSONCodec

if TYPE_CHECKING:
    from loguru import Message, Record


# Both formatters stash their serialized payload back onto `extra` to interpolate
# it. These scratch keys are not audit fields and must never be emitted — nor
# serialized into each other, which would nest a full copy of every record.
_STDOUT_EXTRA_KEY = 'extra_json'
_FILE_EXTRA_KEY = 'file_extra'
# `auditable` is Loguru's binding marker, and joins them as the only other key
# on an audit record that is not one of the entry's own fields.
_NON_AUDIT_EXTRA_KEYS = frozenset({'auditable', _STDOUT_EXTRA_KEY, _FILE_EXTRA_KEY})


def stdout_format(record: 'Record') -> str:
    """
    Generates a formatted string for log records that are output to the console. This format includes a timestamp, log level, source location (module, function, and line), the log message, and any extra data (serialized as JSON).

    Parameters:
    record (Record): A Loguru record that contains logging details including time, level, name, function, line, message, and any extra context.
    Returns:
    str: A formatted log string intended for stdout.
    """
    if record['extra']:
        payload = {key: value for key, value in record['extra'].items() if key not in _NON_AUDIT_EXTRA_KEYS}
        record['extra'][_STDOUT_EXTRA_KEY] = JSONCodec.dumps(payload)
        extra_format = ' - {extra[extra_json]}'
    else:
        extra_format = ''
    return (
        '<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | '
        '<level>{level: <8}</level> | '
        '<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - '
        '<level>{message}</level>' + extra_format + '\n{exception}'
    )


def _write_json_record(message: 'Message') -> None:
    """Write one log record as a single line of JSON to stdout.

    Raises on failure. `_json_sink` wraps this for ordinary application logs;
    strict audit sinks use it directly so a broken stdout is not swallowed.
    """
    record = message.record
    log_entry = {
        'ts': record['time'].isoformat(timespec='milliseconds'),
        'level': _LEVEL_MAP.get(record['level'].name, record['level'].name.lower()),
        'msg': record['message'],
        'caller': f'{record["name"]}:{record["function"]}:{record["line"]}',
    }

    if record['extra']:
        log_entry['extra'] = record['extra']

    exc = record['exception']
    if exc is not None:
        log_entry['error'] = {
            'type': exc.type.__name__ if exc.type else None,
            'message': str(exc.value) if exc.value else None,
            'stacktrace': ''.join(traceback.format_exception(exc.type, exc.value, exc.traceback)).rstrip(),
        }

    sys.stdout.write(json.dumps(log_entry, ensure_ascii=False, default=str) + '\n')
    sys.stdout.flush()


def _json_sink(message: 'Message') -> None:
    """Write log records as single-line JSON to stdout.

    Used as a Loguru sink when LOG_FORMAT is set to "json".
    """
    try:
        _write_json_record(message)
    except Exception:
        # Last-resort fallback: never let a logging failure crash the application.
        # Emit a minimal valid JSON line so the structured logging pipeline stays intact.
        try:
            fallback = {
                'ts': message.record['time'].isoformat(timespec='milliseconds'),
                'level': 'error',
                'msg': f'[logging error] failed to serialize log record: {message}',
            }
            sys.stdout.write(json.dumps(fallback, ensure_ascii=False, default=str) + '\n')
            sys.stdout.flush()
        except Exception:
            sys.stderr.write(f'[logging error] _json_sink failed: {message}\n')
            sys.stderr.flush()


class InterceptHandler(logging.Handler):
    """
    Intercepts log records from Python's standard logging module
    and redirects them to Loguru's logger.
    """

    def emit(self, record):
        """
        Called by the standard logging module for each log event.
        It transforms the standard `LogRecord` into a format compatible with Loguru
        and passes it to Loguru's logger.
        """
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = sys._getframe(6), 6
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        message = record.getMessage()
        logger.opt(depth=depth, exception=record.exc_info).bind(**self._get_extras()).log(level, message)
        if ENABLE_OTEL and ENABLE_OTEL_LOGS:
            from open_webui.utils.telemetry.logs import otel_handler

            # reuse the message we built so %-args format once; a non-str msg is left alone, otel exports it structured
            if isinstance(record.msg, str):
                record.msg, record.args = message, None
            otel_handler.emit(record)

    def _get_extras(self):
        if not ENABLE_OTEL:
            return {}

        from opentelemetry import trace

        extras = {}
        context = trace.get_current_span().get_span_context()
        if context.is_valid:
            extras['trace_id'] = trace.format_trace_id(context.trace_id)
            extras['span_id'] = trace.format_span_id(context.span_id)
        return extras


def file_format(record: 'Record'):
    """
    Formats audit log records into a structured JSON string for file output.

    Parameters:
    record (Record): A Loguru record containing extra audit data.
    Returns:
    str: A JSON-formatted string representing the audit data.
    """

    extra = record['extra']

    # Emit every field the entry carries rather than a hand-maintained allowlist,
    # which had already dropped `error_truncated` — a shortened error reached the
    # file reading as complete. `_NON_AUDIT_EXTRA_KEYS` covers the rest.
    audit_data = {'timestamp': int(record['time'].timestamp())}
    audit_data.update({key: value for key, value in extra.items() if key not in _NON_AUDIT_EXTRA_KEYS})
    audit_data.setdefault('extra', {})

    # `default=str` keeps an exotic value from raising here: a formatter that
    # raises loses the record, and an audit record is not allowed to be lost.
    extra[_FILE_EXTRA_KEY] = json.dumps(audit_data, default=str)
    return '{extra[file_extra]}\n'


def _is_auditable(record) -> bool:
    return record['extra'].get('auditable') is True


def _not_auditable(record) -> bool:
    return not _is_auditable(record)


def _assert_strict_audit_is_possible():
    """Refuse to start when AUDIT_LOG_STRICT cannot mean anything.

    Strict mode promises no audit event goes missing. Two configurations make
    that promise vacuous rather than strict, so both are rejected up front:
    an unrecognised level, and NONE — `main.py` omits AuditLoggingMiddleware in
    either case, leaving the process running with strict guarantees over an
    empty trail.
    """
    # Imported here so the module graph stays acyclic; by the time this runs
    # (from the lifespan) everything is loaded anyway.
    from open_webui.utils.audit import AuditLevel

    try:
        level = AuditLevel(AUDIT_LOG_LEVEL)
    except ValueError as e:
        raise RuntimeError(
            f'AUDIT_LOG_STRICT is enabled but AUDIT_LOG_LEVEL={AUDIT_LOG_LEVEL!r} is not a valid level, '
            f'which leaves the audit middleware uninstalled and nothing recorded.'
        ) from e

    if level == AuditLevel.NONE:
        raise RuntimeError(
            'AUDIT_LOG_STRICT is enabled but AUDIT_LOG_LEVEL is NONE, which records nothing. '
            'Set AUDIT_LOG_LEVEL to METADATA, REQUEST or REQUEST_RESPONSE, or disable AUDIT_LOG_STRICT.'
        )


def _add_audit_sinks():
    """Register the sinks that carry audit records.

    Audit records never share the application sink. They are emitted at INFO and
    used to be dropped whenever GLOBAL_LOG_LEVEL was raised above it, so
    ENABLE_AUDIT_STDOUT gets its own sink pinned to INFO instead.
    """
    if AUDIT_LOG_STRICT:
        _assert_strict_audit_is_possible()

    if AUDIT_LOG_LEVEL == 'NONE':
        # Nothing emits auditable records at this level, so there is nothing to sink.
        return

    if AUDIT_LOG_STRICT and not ENABLE_AUDIT_STDOUT and not ENABLE_AUDIT_LOGS_FILE:
        # `_not_auditable` keeps audit records off the application sink, so there
        # is no fallback destination: booting with nowhere to put them is exactly
        # the failure strict mode prevents.
        raise RuntimeError(
            'AUDIT_LOG_STRICT is enabled but no audit destination is: '
            'enable ENABLE_AUDIT_LOGS_FILE or ENABLE_AUDIT_STDOUT.'
        )

    if ENABLE_AUDIT_STDOUT:
        # Propagate write failures like the file sink: bypass `_json_sink`'s own
        # swallow as well as Loguru's `catch`, or a broken stdout leaves a strict
        # deployment serving with its only audit destination dead.
        catch = not AUDIT_LOG_STRICT
        if LOG_FORMAT == 'json':
            logger.add(
                _write_json_record if AUDIT_LOG_STRICT else _json_sink,
                level='INFO',
                filter=_is_auditable,
                diagnose=LOGURU_DIAGNOSE,
                catch=catch,
            )
        else:
            logger.add(
                sys.stdout,
                level='INFO',
                format=stdout_format,
                filter=_is_auditable,
                diagnose=LOGURU_DIAGNOSE,
                catch=catch,
            )

    if not ENABLE_AUDIT_LOGS_FILE:
        return

    # Loguru's queued writer catches sink exceptions unconditionally, never
    # consulting `catch`, so strict mode needs the write inline and overrides an
    # explicit AUDIT_LOG_ENQUEUE.
    enqueue = AUDIT_LOG_ENQUEUE and not AUDIT_LOG_STRICT
    if AUDIT_LOG_ENQUEUE and AUDIT_LOG_STRICT:
        logger.warning('AUDIT_LOG_ENQUEUE is ignored while AUDIT_LOG_STRICT is enabled; writing audit records inline.')

    try:
        logger.add(
            AUDIT_LOGS_FILE_PATH,
            level='INFO',
            rotation=AUDIT_LOG_FILE_ROTATION_SIZE,
            retention=AUDIT_LOG_FILE_RETENTION,
            compression='zip',
            format=file_format,
            filter=_is_auditable,
            diagnose=LOGURU_DIAGNOSE,
            # Disk write and rotation-time zip move off the event loop thread;
            # stop_logger() drains what is buffered on shutdown.
            enqueue=enqueue,
            # In strict mode a failed audit write must surface to the caller
            # instead of being swallowed by Loguru's own error handling.
            catch=not AUDIT_LOG_STRICT,
        )
    except Exception as e:
        if AUDIT_LOG_STRICT:
            # Running with auditing configured but no audit sink is exactly the
            # silent-loss failure strict mode exists to prevent.
            raise RuntimeError(
                f'AUDIT_LOG_STRICT is enabled but the audit log file handler could not be initialized: {e}'
            ) from e
        logger.error(f'Failed to initialize audit log file handler: {str(e)}')


def start_logger():
    """
    Initializes and configures Loguru's logger with distinct handlers:

    A console (stdout) handler for general log messages (excluding those marked as auditable).
    An optional file handler for audit logs if audit logging is enabled.
    Additionally, this function reconfigures Python’s standard logging to route through Loguru and adjusts logging levels for Uvicorn.

    Parameters:
    enable_audit_logging (bool): Determines whether audit-specific log entries should be recorded to file.
    """
    logger.remove()

    if LOG_FORMAT == 'json':
        logger.add(
            _json_sink,
            level=GLOBAL_LOG_LEVEL,
            filter=_not_auditable,
            diagnose=LOGURU_DIAGNOSE,
        )
    else:
        logger.add(
            sys.stdout,
            level=GLOBAL_LOG_LEVEL,
            format=stdout_format,
            filter=_not_auditable,
            diagnose=LOGURU_DIAGNOSE,
        )

    _add_audit_sinks()

    logging.basicConfig(handlers=[InterceptHandler()], level=GLOBAL_LOG_LEVEL, force=True)

    for uvicorn_logger_name in ['uvicorn', 'uvicorn.error']:
        uvicorn_logger = logging.getLogger(uvicorn_logger_name)
        uvicorn_logger.setLevel(GLOBAL_LOG_LEVEL)
        uvicorn_logger.handlers = []

    for uvicorn_logger_name in AUDIT_UVICORN_LOGGER_NAMES:
        uvicorn_logger = logging.getLogger(uvicorn_logger_name)
        uvicorn_logger.setLevel(GLOBAL_LOG_LEVEL)
        uvicorn_logger.handlers = [InterceptHandler()]

    logger.info(f'GLOBAL_LOG_LEVEL: {GLOBAL_LOG_LEVEL}')


async def stop_logger():
    """Flush every sink before the process goes away.

    With `AUDIT_LOG_ENQUEUE` the audit sink hands records to a background
    writer; without this drain, records still sitting in that queue at shutdown
    are lost. Safe to call when nothing is enqueued.
    """
    try:
        await logger.complete()
    except Exception as e:
        sys.stderr.write(f'[logging error] failed to flush log sinks on shutdown: {e}\n')
        sys.stderr.flush()
