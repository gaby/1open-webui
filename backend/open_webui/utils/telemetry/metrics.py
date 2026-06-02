"""OpenTelemetry metrics bootstrap for Open WebUI.

This module initialises a MeterProvider that sends metrics to an OTLP
collector. The collector is responsible for exposing a Prometheus
`/metrics` endpoint – WebUI does **not** expose it directly.

Metrics collected:

* http.server.requests (counter)
* http.server.duration (histogram, milliseconds)
* webui.users.total (observable gauge)
* webui.users.active (observable gauge)
* webui.users.active.today (observable gauge)
* webui.chat.tokens.input (observable gauge)
* webui.chat.tokens.output (observable gauge)
* webui.chat.tokens.total (observable gauge)
* webui.chat.messages.total (observable gauge)

Attributes used: http.method, http.route, http.status_code, model.id, user.id

If you wish to add more attributes (e.g. user-agent) you can, but beware of
high-cardinality label sets. Chat token metrics include user.id observations by
default; set OTEL_METRICS_EXPORT_USER_TOKEN_USAGE=false to export only model.id
observations.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
from base64 import b64encode
from typing import Callable, Dict, Iterable, List, Optional, Union  # noqa: UP035

from fastapi import FastAPI, Request
from open_webui.env import (
    OTEL_METRICS_BASIC_AUTH_PASSWORD,
    OTEL_METRICS_BASIC_AUTH_USERNAME,
    OTEL_METRICS_EXPORT_INTERVAL_MILLIS,
    OTEL_METRICS_EXPORT_USER_TOKEN_USAGE,
    OTEL_METRICS_EXPORTER_OTLP_ENDPOINT,
    OTEL_METRICS_EXPORTER_OTLP_INSECURE,
    OTEL_METRICS_OTLP_SPAN_EXPORTER,
)
from open_webui.models.chat_messages import ChatMessage, _token_columns
from open_webui.models.users import User
from opentelemetry import metrics
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
    OTLPMetricExporter as OTLPHttpMetricExporter,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.metrics.view import View
from opentelemetry.sdk.resources import Resource
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sync DB helpers for OTel gauge callbacks
#
# The OTel Python SDK calls observable-instrument callbacks *synchronously*
# from a background collection thread — async callbacks are NOT supported
# (the SDK does not ``await`` the return value).
#
# Rather than bridging into the async event loop, we run plain synchronous
# SQL queries using the sync engine that is already available at setup time.
# This avoids any cross-thread / cross-loop concerns entirely.
# ---------------------------------------------------------------------------


def _count_total_users(db_engine: Engine) -> Optional[int]:  # noqa: UP045
    """Return the total number of registered users (sync)."""
    with Session(db_engine) as session:
        return session.execute(select(func.count()).select_from(User)).scalar()


def _count_active_users(db_engine: Engine) -> Optional[int]:  # noqa: UP045
    """Return the number of users active within the last 3 minutes (sync)."""
    three_minutes_ago = int(time.time()) - 180
    with Session(db_engine) as session:
        return session.execute(
            select(func.count()).select_from(User).filter(User.last_active_at >= three_minutes_ago)
        ).scalar()


def _count_users_active_today(db_engine: Engine) -> Optional[int]:  # noqa: UP045
    """Return the number of users active since midnight today (sync)."""
    now = int(dt.datetime.now().timestamp())
    today_midnight = now - (now % 86400)
    with Session(db_engine) as session:
        return session.execute(
            select(func.count()).select_from(User).filter(User.last_active_at > today_midnight)
        ).scalar()


CHAT_TOKEN_METRICS = {
    'input_tokens': 'webui.chat.tokens.input',
    'output_tokens': 'webui.chat.tokens.output',
    'total_tokens': 'webui.chat.tokens.total',
    'message_count': 'webui.chat.messages.total',
}


def _select_chat_token_usage(db_engine: Engine, aggregate_column):
    """Return a sync SQL query for assistant-message token usage by an aggregate column."""
    input_tokens, output_tokens = _token_columns(db_engine.dialect.name)

    return (
        select(
            aggregate_column,
            func.coalesce(func.sum(input_tokens), 0).label('input_tokens'),
            func.coalesce(func.sum(output_tokens), 0).label('output_tokens'),
            func.count(ChatMessage.id).label('message_count'),
        )
        .filter(
            ChatMessage.role == 'assistant',
            aggregate_column.isnot(None),
            ChatMessage.usage.isnot(None),
        )
        .group_by(aggregate_column)
    )


def _get_token_usage_by_model(db_engine: Engine):
    """Aggregate assistant-message token usage by model (sync)."""
    with Session(db_engine) as session:
        return session.execute(_select_chat_token_usage(db_engine, ChatMessage.model_id)).all()


def _get_token_usage_by_user(db_engine: Engine):
    """Aggregate assistant-message token usage by user (sync)."""
    with Session(db_engine) as session:
        return session.execute(_select_chat_token_usage(db_engine, ChatMessage.user_id)).all()


def _chat_usage_metric_value(row, metric_key: str) -> int:
    """Return the selected chat-usage metric value for a DB aggregation row."""
    if metric_key == 'total_tokens':
        return row.input_tokens + row.output_tokens

    return getattr(row, metric_key)


def _make_user_count_observer(
    db_engine: Engine,
    count_func: Callable[[Engine], Optional[int]],  # noqa: UP045
    failure_message: str,
) -> Callable[[metrics.CallbackOptions], Iterable[metrics.Observation]]:
    """Build a synchronous observable-gauge callback for a user count."""

    def observe(options: metrics.CallbackOptions) -> Iterable[metrics.Observation]:
        try:
            value = count_func(db_engine)
            if value is not None:
                yield metrics.Observation(value=value)
        except Exception:
            logger.debug(failure_message, exc_info=True)

    return observe


def _make_chat_usage_observer(
    db_engine: Engine,
    metric_key: str,
) -> Callable[[metrics.CallbackOptions], Iterable[metrics.Observation]]:
    """Build a synchronous observable-gauge callback for chat token usage."""

    def observe(options: metrics.CallbackOptions) -> Iterable[metrics.Observation]:
        try:
            for row in _get_token_usage_by_model(db_engine):
                yield metrics.Observation(
                    value=_chat_usage_metric_value(row, metric_key),
                    attributes={'model.id': row.model_id},
                )
        except Exception:
            logger.debug('Failed to observe chat usage by model', exc_info=True)

        if not OTEL_METRICS_EXPORT_USER_TOKEN_USAGE:
            return

        try:
            for row in _get_token_usage_by_user(db_engine):
                yield metrics.Observation(
                    value=_chat_usage_metric_value(row, metric_key),
                    attributes={'user.id': row.user_id},
                )
        except Exception:
            logger.debug('Failed to observe chat usage by user', exc_info=True)

    return observe


def _build_meter_provider(resource: Resource) -> MeterProvider:
    """Return a configured MeterProvider."""
    headers = []
    if OTEL_METRICS_BASIC_AUTH_USERNAME and OTEL_METRICS_BASIC_AUTH_PASSWORD:
        auth_string = f'{OTEL_METRICS_BASIC_AUTH_USERNAME}:{OTEL_METRICS_BASIC_AUTH_PASSWORD}'
        auth_header = b64encode(auth_string.encode()).decode()
        headers = [('authorization', f'Basic {auth_header}')]

    # Periodic reader pushes metrics over OTLP/gRPC to collector
    if OTEL_METRICS_OTLP_SPAN_EXPORTER == 'http':
        readers: List[PeriodicExportingMetricReader] = [  # noqa: UP006
            PeriodicExportingMetricReader(
                OTLPHttpMetricExporter(endpoint=OTEL_METRICS_EXPORTER_OTLP_ENDPOINT, headers=headers),
                export_interval_millis=OTEL_METRICS_EXPORT_INTERVAL_MILLIS,
            )
        ]
    else:
        readers: List[PeriodicExportingMetricReader] = [  # noqa: UP006
            PeriodicExportingMetricReader(
                OTLPMetricExporter(
                    endpoint=OTEL_METRICS_EXPORTER_OTLP_ENDPOINT,
                    insecure=OTEL_METRICS_EXPORTER_OTLP_INSECURE,
                    headers=headers,
                ),
                export_interval_millis=OTEL_METRICS_EXPORT_INTERVAL_MILLIS,
            )
        ]

    # Optional view to limit cardinality: drop user-agent etc.
    views: List[View] = [  # noqa: UP006
        View(
            instrument_name='http.server.duration',
            attribute_keys=['http.method', 'http.route', 'http.status_code'],
        ),
        View(
            instrument_name='http.server.requests',
            attribute_keys=['http.method', 'http.route', 'http.status_code'],
        ),
        View(
            instrument_name='webui.users.total',
        ),
        View(
            instrument_name='webui.users.active',
        ),
        View(
            instrument_name='webui.users.active.today',
        ),
        *(
            View(
                instrument_name=instrument_name,
                attribute_keys=['model.id', 'user.id'],
            )
            for instrument_name in CHAT_TOKEN_METRICS.values()
        ),
    ]

    provider = MeterProvider(
        resource=resource,
        metric_readers=list(readers),
        views=views,
    )
    return provider


def setup_metrics(app: FastAPI, resource: Resource, db_engine: Engine) -> None:
    """Attach OTel metrics middleware to *app* and initialise provider."""

    metrics.set_meter_provider(_build_meter_provider(resource))
    meter = metrics.get_meter(__name__)

    # Instruments
    request_counter = meter.create_counter(
        name='http.server.requests',
        description='Counts the total number of inbound HTTP requests.',
        unit='1',
    )
    duration_histogram = meter.create_histogram(
        name='http.server.duration',
        description='Measures the duration of inbound HTTP requests.',
        unit='ms',
    )

    # -- Observable gauge callbacks ----------------------------------------
    # These are called synchronously by the OTel SDK from a background
    # collection thread.  They use the sync DB engine directly — no async
    # bridging required.

    meter.create_observable_gauge(
        name='webui.users.total',
        description='Total number of registered users',
        unit='users',
        callbacks=[_make_user_count_observer(db_engine, _count_total_users, 'Failed to observe total users')],
    )

    meter.create_observable_gauge(
        name='webui.users.active',
        description='Number of currently active users',
        unit='users',
        callbacks=[_make_user_count_observer(db_engine, _count_active_users, 'Failed to observe active users')],
    )

    meter.create_observable_gauge(
        name='webui.users.active.today',
        description='Number of users active since midnight today',
        unit='users',
        callbacks=[
            _make_user_count_observer(db_engine, _count_users_active_today, 'Failed to observe users active today')
        ],
    )

    for metric_key, instrument_name in CHAT_TOKEN_METRICS.items():
        meter.create_observable_gauge(
            name=instrument_name,
            description='Aggregated assistant chat token and message usage',
            unit='tokens' if metric_key.endswith('tokens') else 'messages',
            callbacks=[_make_chat_usage_observer(db_engine, metric_key)],
        )

    # FastAPI middleware
    @app.middleware('http')
    async def _metrics_middleware(request: Request, call_next):
        start_time = time.perf_counter()

        status_code = None
        try:
            response = await call_next(request)
            status_code = getattr(response, 'status_code', 500)
            return response
        except Exception:
            status_code = 500
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Route template e.g. "/items/{item_id}" instead of real path.
            route = request.scope.get('route')
            route_path = getattr(route, 'path', request.url.path)

            attrs: Dict[str, Union[str, int]] = {  # noqa: UP006, UP007
                'http.method': request.method,
                'http.route': route_path,
                'http.status_code': status_code,
            }

            request_counter.add(1, attrs)
            duration_histogram.record(elapsed_ms, attrs)
