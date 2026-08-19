import json
import re
import sys
import time
import uuid
from urllib.parse import quote_plus, unquote_plus
from dataclasses import dataclass, fields
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    MutableMapping,
    Optional,
    cast,
)

from asgiref.typing import (
    ASGI3Application,
    ASGIReceiveCallable,
    ASGIReceiveEvent,
    ASGISendCallable,
    ASGISendEvent,
)
from asgiref.typing import (
    Scope as ASGIScope,
)
from loguru import logger
from open_webui.env import (
    AUDIT_LOG_LEVEL,
    AUDIT_LOG_STRICT,
    ENABLE_AUDIT_UNAUTHENTICATED_REQUESTS,
    ENABLE_AUDIT_USAGE,
    MAX_BODY_LOG_SIZE,
)
from open_webui.models.users import UserModel
from open_webui.utils.auth import decode_token
from open_webui.utils.json_codec import JSONCodec
from open_webui.utils.response import USAGE_SUMMABLE_KEYS, merge_usage, normalize_usage
from starlette.requests import Request

if TYPE_CHECKING:
    from loguru import Logger


REDACTED = '********'

# `token` is the one sensitive word that is also ordinary vocabulary: blanking `max_tokens` or
# `prompt_tokens` corrupts the numbers this trail exists to record.
_TOKEN_KEY_PATTERN = re.compile(r'(?:^|[_\-])tokens?(?:[_\-]|$)', re.IGNORECASE)
# An allowlist of shapes known to be counts, not a blanket "plural means metric": `access_tokens`,
# `refresh_tokens` and `api_tokens` are credentials that happen to be plural.
_TOKEN_METRIC_KEY_PATTERN = re.compile(
    r'^(?:'
    r'tokens'
    # `token_<what-about-tokens>`: counts, limits and configuration such as
    # `token_cap`, `token_endpoint`, `token_type`, `compact_token_threshold`.
    r'|(?:\w+[_-])?tokens?[_-](?:count|limit|usage|size|length|threshold|cap|budget|window'
    r'|type|endpoint|method|scope|model|encoding|name|expiry|ttl|lifetime|ratio|per)'
    r'(?:[_-][A-Za-z0-9]+)*'
    # `<what-is-counted>_tokens`: the usage payload's own field names.
    r'|(?:\w+[_-])?(?:max|min|num|n|total|input|output|prompt|completion|cached|reasoning'
    r'|eval|used|remaining|context|new|estimated|audio|text|image|peak|daily'
    r'|accepted[_-]prediction|rejected[_-]prediction)[_-]tokens(?:[_-]details)?'
    r'|max(?:imum)?[_-](?:number[_-]of[_-])?tokens'
    r')$',
    re.IGNORECASE,
)
# Whole-key credentials. Matched whole so `auth_type`, `sig_alg` and ordinary
# `*key` names are not swept up.
_SENSITIVE_EXACT_KEYS = frozenset({'key', 'keys', 'auth', 'cookie', 'set-cookie', 'sig'})
# Names that are credentials only as protocol parameters.
_SENSITIVE_PROTOCOL_KEYS = frozenset(
    {'code', 'state', 'session_state', 'id_token_hint', 'client_assertion', 'device_code'}
)
# Any name ending in `key`/`sk` after a separator.
_CREDENTIAL_KEY_SUFFIX_PATTERN = re.compile(r'[_\-](?:keys?|sk)$', re.IGNORECASE)
# These words admit no metric exception: `secret_tokens` is still redacted.
_UNCONDITIONAL_SENSITIVE_KEY_PATTERN = re.compile(
    r'password|passwd|secret|api[_-]?key|api[_-]?auth|credential|authorization|private[_-]?key|signature',
    re.IGNORECASE,
)
# Names the rules above match on a substring but that name a *location*, not a
# credential — `authorization_endpoint` is a public RFC 8414 discovery field.
_LOCATION_KEY_PATTERN = re.compile(
    r'^(?:\w+[_-])?(?:authorization|token|registration|revocation|introspection|userinfo|jwks)'
    r'[_-](?:endpoint|url|uri|endpoints|urls|uris)(?:[_-][A-Za-z0-9]+)*$',
    re.IGNORECASE,
)


# Every rule below is written in `_`/`-` separated words, so a camelCase name is normalised once
# rather than spelled twice: `maxTokens` becomes `max_Tokens`.
_CAMEL_BOUNDARY_PATTERN = re.compile(r'(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')


def _split_camel_case(key: str) -> str:
    return _CAMEL_BOUNDARY_PATTERN.sub('_', key)


def _decode_json_key(key: str) -> str:
    """The key as a JSON parser would spell it.

    `_JSON_KEY_PATTERN` matches raw source text, so an escaped name reaches the
    predicate spelled differently from the field it names: `Authoriz\\u0061tion`
    is a valid way to write `Authorization`, and `POST /api/v1/configs/tool_servers`
    takes exactly such a name in its `headers` dictionary. Decoding first keeps
    the textual fallback agreeing with the structural pass, which only ever sees
    keys a JSON parser has already unescaped.
    """
    if '\\' not in key:
        return key
    try:
        decoded = json.loads(f'"{key}"')
    except Exception:
        return key
    return decoded if isinstance(decoded, str) else key


def _is_sensitive_key(key: str) -> bool:
    normalized = _split_camel_case(key.strip())
    if _LOCATION_KEY_PATTERN.match(normalized):
        return False
    if normalized.lower() in _SENSITIVE_EXACT_KEYS:
        return True
    if _CREDENTIAL_KEY_SUFFIX_PATTERN.search(normalized):
        return True
    if _UNCONDITIONAL_SENSITIVE_KEY_PATTERN.search(normalized):
        return True
    return bool(_TOKEN_KEY_PATTERN.search(normalized)) and not _TOKEN_METRIC_KEY_PATTERN.search(normalized)


# Every `"key":` in the text, sensitive or not — never its value, since consuming that would skip
# the pairs nested inside it.
_JSON_KEY_PATTERN = re.compile(r'"((?:[^"\\]|\\.)*)"\s*:\s*' r"|'((?:[^'\\]|\\.)*)'\s*:\s*")

# `a=1&b=2` text: query strings and form bodies, which no structural pass sees.
_ENCODED_PAIR_PATTERN = re.compile(r'(^|[?&\s])([^?&=#\s]+)(=)([^&#\s]*)')
# Credentials written as prose — `Authorization: Bearer …`, `api_key: LIVE` — which reach an audited
# body when a client echoes its headers into an error.
_COLON_PAIR_PATTERN = re.compile(r'(?:^|(?<=[\s,;(\[{"\']))([A-Za-z][A-Za-z0-9_-]*)[ \t]*:[ \t]*')
# Credentials in the path: `POST /channels/webhooks/{id}/{token}` authenticates on its final segment
# alone.
_SENSITIVE_PATH_PATTERN = re.compile(r'(/channels/webhooks/[^/?#]+/)[^/?#]+(?=/?(?:$|[?#]))', re.IGNORECASE)
# Where `_SENSITIVE_PROTOCOL_KEYS` applies.
_OAUTH_PATH_PATTERN = re.compile(r'(?:^|/)oauth\d?(?:/|$)', re.IGNORECASE)


def _is_oauth_path(path: Optional[str]) -> bool:
    return bool(path) and bool(_OAUTH_PATH_PATTERN.search(path))


# A multipart body identifies itself (RFC 2046), so the boundary is recoverable
# from the bytes alone without the content type this redactor never gets.
_MULTIPART_OPENING_PATTERN = re.compile(r'--([^\r\n]{1,70})\r?\n')
# `python_multipart` accepts both the quoted and bare-token spellings of `name`,
# so matching only the quoted one would leave a whole serialization unredacted.
_MULTIPART_NAME_PATTERN = re.compile(
    r'content-disposition:[^\r\n]*?[;\s]name\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;,"\s]+))',
    re.IGNORECASE,
)


# Webhooks whose credential is the URL itself rather than a header, echoed under the ordinary name
# `url`.
_CREDENTIAL_URL_PATTERNS = (
    # Slack `https://hooks.slack.com/services/T…/B…/<secret>`, and the `/workflows/` variant, which
    # has a fourth segment.
    re.compile(r'(https://hooks\.slack\.com/[\w-]+/[^/?#\s"\'\\]+/)[^\s"\'\\]+', re.IGNORECASE),
    # Discord `https://discord.com/api/webhooks/<id>/<token>`.
    re.compile(r'(https://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks/[^/?#\s"\'\\]+/)[^\s"\'\\]+', re.IGNORECASE),
    # Teams `https://<tenant>.webhook.office.com/webhookb2/…/IncomingWebhook/<hash>/<guid>`.
    re.compile(r'(https://[^/?#\s"\'\\]*webhook\.office\.com/\S*?/IncomingWebhook/)[^\s"\'\\]+', re.IGNORECASE),
)
# `https://user:password@host/…`. Not provider-specific: any URL can carry a
# credential this way, and none of them should record it.
_URL_USERINFO_PATTERN = re.compile(r'(://)[^/?#\s"\'\\@]+(@)')
# The same credential with the `@` on the far side of a cut: bodies are bounded before they are
# redacted, so `postgresql://user:LIVE` can end the text.
_URL_USERINFO_CUT_PATTERN = re.compile(r'(://)[^/?#\s"\'\\@]*:[^/?#\s"\'\\@]*$')
# A URL embedded in text.
_URL_PATTERN = re.compile(r'(?:https?|wss?):(?:\\?/){2}(?:[^\s"\'<>\\]|\\/)+', re.IGNORECASE)


# Keys whose value is a webhook URL.
_WEBHOOK_URL_KEY_PATTERN = re.compile(r'(?:^|[_\-.])webhooks?[_\-]?urls?$', re.IGNORECASE)
_WEBHOOK_ROUTE_PATTERN = re.compile(r'/events/webhooks(?:/|$)', re.IGNORECASE)
# Keys whose value *contains* webhooks rather than being one: `events.webhooks` is a list of records
# each naming its endpoint with a bare `url`.
_WEBHOOK_CONTAINER_KEY_PATTERN = re.compile(r'(?:^|[_\-.])webhooks?$', re.IGNORECASE)
# The container name in unparsed source: a cut body has no structure to descend,
# so finding it anywhere turns the rule on for the whole text.
_WEBHOOK_CONTAINER_TEXT_PATTERN = re.compile(r'["\'][\w.\-]*webhooks?["\']\s*:', re.IGNORECASE)


def _is_webhook_container_key(key: str) -> bool:
    return bool(_WEBHOOK_CONTAINER_KEY_PATTERN.search(_split_camel_case(key.strip())))


def _is_webhook_url_key(key: str, webhook_route: bool) -> bool:
    normalized = _split_camel_case(key.strip())
    return bool(_WEBHOOK_URL_KEY_PATTERN.search(normalized)) or (webhook_route and normalized.lower() == 'url')


# Operator-configured header maps carry any auth scheme their upstream asks for, so the set of
# credential-bearing names is open and enumerating it always loses.
_HEADER_MAP_KEY_PATTERN = re.compile(r'(?:^|[_\-.])headers?$', re.IGNORECASE)


def _is_header_map_key(key: str) -> bool:
    return bool(_HEADER_MAP_KEY_PATTERN.search(_split_camel_case(key.strip())))


def _redact_webhook_host(origin: str) -> str:
    """Keep the domain a webhook host belongs to and drop the rest of it.

    A per-webhook capability has to be unique per webhook, so in a hostname it
    can only live in a subdomain label — an ngrok tunnel is
    `https://<random>.ngrok-free.app/hook`, and a relay is free to do the same
    with a secret. Nobody registers a domain per webhook, so the last two
    labels are the provider and the labels in front of them are the capability.

    Keeping the domain is what makes the record useful: an auditor learns which
    service an admin wired the integration to, which is exactly the metadata a
    whole-value mask destroys.
    """
    host, colon, port = origin.partition(':')
    labels = host.split('.')
    if len(labels) <= 2:
        return origin
    return f'{REDACTED}.{".".join(labels[-2:])}{colon}{port}'


def _redact_webhook_url(value: Any) -> Any:
    """Mask everything a webhook URL can carry a capability in.

    For a webhook the URL *is* the credential, and every part of it after the
    scheme can hold one: the path, the query, and — since the host is free-form
    too — a subdomain label. The domain survives, because which service an
    integration points at is the metadata this record exists to carry and it
    cannot be a per-webhook secret; everything else goes.
    """
    if not isinstance(value, str):
        return _redact_value(value)
    if '://' not in value:
        return REDACTED if value else value

    scheme, separator, rest = value.partition('://')
    origin_end = len(rest)
    for char in '/?#':
        index = rest.find(char)
        if index != -1:
            origin_end = min(origin_end, index)
    if origin_end >= len(rest):
        # Origin only.
        return REDACTED
    return f'{scheme}{separator}{_redact_webhook_host(rest[:origin_end])}/{REDACTED}'


def _redact_url_credentials(url: str) -> str:
    """Mask the credentials a URL carries in its userinfo or its path.

    Split out from `_redact_url` so `_redact_uri` can apply it to a request URI
    without re-running the query pass that has already handled the query.
    """
    url = _URL_USERINFO_PATTERN.sub(rf'\g<1>{REDACTED}\g<2>', url)
    for pattern in _CREDENTIAL_URL_PATTERNS:
        url = pattern.sub(rf'\g<1>{REDACTED}', url)
    return url


# A URL value can itself carry a URL value.
_MAX_NESTED_URL_DEPTH = 4


def _redact_url(url: str, depth: int = 0) -> str:
    # `\/` and `/` are the same character to a JSON reader, so the two spellings are folded before
    # matching.
    url = _redact_url_credentials(url.replace('\\/', '/'))
    base, separator, query = url.partition('?')
    if not separator:
        return base
    # Decided by the URL being redacted, not the request carrying it: the terminal proxy forwards an
    # encoded callback URL whose `code` is still live.
    return base + separator + _redact_encoded_pairs(query, protocol_keys=_is_oauth_path(base), depth=depth)


def _redact_nested_url_value(value: str, depth: int = 0) -> str:
    """Mask a credential inside a URL that is itself a query or form value.

    `?url=https%3A%2F%2Fuser%3Apassword%40host` names an ordinary key, so the
    key predicate has nothing to say about it, and percent-encoding hides the
    URL from the value-level pass as well. The terminal proxy forwards these
    parameters verbatim to the upstream service, where the value is decoded and
    usable, so the credential is live.

    The decoded URL goes through the full `_redact_url`, not just the
    userinfo-and-path pass: a nested URL's own query string carries credentials
    exactly as an outer one does — Google Chat's webhook puts them in `?key=`
    and `?token=` — and there is no reason for the rule to weaken by one level
    of nesting.

    A value that had to be decoded is re-encoded, so the query it sits in keeps
    its structure; one that was already plain is returned plain.
    """
    decoded = unquote_plus(value)
    if '://' not in decoded:
        return value
    if depth >= _MAX_NESTED_URL_DEPTH:
        # The bound exists to stop the recursion, not to stop the redaction.
        return REDACTED
    redacted = _redact_url(decoded, depth + 1)
    if redacted == decoded:
        return value
    return quote_plus(redacted) if decoded != value else redacted


def _redact_credential_urls(text: str, complete: bool = True) -> str:
    """Mask credentials carried inside URL *values*, wherever they appear.

    Applied to the finished text rather than per value, so one pass covers
    request bodies, response bodies, form fields and exception messages alike,
    and no caller can be the one that forgets.
    """
    if '//' not in text and '\\/\\/' not in text:
        return text
    # Over the whole text, not just the schemes `_URL_PATTERN` knows: userinfo
    # belongs to the URL grammar, and pgvector stores DSNs under ordinary keys.
    text = _URL_USERINFO_PATTERN.sub(rf'\g<1>{REDACTED}\g<2>', text)
    if not complete:
        text = _URL_USERINFO_CUT_PATTERN.sub(rf'\g<1>{REDACTED}', text)
    return _URL_PATTERN.sub(lambda match: _redact_url(match.group(0)), text)


def _redact_value(value: Any) -> Any:
    """Mask a value found under a sensitive key, preserving its shape.

    Booleans and nulls are kept: they cannot carry a secret, and blanking them
    would hide whether a flag such as `ENABLE_API_KEY` was being turned on or
    off.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    return REDACTED


def _redact_structure(node: Any, webhook_route: bool = False, protocol_keys: bool = False) -> Any:
    if isinstance(node, dict):
        return {key: _redact_structure_value(key, value, webhook_route, protocol_keys) for key, value in node.items()}
    if isinstance(node, list):
        return [_redact_structure(item, webhook_route, protocol_keys) for item in node]
    if isinstance(node, str):
        # A credential can sit inside a string rather than under a key of its own,
        # so a body that parses is no weaker than the textual fallback.
        node = _redact_free_text(node, protocol_keys=protocol_keys, webhook_route=webhook_route)
    return node


def _redact_structure_value(key: Any, value: Any, webhook_route: bool, protocol_keys: bool = False) -> Any:
    if isinstance(key, str):
        if _is_sensitive_key(key):
            return _redact_value(value)
        if _is_webhook_url_key(key, webhook_route):
            return _redact_webhook_url(value)
        if _is_header_map_key(key):
            return _redact_value(value)
        if _is_webhook_container_key(key):
            if isinstance(value, str):
                # `webhook: "https://…"` — the container name on a scalar means
                # the value is the endpoint itself, not a container of them.
                return _redact_webhook_url(value)
            # Everything under here is a webhook record, so its bare `url` is an endpoint.
            webhook_route = True
    return _redact_structure(value, webhook_route, protocol_keys)


def _redact_encoded_pairs(
    text: str, *, protocol_keys: bool = False, depth: int = 0, webhook_route: bool = False
) -> str:
    """Mask sensitive values in `a=1&b=2` text — query strings and form bodies.

    Keys are percent-decoded before the sensitivity test, so an encoded name like
    `api%5Fkey` cannot slip past, and only the matched value is rewritten, so
    every untouched pair keeps its original encoding.

    `protocol_keys` additionally masks the OAuth parameter names, and is set only
    on OAuth routes — see `_OAUTH_PATH_PATTERN`.
    """

    def mask(match: 're.Match') -> str:
        separator, key, equals, value = match.groups()
        if not value:
            return match.group(0)
        decoded = unquote_plus(key).strip()
        if protocol_keys and decoded.lower() in _SENSITIVE_PROTOCOL_KEYS:
            return f'{separator}{key}{equals}{REDACTED}'
        if _is_webhook_url_key(decoded, webhook_route):
            # The same rule the structural pass applies, on the same key: the path is the
            # credential, the origin is the metadata.
            masked = _redact_webhook_url(unquote_plus(value))
            if masked == unquote_plus(value):
                return match.group(0)
            return f'{separator}{key}{equals}{quote_plus(masked)}'
        if not _is_sensitive_key(decoded):
            # The name is ordinary, but the value may be a URL carrying a
            # credential of its own.
            nested = _redact_nested_url_value(value, depth)
            return match.group(0) if nested == value else f'{separator}{key}{equals}{nested}'
        return f'{separator}{key}{equals}{REDACTED}'

    return _ENCODED_PAIR_PATTERN.sub(mask, text)


def _colon_value_end(text: str, start: int) -> int:
    """Index just past the value of a `Name: value` pair beginning at `start`.

    A header value runs to the end of its line, and inside a JSON string leaf it
    runs to the closing quote. A backslash ends it too: it is the escape of that
    closing quote, and consuming it would leave the quote unescaped and corrupt
    a body the redactor is only meant to mask.

    Unless the value *opens* with a quote, which is how a client library prints
    the headers it sent — `Authorization: "Bearer …"`, and `Authorization:
    \\"Bearer …\\"` once that message is embedded in a JSON string. Then the quote
    is the start of the value rather than the end of it, and stopping there left
    the credential in the record: the run was empty, so there was nothing to
    mask.
    """
    if start < len(text):
        if text[start] in '"\'':
            return _json_value_end(text, start)
        # The same value, escaped, as it appears in unparsed JSON source.
        for quote in ('\\"', "\\'"):
            if text.startswith(quote, start):
                closing = text.find(quote, start + 2)
                return closing + 2 if closing != -1 else len(text)

    index = start
    while index < len(text) and text[index] not in '\r\n"\'\\':
        index += 1
    return index


def _redact_colon_pairs(text: str) -> str:
    """Mask `Name: value` credentials carried as prose rather than as fields.

    The same predicate as everywhere else decides which names are credentials,
    so this pass cannot drift from the structural one. A name that is not
    sensitive is stepped over rather than consumed, which is what lets a pair
    nested behind an ordinary one — `error: Authorization: Bearer …` — still be
    reached.
    """
    result: list[str] = []
    position = 0

    for match in _COLON_PAIR_PATTERN.finditer(text):
        if match.start() < position:
            # Inside a value that has already been masked.
            continue
        if not _is_sensitive_key(match.group(1)):
            continue
        end = _colon_value_end(text, match.end())
        if end <= match.end():
            # `Authorization:` with nothing after it — a header name on its own
            # is metadata, and there is no value to hide.
            continue
        result.append(text[position : match.end()])
        result.append(REDACTED)
        position = end

    if not result:
        return text

    result.append(text[position:])
    return ''.join(result)


def _redact_free_text(text: str, *, protocol_keys: bool = False, webhook_route: bool = False) -> str:
    """The passes that apply to text carrying no structure of its own.

    One definition, because the two callers kept drifting: text reached through
    the multipart branch used to get the URL pass alone, which knows the HTTP
    and WebSocket schemes — so a `postgresql://host/db?password=…` submitted as
    a form part kept its password while the identical string in a JSON body was
    masked.
    """
    if '=' in text:
        text = _redact_encoded_pairs(text, protocol_keys=protocol_keys, webhook_route=webhook_route)
    if ':' in text:
        text = _redact_colon_pairs(text)
    return text


def _balanced_end(text: str, start: int, opening: str) -> int:
    """Index just past the balanced `{...}` or `[...]` beginning at `start`."""
    closing = '}' if opening == '{' else ']'
    depth, in_string, escaped = 0, False, False

    for index in range(start, len(text)):
        current = text[index]
        if escaped:
            escaped = False
        elif current == '\\':
            escaped = True
        elif current == '"':
            in_string = not in_string
        elif not in_string:
            if current == opening:
                depth += 1
            elif current == closing:
                depth -= 1
                if depth == 0:
                    return index + 1

    return len(text)


def _json_value_end(text: str, start: int) -> int:
    """Index just past the JSON value starting at `start`.

    Returns the end of the text for a value the body was truncated in the middle
    of, so a cut-off credential is masked to the end rather than left dangling.
    """
    if start >= len(text):
        return len(text)

    char = text[start]

    if char in '"\'':
        index = start + 1
        while index < len(text):
            if text[index] == '\\':
                index += 2
                continue
            if text[index] == char:
                return index + 1
            index += 1
        return len(text)

    if char in '{[':
        return _balanced_end(text, start, char)

    index = start
    while index < len(text) and text[index] not in ',}]\n\r\t ':
        index += 1
    return index


def _redact_json_keys(body: str, *, webhook_route: bool = False) -> str:
    """Mask the value of every sensitively-named quoted key in unparsed text.

    Shared by `_redact_text` and the ordinary-part branch of
    `_redact_multipart`, which used to run only the free-text passes and so let
    a JSON credential through inside a part whose own name was innocuous.

    Keys are scanned in place and only a sensitive one consumes its value, so
    pairs nested inside a container are still reached.
    """
    result: list[str] = []
    position = 0

    for match in _JSON_KEY_PATTERN.finditer(body):
        if match.start() < position:
            # Inside a value that has already been masked.
            continue

        key = match.group(1) if match.group(1) is not None else match.group(2)
        decoded_key = _decode_json_key(key)
        # Masked whole rather than origin-preserved: this is the degraded path, where losing the
        # host is the safe way to be wrong.
        if (
            not _is_sensitive_key(decoded_key)
            and not _is_webhook_url_key(decoded_key, webhook_route)
            and not _is_header_map_key(decoded_key)
        ):
            # Left in place, and scanning continues into its value.
            continue

        result.append(body[position : match.start()])
        result.append(f'"{key}": "{REDACTED}"')
        position = _json_value_end(body, match.end())

    if not result:
        return body

    result.append(body[position:])
    return ''.join(result)


def _redact_multipart(body: str, *, protocol_keys: bool, webhook_route: bool = False) -> Optional[str]:
    """Mask the content of every sensitively-named part of a multipart body.

    `request.form()` accepts `multipart/form-data` as readily as
    `application/x-www-form-urlencoded`, so a credential this backend reads out
    of a form — `logout_token` on `POST /oauth/backchannel-logout` — can arrive
    in a shape that has no `a=b` pairs at all. The audit middleware captures
    request bodies without consulting the content type, so an unrecognised
    multipart part is written verbatim.

    Returns `None` when the body is not multipart, so the caller can fall
    through to the other passes.
    """
    match = _MULTIPART_OPENING_PATTERN.match(body)
    if not match:
        return None

    delimiter = f'--{match.group(1)}'
    segments = body.split(delimiter)

    for index, segment in enumerate(segments):
        name = _MULTIPART_NAME_PATTERN.search(segment)
        if name is None:
            continue
        quoted, token = name.group(1), name.group(2)
        key = _decode_json_key(quoted if quoted is not None else token)
        sensitive = (protocol_keys and key.strip().lower() in _SENSITIVE_PROTOCOL_KEYS) or _is_sensitive_key(key)

        # A part is `<headers>\r\n\r\n<content>\r\n`; keep the headers, which
        # carry the field name and filename this record is evidence of.
        headers, separator, content = segment.partition('\r\n\r\n')
        if not separator:
            headers, separator, content = segment.partition('\n\n')
        if not separator:
            # Truncated inside the part headers: no content was captured.
            continue

        trailing = ''
        for terminator in ('\r\n', '\n'):
            if content.endswith(terminator):
                trailing = terminator
                break

        if sensitive:
            body = REDACTED
        else:
            # Ordinary name, but the content can still carry a credential.
            original = content[: len(content) - len(trailing)]
            body = _redact_json_keys(original, webhook_route=webhook_route)
            body = _redact_free_text(body, protocol_keys=protocol_keys, webhook_route=webhook_route)
            if body == original:
                continue
        segments[index] = f'{headers}{separator}{body}{trailing}'

    return delimiter.join(segments)


def _redact_text(body: str, *, protocol_keys: bool = False, webhook_route: bool = False, complete: bool = False) -> str:
    """Textual fallback for bodies that are not parseable JSON.

    Used for truncated payloads and non-JSON content types, where the structural
    pass cannot run. Keys are scanned in place and only a sensitive one consumes
    its value, so pairs nested inside a container are still reached.

    `complete` says the text is all there was. It defaults to false so that a
    caller which does not know errs towards masking a value the cut may have
    made unrecognisable — see `_URL_USERINFO_CUT_PATTERN`.
    """
    if not webhook_route and _WEBHOOK_CONTAINER_TEXT_PATTERN.search(body):
        # No structure to descend on this path, so the container is read off the text: a cut config
        # import still holds `"events.webhooks":` in front of the records it carries.
        webhook_route = True

    multipart = _redact_multipart(body, protocol_keys=protocol_keys, webhook_route=webhook_route)
    if multipart is not None:
        return _redact_credential_urls(multipart, complete)

    body = _redact_json_keys(body, webhook_route=webhook_route)

    # The `a=b` and `Name: value` spellings, which the quoted-name key scan above does not see.
    body = _redact_free_text(body, protocol_keys=protocol_keys, webhook_route=webhook_route)

    return _redact_credential_urls(body, complete)


def _redact(body: str, path: Optional[str] = None, complete: bool = False) -> str:
    """Replace the value of every sensitive-looking key with `REDACTED`.

    Complete JSON bodies are redacted structurally, which reaches values the
    textual pass cannot see — arrays of keys, numbers, nested objects. Anything
    else, a body truncated at `max_body_size` above all, falls back to the regex
    pass.
    """
    if not body:
        return body

    webhook_route = bool(path) and bool(_WEBHOOK_ROUTE_PATTERN.search(path))

    if body.lstrip()[:1] in ('{', '['):
        try:
            # Compact separators so an already-compact body — which is what
            # clients actually send — survives the round trip byte for byte.
            return _redact_credential_urls(
                json.dumps(
                    _redact_structure(json.loads(body), webhook_route, _is_oauth_path(path)),
                    ensure_ascii=False,
                    separators=(',', ':'),
                    default=str,
                )
            )
        except Exception:
            pass

    return _redact_text(body, protocol_keys=_is_oauth_path(path), webhook_route=webhook_route, complete=complete)


# A `usage` object is provider-controlled and unbounded: a custom backend can return a diagnostic
# blob beside its counters, and `normalize_usage` keeps every field the provider sent.
MAX_USAGE_LOG_SIZE = MAX_BODY_LOG_SIZE


def _bound_usage(usage: Optional[dict]) -> tuple[Optional[dict], bool]:
    """Cap an oversized usage object, keeping the numbers it exists for.

    Over budget, the containers go and the scalar counters stay: `usage` is
    read for its metrics, so dropping a provider's prose while keeping every
    token and cost figure loses nothing an auditor came for. Still over after
    that — implausible, but the bound has to hold — and only the normalised
    fields survive.
    """
    if not isinstance(usage, dict) or not usage:
        return usage, False

    def size(value: dict) -> int:
        try:
            return len(json.dumps(value, default=str))
        except Exception:
            return MAX_USAGE_LOG_SIZE + 1

    if size(usage) <= MAX_USAGE_LOG_SIZE:
        return usage, False

    numeric = {
        key: value for key, value in usage.items() if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    if size(numeric) <= MAX_USAGE_LOG_SIZE:
        return numeric, True

    return {key: value for key, value in numeric.items() if key in USAGE_SUMMABLE_KEYS}, True


def _redact_usage_urls(node: Any) -> Any:
    """Apply the URL-credential pass to every string in a parsed structure.

    `_redact_credential_urls` runs over finished body text, where one pass
    covers every value at once. `usage` never becomes body text — it is written
    as its own field — so the same pass has to walk it. Cheap: the function
    returns immediately for a string with no `//` in it, which is every token
    count and nearly every label.
    """
    if isinstance(node, dict):
        return {key: _redact_usage_urls(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_redact_usage_urls(item) for item in node]
    if isinstance(node, str):
        return _redact_credential_urls(node)
    return node


def _redact_usage(usage: Optional[dict]) -> Optional[dict]:
    """Mask credentials a provider tucked into its `usage` object.

    `normalize_usage` keeps every key the provider sent, and `usage` is written
    as its own top-level field that never passes through the body redaction, so
    a secret masked inside `response_object` could reappear here in the clear.

    Both passes the body gets, in the same order: the key-based structural one,
    then the URL one — an ordinary name like `trace_url` says nothing about
    what its value carries, and a `?key=` in it is as live here as anywhere.
    """
    if not isinstance(usage, dict) or not usage:
        return usage
    return _redact_usage_urls(_redact_structure(usage))


def _bounded_redacted_usage(usage: Optional[dict], normalize: bool = True) -> tuple[Optional[dict], bool]:
    """Bound a provider's usage object, then redact what survived.

    Order matters for cost, not for safety. Bounding first measures once with
    `json.dumps` and drops the containers; redacting first would build a full
    recursive copy of a provider-controlled payload — every dict, every list —
    only for the bound to throw most of it away, on the request path, at
    METADATA level where no body is captured at all.

    Nothing escapes by being measured before it is masked: over budget, only
    the scalar counters survive the bound, and under budget the whole object is
    redacted exactly as before.
    """
    if normalize:
        usage = normalize_usage(usage)
    bounded, truncated = _bound_usage(usage)
    return _redact_usage(bounded), truncated


# The one audit field whose size this process does not choose: a provider error can quote the whole
# payload it rejected.
MAX_ERROR_LOG_SIZE = MAX_BODY_LOG_SIZE


def _truncate_error(text: Optional[str]) -> tuple[Optional[str], bool]:
    """The error text, cut to `MAX_ERROR_LOG_SIZE`, and whether it was cut."""
    if not text or len(text) <= MAX_ERROR_LOG_SIZE:
        return text, False
    return text[:MAX_ERROR_LOG_SIZE], True


def _redact_error(text: Optional[str], path: Optional[str] = None, complete: bool = False) -> Optional[str]:
    """Mask credentials in free text before it is recorded.

    `error` holds an exception message, which is the one audit field built from
    arbitrary strings rather than a parsed structure: an upstream URL with a
    query credential, or a provider error quoting the payload it rejected.
    """
    if not text:
        return text
    return _redact_text(text, protocol_keys=_is_oauth_path(path), complete=complete)


def _redact_uri(uri: str) -> str:
    """Mask credentials carried in the query string or in the path itself."""
    if not uri:
        return uri

    uri = _SENSITIVE_PATH_PATTERN.sub(lambda match: f'{match.group(1)}{REDACTED}', uri)
    uri = _redact_url_credentials(uri)

    # Split first so the pair pattern can never reach into the path, and so the query obeys exactly
    # the same sensitivity rule as a request body: `?key=` is masked, `?max_tokens=` is not.
    base, separator, query = uri.partition('?')
    if not separator:
        return base
    return (
        base
        + separator
        + _redact_encoded_pairs(
            query, protocol_keys=_is_oauth_path(base), webhook_route=bool(_WEBHOOK_ROUTE_PATTERN.search(base))
        )
    )


# ---------------------------------------------------------------------------
# Stream usage collection. Here rather than in `utils/middleware.py` because the
# audit middleware uses these as its fallback collector.
# ---------------------------------------------------------------------------


# Counters a provider reports at the top level instead of inside a `usage` object.
_NATIVE_USAGE_KEYS = ('prompt_eval_count', 'eval_count', 'prompt_n', 'predicted_n', 'cache_n')
# The cheap pre-filter for the above, alongside `"usage"`.
_NATIVE_USAGE_HINTS = ('_count"', '_n"')


def _record_model(data: dict) -> Optional[str]:
    """The model a parsed response record names, in whichever shape it uses.

    Chat Completions and Ollama put it at the top level, the Responses API
    nests it under `response`, and Anthropic reports it once on `message_start`
    under `message`. Read from the same records the usage scan already parses,
    so this costs nothing extra and — unlike the request body — cannot be lost
    to `MAX_BODY_LOG_SIZE`.
    """
    for holder in (data, data.get('response'), data.get('message')):
        if isinstance(holder, dict):
            model = holder.get('model')
            if isinstance(model, str) and model:
                return model
    return None


def _native_usage(data: dict) -> dict:
    return {key: data[key] for key in _NATIVE_USAGE_KEYS if isinstance(data.get(key), (int, float))}


def _has_usage_hint(text: str) -> bool:
    return '"usage"' in text or any(hint in text for hint in _NATIVE_USAGE_HINTS)


def _is_model_response(data: dict) -> bool:
    """Whether a parsed record looks like something a model produced.

    A bare `{"usage": {...}}` is not evidence of a model call. The middleware
    collector reads every audited JSON response, and `POST /api/v1/configs/import`
    echoes back `Config.get_all()` — so a stored top-level key called `usage`
    would be recorded as tokens no model generated. An audit trail inventing a
    cost is worse than one missing it.

    Every shape this reads reports usage beside at least one of these markers:
    OpenAI's `object` and `choices`, the Responses API's `type` and `response`,
    Ollama's `done`, Anthropic's `type`. A configuration payload has none.

    The native top-level counters are their own marker — nothing but a model
    backend reports `prompt_eval_count` — so they are checked here rather than
    being gated by it.
    """
    return bool(
        isinstance(data.get('choices'), list)
        or isinstance(data.get('object'), str)
        or isinstance(data.get('type'), str)
        or isinstance(data.get('done'), bool)
        or isinstance(data.get('response'), (dict, str))
        or _native_usage(data)
    )


def extract_stream_usage(raw) -> dict:
    """Pull the `usage` object out of one raw SSE chunk, if it carries one.

    The substring guard keeps this cheap: content deltas, which are almost every
    chunk of a stream, are rejected without a JSON parse.
    """
    return _extract_stream_usage(raw)[0]


# SSE field lines that are not data.
_SSE_FIELD_PATTERN = re.compile(r'^(?::|event:|id:|retry:)', re.IGNORECASE)


# An SSE event ends at a blank line, which is what separates one event's data fields from the next
# event's.
_SSE_EVENT_BOUNDARY_PATTERN = re.compile(r'\n[ \t]*\r?\n')
# A `data:` field, which is what marks a trailing run as SSE rather than NDJSON.
_SSE_DATA_LINE_PATTERN = re.compile(r'^[ \t]*data:', re.IGNORECASE | re.MULTILINE)


def _iter_stream_records(line: str):
    """Yield `(payload, streamed)` for each SSE event or bare JSON line."""
    data_lines: list[str] = []

    def flush():
        if data_lines:
            joined = '\n'.join(data_lines)
            data_lines.clear()
            return joined
        return None

    for raw_part in line.splitlines():
        stripped = raw_part.strip()
        if stripped.startswith('data:'):
            data_lines.append(stripped[5:].strip())
            continue

        pending = flush()
        if pending is not None:
            yield pending, True
        # A blank line closes the event; `event:`/`id:`/`retry:`/comment lines belong to the next
        # one.
        if stripped and not _SSE_FIELD_PATTERN.match(stripped):
            yield stripped, False

    pending = flush()
    if pending is not None:
        yield pending, True


# The spellings `normalize_usage` folds into one counter.
_USAGE_INPUT_ALIASES = frozenset({'input_tokens', 'prompt_tokens', 'prompt_eval_count', 'prompt_n', 'cache_n'})
_USAGE_OUTPUT_ALIASES = frozenset({'output_tokens', 'completion_tokens', 'eval_count', 'predicted_n'})


def _usage_alias(key: str) -> str:
    lowered = key.strip().lower()
    if lowered in _USAGE_INPUT_ALIASES:
        return 'input'
    if lowered in _USAGE_OUTPUT_ALIASES:
        return 'output'
    return lowered


def _accumulate_snapshot(snapshot: dict, incoming: dict) -> None:
    """Fold one cumulative usage snapshot into the snapshot state.

    Deliberately not `merge_usage`: that normalizes, and a normalized snapshot
    grows a `total_tokens` the provider never sent — a derived field that no
    terminal event can be said to have "already reported", so it survives the
    reconciliation below and is added on top of the real total. Raw keys in,
    raw keys out, so the alias test compares what the provider actually wrote.

    Numeric counters are summed rather than overwritten: one stream carrying two
    messages carries two prompts, and the audit trail is for what was billed.
    """
    for key, value in incoming.items():
        current = snapshot.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            snapshot[key] = value
        elif isinstance(current, (int, float)) and not isinstance(current, bool):
            snapshot[key] = current + value
        else:
            snapshot[key] = value


def _reconcile_snapshot(usage: dict, snapshot: dict, reported_aliases: set) -> dict:
    """Add the counters only the start snapshot reported.

    Anthropic reports the prompt once, on `message_start`, and the terminal
    `message_delta` reports the totals again — cumulative snapshots of one call,
    not increments. Whatever a later record already reported is therefore
    dropped from the snapshot instead of being summed with it.
    """
    if not snapshot:
        return usage

    remainder = {key: value for key, value in snapshot.items() if _usage_alias(key) not in reported_aliases}
    if not remainder:
        return usage

    try:
        return merge_usage(usage, remainder)
    except Exception as e:
        logger.warning('Discarding unusable streamed usage record: {}', e)
        return usage


def _extract_stream_usage(raw, trust_bare_usage: bool = True, state: Optional[dict] = None) -> tuple[dict, bool]:
    """As `extract_stream_usage`, plus whether any record actually parsed.

    The second value is what lets the collector tell "this text held complete
    records and none of them reported usage" from "this text was not parseable
    at all", which are the two cases the fragment fallback has to distinguish.

    `trust_bare_usage` is false when the bytes are a plain JSON response body
    rather than a stream, where a lone `usage` object is not evidence a model
    ran — see `_is_model_response`.

    `state` carries Anthropic's `message_start` snapshot and the counters later
    records have reported across several calls. A stream's start and terminal
    events land in different ASGI chunks as a matter of course — they are the
    first and last thing a response emits — so reconciling only what one call
    happened to see left the prompt counted twice in exactly the ordinary case.
    The caller holding the state reconciles once, at the end; without it this
    reconciles what it saw itself.
    """
    line = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw
    if not isinstance(line, str) or not _has_usage_hint(line):
        return {}, False

    usage = {}
    # Anthropic's `message_start` snapshot is held apart from the running sum — see
    # `_reconcile_snapshot`.
    snapshot: dict = {} if state is None else state.setdefault('snapshot', {})
    reported_aliases: set = set() if state is None else state.setdefault('aliases', set())
    parsed_any = False
    # `streamed` says the record came from `data:` fields, which a JSON response body never is.
    for part, streamed in _iter_stream_records(line):
        if not part or part == '[DONE]':
            continue

        try:
            data = JSONCodec.loads(part)
        except Exception:
            continue

        # Before the shape test, not after: `parsed_any` decides whether the caller may fall back to
        # the fragment scan.
        parsed_any = True

        if not isinstance(data, dict):
            continue

        if state is not None and not state.get('model'):
            # The first record that names one; every later chunk of a stream repeats it.
            model = _record_model(data)
            if model:
                state['model'] = model

        if not streamed and not trust_bare_usage and not _is_model_response(data):
            continue

        # Chat Completions puts usage at the top level, the Responses API nests it under the
        # response object of a `response.completed` event.
        nested = data.get('response')
        raw_usage = data.get('usage') or (nested.get('usage') if isinstance(nested, dict) else None)
        start_snapshot = False
        if not (isinstance(raw_usage, dict) and raw_usage) and data.get('type') == 'message_start':
            # Anthropic's native streaming shape reports the input tokens once, on `message_start`,
            # under `message.usage`; the terminal `message_delta` carries only the output count.
            message = data.get('message')
            if isinstance(message, dict):
                raw_usage = message.get('usage')
                start_snapshot = isinstance(raw_usage, dict) and bool(raw_usage)
        if not (isinstance(raw_usage, dict) and raw_usage):
            raw_usage = _native_usage(data)
        if isinstance(raw_usage, dict) and raw_usage:
            try:
                if start_snapshot:
                    _accumulate_snapshot(snapshot, raw_usage)
                else:
                    # Merge first, mark second.
                    merged = merge_usage(usage, raw_usage)
                    reported_aliases.update(_usage_alias(key) for key in raw_usage)
                    usage = merged
            except Exception as e:
                # One unparseable record must not cost the rest of the chunk: a terminal usage event
                # routinely shares a chunk with the deltas before it.
                logger.warning('Discarding unusable streamed usage record: {}', e)

    if state is None:
        usage = _reconcile_snapshot(usage, snapshot, reported_aliases)

    return usage, parsed_any


# The only characters that can change JSON structure.
_JSON_STRUCTURAL_PATTERN = re.compile(r'["{}\[\]]')


def _string_end(text: str, start: int) -> int:
    """Index just past the string literal opening at `start`.

    `str.find` rather than a character loop: a single provider payload can carry
    megabytes inside one string, and this runs on the response path.
    """
    index = start + 1
    while True:
        quote = text.find('"', index)
        if quote == -1:
            return len(text)
        backslashes = 0
        probe = quote - 1
        while probe > start and text[probe] == '\\':
            backslashes += 1
            probe -= 1
        if backslashes % 2 == 0:
            return quote + 1
        index = quote + 1


# `"usage": {` wherever it appears.
_USAGE_KEY_PATTERN = re.compile(r'"usage"\s*:\s*(?=\{)')
# A usage object is small, so the flat scan bounds itself: each candidate is walked at most this
# far, and the scan gives up after this much total text.
_FRAGMENT_OBJECT_LIMIT = 64 * 1024
_FRAGMENT_SCAN_LIMIT = 256 * 1024


def _scan_top_level_source(text: str, key: str, opener: str) -> Optional[str]:
    """The source of `key`'s value, read forward from the start of a document.

    Depth is tracked from the first byte, which is what makes this exact on a
    *prefix*: a body cut at `MAX_BODY_LOG_SIZE`, or a record cut at the buffer
    bound, still says truthfully how deep everything before the cut was. Reading
    depth backwards from the end cannot — with the closing braces gone, a nested
    value's own wrapper closing looks exactly like the root closing, and a
    `usage` belonging to an output item gets recorded as the response's own.

    The `response` and `message` envelopes count as the document's own level:
    the Responses API and Anthropic both report one object in.

    Bounded by the caller, since reading forward pays for everything before the
    value rather than everything after it.
    """
    depth = 0
    opened_by: list[Optional[str]] = []
    pending: Optional[str] = None
    length = len(text)
    skip_to = 0

    # One `finditer` rather than a `search` per character: the matches inside a string are consumed
    # and dropped, so the payload's own text costs an iteration each rather than a fresh scan each.
    for match in _JSON_STRUCTURAL_PATTERN.finditer(text):
        index = match.start()
        if index < skip_to:
            continue
        char = match.group()

        if char == '"':
            end = _string_end(text, index)
            skip_to = end
            token = text[index + 1 : max(end - 1, index + 1)]

            probe = end
            while probe < length and text[probe] in ' \t\r\n':
                probe += 1
            if probe >= length or text[probe] != ':':
                # A value, not a key.
                continue

            value = probe + 1
            while value < length and text[value] in ' \t\r\n':
                value += 1

            if token == key and value < length and text[value] == opener:
                envelope = depth == 2 and len(opened_by) > 1 and opened_by[1] in ('response', 'message')
                if depth == 1 or envelope:
                    end_of_value = _string_end(text, value) if opener == '"' else _balanced_end(text, value, opener)
                    return text[value:end_of_value]

            pending = token
            skip_to = probe + 1
            continue

        if char in '{[':
            depth += 1
            opened_by.append(pending)
            pending = None
        else:
            depth -= 1
            if opened_by:
                opened_by.pop()
            pending = None

    return None


def _scan_top_level_model(text: str) -> Optional[str]:
    """The `model` a document names for itself, read without parsing it."""
    source = _scan_top_level_source(text, 'model', '"')
    if source is None:
        return None
    try:
        name = JSONCodec.loads(source)
    except Exception:
        return None
    return name if isinstance(name, str) and name else None


def _scan_top_level_usage(text: str) -> dict:
    """The `usage` a document reports for itself, read without parsing it."""
    source = _scan_top_level_source(text, 'usage', '{')
    if source is None:
        return {}
    try:
        usage = JSONCodec.loads(source)
    except Exception:
        return {}
    return usage if isinstance(usage, dict) and usage else {}


def _request_model(text: str) -> Optional[str]:
    """The model the request asked for, from a complete body or a cut one."""
    if '"model"' not in text:
        return None

    try:
        data = JSONCodec.loads(text)
    except Exception:
        data = None

    if isinstance(data, dict):
        model = data.get('model')
        return model if isinstance(model, str) and model else None

    # Truncated, or not JSON at all.
    return _scan_top_level_model(text)


def _state_model(request: Request) -> Optional[str]:
    """The model the endpoint resolved, when it left one on the scope state.

    Nothing is asked of the routes for this: `request.state.model` and the chat
    pipeline's `metadata['model']` are already set by the time the entry is
    built, and neither can be truncated. It is the only source for a request
    that failed before a response was produced and whose body was cut.
    """
    candidates = (
        getattr(request.state, 'audit_model', None),
        getattr(request.state, 'model', None),
        getattr(request.state, 'metadata', None) or {},
    )
    for candidate in candidates:
        if isinstance(candidate, dict):
            for key in ('id', 'model'):
                value = candidate.get(key)
                if isinstance(value, str) and value:
                    return value
                if isinstance(value, dict):
                    nested = value.get('id')
                    if isinstance(nested, str) and nested:
                        return nested
        elif isinstance(candidate, str) and candidate:
            return candidate
    return None


# A response names its own `usage` in the head of its body in every shape this
# proxies, so the head is read first and the rest is usually never touched.
_HEAD_SCAN_LIMIT = 64 * 1024
# The most a forward scan will read when the head did not answer and the document cannot be parsed
# because it was cut.
_FORWARD_SCAN_LIMIT = 4 * 1024 * 1024


def _document_usage(data: dict) -> dict:
    """The `usage` a parsed document reports for itself.

    The same two positions the forward scan accepts: the top level, and the
    envelope the Responses API and Anthropic report one object in.
    """
    for holder in (data, data.get('response'), data.get('message')):
        if isinstance(holder, dict):
            usage = holder.get('usage')
            if isinstance(usage, dict) and usage:
                return usage
    return {}


def _document_body(text: str) -> str:
    """The JSON document a chunk begins with, past an SSE `data:` field name."""
    stripped = text.lstrip()
    if stripped[:5].lower() == 'data:':
        stripped = stripped[5:].lstrip()
    return stripped


def _scan_usage(text: str) -> dict:
    """Read usage out of text too large or too broken to parse as records.

    Text that starts a JSON document is read with the depth-aware scan, so a
    nested `usage` cannot stand in for the response's own. The flat scan is what
    is left when depth cannot be read at all: text that starts mid-document, or
    stops before its containers close — a record cut at the buffer bound still
    gave up its usage before this existed, and should still.
    """
    document = _document_body(text)
    if document[:1] != '{':
        # Text that starts mid-document has no depth to read: the head is gone, and a suffix cannot
        # distinguish a nested value's wrapper closing from the root closing.
        return extract_usage_fragment(text)

    usage = _scan_top_level_usage(document[:_HEAD_SCAN_LIMIT])
    if usage or len(document) <= _HEAD_SCAN_LIMIT:
        return usage

    # The head did not name it.
    try:
        data = JSONCodec.loads(document)
    except Exception:
        data = None
    if isinstance(data, dict):
        return _document_usage(data)

    # Cut, so it cannot be parsed at all: walk it, which stays exact because
    # depth read forward from the first byte is truthful even for a prefix.
    return _scan_top_level_usage(document[:_FORWARD_SCAN_LIMIT])


def extract_usage_fragment(text: str) -> dict:
    """Pull a `"usage": {...}` object out of text that is not a whole SSE event.

    Scans for the key and takes the balanced object after it — reusing
    `_balanced_end`, the same brace walk the redaction and depth scans use — so a
    truncated or concatenated fragment still gives up its usage where a JSON
    parse of the whole thing would fail. Both the per-candidate window and the
    total scan are bounded so the walk stays linear on adversarial text.
    """
    scanned = 0
    for match in _USAGE_KEY_PATTERN.finditer(text):
        if scanned >= _FRAGMENT_SCAN_LIMIT:
            break
        start = match.end()
        # A real usage object closes well within the window; one that does not is not the response's
        # own, and walking to the end of a large body for it is exactly the cost being bounded.
        window = text[start : start + _FRAGMENT_OBJECT_LIMIT]
        end = _balanced_end(window, 0, '{')
        scanned += end
        try:
            usage = JSONCodec.loads(window[:end])
        except Exception:
            continue
        if isinstance(usage, dict) and usage:
            return usage

    return {}


class StreamUsageCollector:
    """Accumulate `usage` from a stream whose chunks may split records.

    Network chunks land on arbitrary byte boundaries — `stream_wrapper` in
    `utils/misc.py` forwards whatever the transport hands it — so the terminal
    usage record can straddle two of them, where per-chunk parsing sees only
    fragments and finds nothing. Text is parsed as it closes, whatever has not
    closed yet is held for the next chunk, and `finish()` drains the remainder.

    What counts as closed is `_split_open_event`: a line for NDJSON and for the
    single-line `data:` events that make up almost every SSE stream, and the
    event's blank line for a run of `data:` fields that does not yet parse on
    its own. Both framings of SSE are handled, including CRLF, where `\n\n`
    never appears at all. Holding is bounded by `MAX_BUFFER`, so a stream that
    never closes an event cannot accumulate the whole response.
    """

    # A line that never ends must not grow without bound.
    MAX_BUFFER = 512 * 1024

    def __init__(self, trust_bare_usage: bool = True):
        self._buffer = ''
        self.usage = {}
        # Held across chunks: a stream's start and terminal events never share one, so the snapshot
        # cannot live inside a single parse.
        self._state: dict = {}
        # Streams are trusted with a lone `usage` object; a plain JSON response body is not.
        self._trust_bare_usage = trust_bare_usage

    @property
    def model(self) -> Optional[str]:
        """The model the stream named, if any of its records did."""
        return self._state.get('model')

    def feed(self, raw) -> None:
        try:
            self._feed(raw)
        except Exception as e:
            # A backend can send a dict-shaped `usage` whose metrics are not numbers, which
            # `normalize_usage` chokes on.
            logger.debug('Failed to collect stream usage: {}', e)

    def _feed(self, raw) -> None:
        chunk = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw
        if not isinstance(chunk, str) or not chunk:
            return

        if self._buffer and len(self._buffer) + len(chunk) > self.MAX_BUFFER:
            # Appending would put the buffer over the bound that exists to stop exactly that, so the
            # held text is scanned and released before the chunk is joined to it.
            self._merge(self._buffer)
            self._buffer = ''

        text = self._buffer + chunk if self._buffer else chunk
        closed, held = self._split_open_event(text)
        if closed:
            self._merge(closed)
        self._buffer = held

        if len(self._buffer) > self.MAX_BUFFER:
            # A single event, or a single line, can exceed it on its own.
            self._merge(self._buffer)
            self._buffer = ''

    def _split_open_event(self, text: str) -> tuple[str, str]:
        """Split `text` into what can be scanned now and what must be held.

        A line boundary is a safe cut for NDJSON, where every record is a line,
        but not for SSE, where one event's data may span several `data:` fields
        that a client joins with a newline before parsing. Chunk boundaries fall
        wherever the transport puts them, so those fields routinely arrive in
        different ASGI messages — and scanning each as it closes leaves the
        halves of a pretty-printed record that parses as neither JSON nor a
        recoverable fragment.

        So the cut is the event boundary — the blank line — for a trailing run
        that looks like an SSE event still being written, and the line boundary
        for everything else. "Still being written" is decided by parsing it: a
        run that already yields a complete record is released immediately, which
        is every ordinary single-line `data:` event.
        """
        cut = text.rfind('\n')
        if cut == -1:
            return '', text

        complete, tail = text[: cut + 1], text[cut + 1 :]

        boundary = None
        for match in _SSE_EVENT_BOUNDARY_PATTERN.finditer(complete):
            boundary = match
        start = boundary.end() if boundary else 0
        # The closed lines of the run only: the partial tail is held either way, so testing it here
        # would judge the run on text that is not being released with it.
        run = complete[start:]

        if _SSE_DATA_LINE_PATTERN.search(run) and not _extract_stream_usage(run, self._trust_bare_usage)[1]:
            return complete[:start], run + tail

        return complete, tail

    def finish(self) -> dict:
        """Drain a final record that arrived without its trailing newline."""
        try:
            if self._buffer:
                self._merge(self._buffer)
        except Exception as e:
            logger.debug('Failed to drain stream usage: {}', e)
        finally:
            self._buffer = ''

        # Only here has every record been seen, so "no later record reported this counter" is a fact
        # rather than a guess.
        self.usage = _reconcile_snapshot(self.usage, self._state.pop('snapshot', {}), self._state.get('aliases', set()))
        return self.usage

    # A response names its model in the head of its body, and a stream in its first chunk.
    MAX_MODEL_SCAN = 64 * 1024

    def _merge(self, text: str) -> None:
        if not self._state.get('model') and '"model"' in text:
            # Before the usage hint: a stream names its model on the first chunk and its tokens on
            # the last.
            model = _scan_top_level_model(_document_body(text)[: self.MAX_MODEL_SCAN])
            if model:
                self._state['model'] = model

        if not _has_usage_hint(text):
            return

        if len(text) > self.MAX_BUFFER:
            # One enormous record rather than a run of them.
            usage = _scan_usage(text)
            if usage:
                self.usage = merge_usage(self.usage, usage)
            return

        usage, parsed_any = _extract_stream_usage(text, self._trust_bare_usage, state=self._state)
        if not usage and not parsed_any:
            # Nothing parsed as a record — the case the fragment scan exists for, an oversized event
            # cut at the bound.
            usage = _scan_usage(text)
        if usage:
            self.usage = merge_usage(self.usage, usage)


# Response media types a `usage` object can appear in.
_USAGE_SCANNABLE_MEDIA = frozenset(
    {
        'application/json',
        'application/x-ndjson',
        'application/jsonl',
        'application/jsonlines',
        'text/event-stream',
    }
)


# The scannable types that are streams.
_STREAMING_MEDIA = frozenset(
    {'application/x-ndjson', 'application/jsonl', 'application/jsonlines', 'text/event-stream'}
)


def _media_type(content_type: Optional[str]) -> str:
    return content_type.split(';', 1)[0].strip().lower() if content_type else ''


def _is_usage_scannable(content_type: Optional[str]) -> bool:
    media = _media_type(content_type)
    return bool(media) and (media in _USAGE_SCANNABLE_MEDIA or media.endswith('+json'))


def _is_streaming_media(content_type: Optional[str]) -> bool:
    return _media_type(content_type) in _STREAMING_MEDIA


# Routes that run a model, enumerated by operation rather than by provider prefix: `/openai/` and
# `/ollama/` also carry model *management*.
_MODEL_ROUTE_PATTERN = re.compile(
    r'/(?:chat/)?completions(?:/|$)'
    r'|/responses(?:/|$)'
    r'|/embeddings(?:/|$)'
    r'|/ollama/api/(?:embed|chat|generate)(?:/|$)'
    r'|(?:^|/)v1/messages(?:/|$)'
    # `POST /api/message` is the same handler as `/api/v1/messages`; anchored so the sibling
    # `/count_tokens`, which runs no model, stays out.
    r'|(?:^|/)api/message$',
    re.IGNORECASE,
)


def _is_model_route(path: Optional[str]) -> bool:
    return bool(path) and bool(_MODEL_ROUTE_PATTERN.search(path))


def _emit_last_resort(entry: dict, error: BaseException) -> None:
    """Write an audit record straight to stderr when the logging pipeline fails.

    The audit trail must never lose an event silently: if Loguru cannot take the
    record we still put it somewhere a log collector can pick it up, and we make
    the failure loud.
    """
    try:
        payload = json.dumps(
            {'audit_sink_error': f'{type(error).__name__}: {error}', 'record': entry},
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        payload = f'{{"audit_sink_error": "{type(error).__name__}", "record": "<unserializable>"}}'

    try:
        sys.stderr.write(f'[audit error] {payload}\n')
        sys.stderr.flush()
    except Exception:
        pass


@dataclass(frozen=True)
class AuditLogEntry:
    # `Metadata` audit level properties
    id: str
    user: Optional[dict[str, Any]]
    audit_level: str
    verb: str
    request_uri: str
    user_agent: Optional[str] = None
    source_ip: Optional[str] = None
    # `Request` audit level properties
    request_object: Any = None
    # `Request Response` level
    response_object: Any = None
    response_status_code: Optional[int] = None
    # Always-on reliability/observability properties The model this request ran, when it ran one.
    model: Optional[str] = None
    usage: Optional[dict[str, Any]] = None
    duration_ms: Optional[int] = None
    request_object_truncated: bool = False
    response_object_truncated: bool = False
    error_truncated: bool = False
    usage_truncated: bool = False
    # Set when the request died before a response was produced, or when the
    # audit record itself could only be built in degraded form.
    error: Optional[str] = None
    # Set on a follow-up entry that reports work finished after its request's
    # own entry was already written; points at that entry's `id`.
    parent_id: Optional[str] = None


# Cached so the hot path does not re-introspect the dataclass on every request.
_AUDIT_ENTRY_FIELDS = tuple(field.name for field in fields(AuditLogEntry))


class AuditLevel(str, Enum):
    NONE = 'NONE'
    METADATA = 'METADATA'
    REQUEST = 'REQUEST'
    REQUEST_RESPONSE = 'REQUEST_RESPONSE'


def _usage_collection_enabled() -> bool:
    if not ENABLE_AUDIT_USAGE:
        return False
    try:
        # Mirrors how main.py resolves the level: anything unparseable means the
        # middleware is never installed, so nothing would read the usage.
        return AuditLevel(AUDIT_LOG_LEVEL) != AuditLevel.NONE
    except ValueError:
        return False


# True when a usage object could actually reach the audit trail.
AUDIT_USAGE_ENABLED = _usage_collection_enabled()


def _presented_credential(request: Request) -> Optional[str]:
    """The credential this request presented, whatever transport carried it.

    Authorization header, token cookie, or `request.state.token` — which is
    where `AppHTTPMiddleware`, running outside this one, normalizes the
    CUSTOM_API_KEY_HEADER (default `x-api-key`). All three have to be consulted
    in both places that ask "is anyone claiming to be someone here": the skip
    check, or a whole authentication transport produces no audit trail at all,
    and the actor resolver, or its rejected requests record an empty actor.

    Returned for its shape only — callers classify the mechanism and never put
    the value in a record.
    """
    auth_header = request.headers.get('authorization')
    if auth_header:
        scheme, _, credentials = auth_header.partition(' ')
        if scheme.lower() == 'bearer' and credentials.strip():
            return credentials.strip()

    cookie_token = request.cookies.get('token')
    if cookie_token:
        return cookie_token

    state_token = getattr(request.state, 'token', None)
    return getattr(state_token, 'credentials', None)


def _credential_offered(request: Request) -> bool:
    """Whether the request tried to authenticate at all — for the skip gate.

    Deliberately looser than `_presented_credential`: a raw or malformed
    `Authorization` header (a schemeless API key, a bare `Bearer`, a token with
    no scheme) is a rejected access attempt, which is exactly what the trail is
    asked about, so it must not be dropped at the default settings the way a
    request carrying no credentials at all is. The actor resolver stays strict —
    it will not derive an identity from a header it cannot parse — so this only
    decides *whether* to record, never *whom* to record.
    """
    return bool(request.headers.get('authorization') or request.cookies.get('token') or _presented_credential(request))


class AuditLogger:
    """
    A helper class that encapsulates audit logging functionality. It uses Loguru’s logger with an auditable binding to ensure that audit log entries are filtered correctly.

    Parameters:
    logger (Logger): An instance of Loguru’s logger.
    """

    def __init__(self, logger: 'Logger'):
        self.logger = logger.bind(auditable=True)

    def write(
        self,
        audit_entry: AuditLogEntry,
        *,
        log_level: str = 'INFO',
        extra: Optional[dict] = None,
    ):
        # Plain attribute reads instead of `dataclasses.asdict`, which deep-copies
        # every value (including the captured bodies) on each request.
        entry = {name: getattr(audit_entry, name) for name in _AUDIT_ENTRY_FIELDS}

        if extra:
            entry['extra'] = extra

        try:
            self.logger.log(
                log_level,
                '',
                **entry,
            )
        except Exception as e:
            # Reached when the sink raises, which it only does when AUDIT_LOG_STRICT turns off
            # Loguru's `catch`.
            _emit_last_resort(entry, e)
            if AUDIT_LOG_STRICT:
                raise


# Used for entries emitted outside the middleware's request cycle.
_out_of_band_logger = AuditLogger(logger)


def audit_usage_wanted(request: Request) -> bool:
    """Whether anything will read usage collected for this request.

    `AUDIT_USAGE_ENABLED` only says the feature is on process-wide. The
    middleware marks the requests it actually audits, so an excluded path — and
    `/api/chat/completions` is excluded by default — does not pay to gather
    usage that no entry will carry.
    """
    if not AUDIT_USAGE_ENABLED:
        return False
    try:
        return request.scope.get('state', {}).get('audit_active') is True
    except Exception:
        return False


def _recorded_usage(request: Request) -> bool:
    """Whether the route has already reported usage for this request."""
    recorded = getattr(request.state, 'audit_usage', None)
    return isinstance(recorded, dict) and bool(recorded)


def record_audit_usage(request: Request, usage: Optional[dict], model: Optional[str] = None) -> None:
    """Attach model usage (tokens/cost) to the audit trail for this request.

    Called from the chat pipeline once usage is known, and accumulated across
    the several model calls a single request can make. It is stored on the ASGI
    scope state, which the audit middleware shares with the endpoint.

    The UI chat path runs the model in a background task that outlives the HTTP
    response (`create_task` in the `/api/chat/completions` handler), so by the
    time usage exists the request's own audit entry has long been written. That
    case emits a follow-up entry carrying the usage and pointing at the original
    through `parent_id`, rather than updating a record that is already on disk.
    """
    if not audit_usage_wanted(request):
        return

    if model:
        # Reported together with the usage because it is the same fact: what ran, and what it cost.
        try:
            request.scope.setdefault('state', {})['audit_model'] = model
        except Exception:
            pass

    if not usage or not isinstance(usage, dict):
        return

    try:
        state = request.scope.setdefault('state', {})
        receipt = state.get('audit_receipt')

        if receipt is None:
            # Either the entry has not been written yet, in which case the
            # middleware picks this up, or the request was never audited at all.
            state['audit_usage'] = merge_usage(state.get('audit_usage'), usage)
            return

        entry = _usage_entry(receipt, usage, model)
    except Exception as e:
        # Provider data this build could not make sense of — `normalize_usage` raises on a non-
        # numeric metric.
        logger.warning('Discarding unusable audit usage: {}', e)
        return

    _write_out_of_band(entry, 'usage')


def _usage_entry(receipt: dict, usage: dict, model: Optional[str] = None) -> AuditLogEntry:
    bounded_usage, usage_truncated = _bounded_redacted_usage(usage)
    return AuditLogEntry(
        id=str(uuid.uuid4()),
        # The model reported *with* this usage wins over the parent entry's: an arena sub-model
        # resolves after the parent entry is written.
        model=model or receipt.get('model'),
        parent_id=receipt.get('id'),
        user=receipt.get('user'),
        audit_level=receipt.get('audit_level', ''),
        verb=receipt.get('verb', ''),
        request_uri=receipt.get('request_uri', ''),
        source_ip=receipt.get('source_ip'),
        user_agent=receipt.get('user_agent'),
        usage=bounded_usage,
        usage_truncated=usage_truncated,
    )


def _write_out_of_band(entry: AuditLogEntry, kind: str) -> None:
    """Emit a follow-up entry, holding it to the same guarantee as any other.

    Strict mode means a lost audit *record* is a failure rather than a note, so
    a sink error propagates. `AuditLogger.write` has already put the record on
    stderr by then, so the event survives either way.
    """
    try:
        _out_of_band_logger.write(entry)
    except Exception as e:
        logger.error('Failed to write audit {} entry: {}', kind, e)
        if AUDIT_LOG_STRICT:
            raise


def record_audit_error(request: Request, message: str) -> None:
    """Record something that went wrong after the request's own entry was written.

    The post-response session commit is the case this exists for: it runs in a
    middleware outside this one, so by the time it fails and rolls back, the
    audit trail already says the mutation succeeded with a 2xx.
    """
    try:
        receipt = request.scope.get('state', {}).get('audit_receipt')
        if not receipt:
            return

        bounded_message, message_truncated = _truncate_error(message)
        entry = AuditLogEntry(
            id=str(uuid.uuid4()),
            parent_id=receipt.get('id'),
            user=receipt.get('user'),
            audit_level=receipt.get('audit_level', ''),
            verb=receipt.get('verb', ''),
            request_uri=receipt.get('request_uri', ''),
            source_ip=receipt.get('source_ip'),
            user_agent=receipt.get('user_agent'),
            error=_redact_error(bounded_message, request.scope.get('path', '')),
            error_truncated=message_truncated,
        )
    except Exception as e:
        logger.error('Failed to build audit error entry: {}', e)
        return

    _write_out_of_band(entry, 'error')


class AuditContext:
    """
    Captures and aggregates the HTTP request and response bodies during the processing of a request. It ensures that only a configurable maximum amount of data is stored to prevent excessive memory usage.

    Attributes:
    request_body (bytearray): Accumulated request payload.
    response_body (bytearray): Accumulated response payload.
    max_body_size (int): Maximum number of bytes to capture.
    metadata (Dict[str, Any]): A dictionary to store additional audit metadata (user, http verb, user agent, etc.).
    """

    # How much of a request body is read *for the model alone*.
    MODEL_SCAN_LIMIT = 64 * 1024

    def __init__(self, max_body_size: int = MAX_BODY_LOG_SIZE, scan_model: bool = False):
        self.request_body = bytearray()
        self.response_body = bytearray()
        self.max_body_size = max_body_size
        self.metadata: Dict[str, Any] = {}
        # Recorded even when bodies are not captured, so METADATA-level entries
        # still carry the response status.
        self.status_code: Optional[int] = None
        self.duration_ms: Optional[int] = None
        self.error: Optional[str] = None
        self.request_truncated = False
        self.response_truncated = False
        # True once a `http.request` message arrives with `more_body` unset.
        self.request_complete = False
        # The same for the response: a stream that raises, is cancelled, or
        # loses its client never sends its final `http.response.body`.
        self.response_complete = False
        # Usage read off the response bytes, used only when the route reported
        # none of its own.
        self.response_usage: Dict[str, Any] = {}
        # The model named by the response's own records — what actually served
        # the request, which the request body can only claim.
        self.response_model: Optional[str] = None
        # Request bytes kept only long enough to read a model out of them, on
        # routes that run one. Dropped with the context; never recorded.
        self.scan_model = scan_model
        self.model_scan = bytearray()

    def add_model_scan(self, chunk: bytes):
        """Keep request bytes for the model read, independently of capture.

        Separate from `add_request_chunk` because the two answer to different
        settings: the stored body is gated on the audit level, while the model
        is metadata every level records. Wiring the scan into the capture branch
        meant a `METADATA` deployment — which stores no body at all — got the
        buffer allocated and never filled.
        """
        if not self.scan_model:
            return
        headroom = self.MODEL_SCAN_LIMIT - len(self.model_scan)
        if headroom > 0:
            self.model_scan.extend(chunk[:headroom])

    def add_request_chunk(self, chunk: bytes):
        remaining = self.max_body_size - len(self.request_body)
        if remaining <= 0:
            self.request_truncated = self.request_truncated or bool(chunk)
            return
        if len(chunk) > remaining:
            self.request_truncated = True
        self.request_body.extend(chunk[:remaining])

    def add_response_chunk(self, chunk: bytes):
        remaining = self.max_body_size - len(self.response_body)
        if remaining <= 0:
            self.response_truncated = self.response_truncated or bool(chunk)
            return
        if len(chunk) > remaining:
            self.response_truncated = True
        self.response_body.extend(chunk[:remaining])


class AuditLoggingMiddleware:
    """
    ASGI middleware that intercepts HTTP requests and responses to perform audit logging. It captures request/response bodies (depending on audit level), headers, HTTP methods, and user information, then logs a structured audit entry at the end of the request cycle.

    The audit record is written from a synchronous `finally` block that performs
    no awaits, so a cancelled request (client disconnect mid-stream, server
    shutdown) still produces an entry instead of losing it to `CancelledError`.
    """

    DEFAULT_AUDITED_METHODS = {'PUT', 'PATCH', 'DELETE', 'POST'}

    def __init__(
        self,
        app: ASGI3Application,
        *,
        excluded_paths: Optional[list[str]] = None,
        included_paths: Optional[list[str]] = None,
        max_body_size: int = MAX_BODY_LOG_SIZE,
        audit_level: AuditLevel = AuditLevel.NONE,
        audit_get_requests: bool = False,
    ) -> None:
        self.app = app
        self.audit_logger = AuditLogger(logger)

        def normalize_paths(paths: Optional[list[str]]) -> list[str]:
            return [path for path in (path.strip().lstrip('/') for path in paths or []) if path]

        self.excluded_paths = normalize_paths(excluded_paths)
        self.included_paths = normalize_paths(included_paths)
        self.max_body_size = max_body_size
        self.audited_methods = set(self.DEFAULT_AUDITED_METHODS)
        if audit_get_requests:
            self.audited_methods.add('GET')
        self.audit_level = audit_level

        self._capture_request_body = audit_level in (AuditLevel.REQUEST, AuditLevel.REQUEST_RESPONSE)
        self._capture_response_body = audit_level == AuditLevel.REQUEST_RESPONSE

        # Paths are fixed for the process lifetime; compile once instead of
        # per request. None means the corresponding mode has nothing to match.
        self._included_pattern = (
            re.compile(r'^/api(?:/v1)?/(' + '|'.join(self.included_paths) + r')\b') if self.included_paths else None
        )
        self._excluded_pattern = (
            re.compile(r'^/api(?:/v1)?/(' + '|'.join(self.excluded_paths) + r')\b') if self.excluded_paths else None
        )

        if self.included_paths and self.excluded_paths:
            logger.warning(
                'Both AUDIT_INCLUDED_PATHS and AUDIT_EXCLUDED_PATHS are set. '
                'AUDIT_INCLUDED_PATHS (whitelist) takes precedence.'
            )

    async def __call__(
        self,
        scope: ASGIScope,
        receive: ASGIReceiveCallable,
        send: ASGISendCallable,
    ) -> None:
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        request = Request(scope=cast(MutableMapping, scope))

        if self._should_skip_auditing(request):
            return await self.app(scope, receive, send)

        # Marks the request as audited for `audit_usage_wanted`, so collectors
        # elsewhere can tell an audited request from an excluded one.
        scope.setdefault('state', {})['audit_active'] = True

        return await self._call_audited(scope, receive, send, request)

    async def _call_audited(
        self,
        scope: ASGIScope,
        receive: ASGIReceiveCallable,
        send: ASGISendCallable,
        request: Request,
    ) -> None:
        model_route = _is_model_route(scope.get('path', ''))
        context = AuditContext(max_body_size=self.max_body_size, scan_model=model_route)
        capture_response_body = self._capture_response_body
        # Last-resort collection for the direct provider proxies, which return the upstream response
        # straight to the client and never reach the pipeline that calls `record_audit_usage`.
        collect_usage = AUDIT_USAGE_ENABLED and model_route
        usage_collector = StreamUsageCollector() if collect_usage else None
        streaming_response = False
        started = time.monotonic()

        async def send_wrapper(message: ASGISendEvent) -> None:
            nonlocal usage_collector
            message_type = message['type']
            # The status code is `Metadata`-level information, so it is recorded
            # at every audit level — only the body capture is level-gated.
            if message_type == 'http.response.start':
                context.status_code = message['status']
                if usage_collector is not None:
                    content_type = next(
                        (
                            value.decode('latin-1')
                            for name, value in (message.get('headers') or [])
                            if name.lower() == b'content-type'
                        ),
                        None,
                    )
                    if not _is_usage_scannable(content_type):
                        usage_collector = None
                    else:
                        streaming_response = _is_streaming_media(content_type)
                        usage_collector = StreamUsageCollector(trust_bare_usage=streaming_response)
            elif message_type == 'http.response.body':
                body = message.get('body', b'')
                if capture_response_body:
                    context.add_response_chunk(body)
                if usage_collector is not None and body:
                    if _recorded_usage(request):
                        # The route reported its own usage, which `_build_entry` prefers, so
                        # scanning can only confirm it.
                        usage_collector = None
                    else:
                        usage_collector.feed(body)

            await send(message)

            # After the await: `send` raises when the client has gone, and a chunk that never
            # reached the wire has not completed the response.
            if message_type == 'http.response.body' and not message.get('more_body', False):
                context.response_complete = True

        if self._capture_request_body or context.scan_model:

            async def receive_wrapper() -> ASGIReceiveEvent:
                message = await receive()

                if message['type'] == 'http.request':
                    body = message.get('body', b'')
                    context.add_model_scan(body)
                    if self._capture_request_body:
                        context.add_request_chunk(body)
                        if not message.get('more_body', False):
                            context.request_complete = True

                return message

        else:
            receive_wrapper = receive

        app_failed = False
        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except BaseException as e:
            # Includes CancelledError: a request torn down mid-flight is still
            # an audited event, and the reason belongs in the record.
            context.error = f'{type(e).__name__}: {e}'
            app_failed = True
            raise
        finally:
            context.duration_ms = int((time.monotonic() - started) * 1000)
            if usage_collector is not None:
                context.response_usage = usage_collector.finish()
                context.response_model = usage_collector.model
            try:
                # Deliberately synchronous — see the class docstring.
                self._log_audit_entry(request, context)
            except Exception:
                # Strict mode propagates only while the response can still be affected.
                if not app_failed and not context.response_complete:
                    raise

    def _resolve_user(self, request: Request) -> dict[str, Any]:
        """Identify the actor without awaiting and without side effects.

        `get_current_user` stashes the resolved user on the scope-backed state,
        so authenticated requests get the full record for free. Everything else
        (auth failures, endpoints that never ran the dependency, requests
        cancelled before auth) falls back to the identity *claimed* by the
        presented credentials, marked unverified. Re-running the auth pipeline
        here is not an option: it awaits (and would be lost to cancellation),
        hits the DB and Redis, and mutates `last_active_at` from a logging path.
        """
        user = getattr(request.state, 'user', None)
        if isinstance(user, UserModel):
            return user.model_dump(include={'id', 'name', 'email', 'role'})

        # An authentication that succeeded without producing a `UserModel`.
        actor = getattr(request.state, 'audit_actor', None)
        if isinstance(actor, dict) and actor:
            return dict(actor)

        token = _presented_credential(request)
        if not token:
            return {}

        if token.startswith('sk-'):
            # Never derive anything from the key material itself.
            return {'auth_type': 'api_key', 'verified': False}

        data = decode_token(token)
        if data and data.get('id'):
            return {'id': data['id'], 'auth_type': 'jwt', 'verified': False}

        return {'auth_type': 'jwt', 'verified': False}

    # Routes audited whatever their method, because the method is not what makes them worth
    # recording.
    ALWAYS_AUDITED_PATH_PATTERN = re.compile(
        r'^/oauth/(?:clients/)?[^/]+/(?:login/)?callback/?$',
        re.IGNORECASE,
    )

    ALWAYS_LOG_ENDPOINTS = (
        '/api/v1/auths/signin',
        '/api/v1/auths/signout',
        '/api/v1/auths/signup',
    )

    def _should_skip_auditing(self, request: Request) -> bool:
        if self.audit_level == AuditLevel.NONE or AUDIT_LOG_LEVEL == 'NONE':
            return True

        path = request.scope.get('path', '')
        lowered_path = path.lower()
        # Before the method gate, not after: these are audited *because of what
        # they are*, and one of them is a GET.
        for endpoint in self.ALWAYS_LOG_ENDPOINTS:
            if lowered_path.startswith(endpoint):
                return False  # Do NOT skip logging for auth endpoints
        if self.ALWAYS_AUDITED_PATH_PATTERN.match(path):
            return False

        if request.method not in self.audited_methods:
            return True

        # Skip logging if the request carries no credentials at all
        if not ENABLE_AUDIT_UNAUTHENTICATED_REQUESTS and not _credential_offered(request):
            return True

        # Whitelist mode: only log paths that match included_paths
        if self._included_pattern:
            return not self._included_pattern.match(path)

        # Blacklist mode: skip paths that match excluded_paths
        if self._excluded_pattern and self._excluded_pattern.match(path):
            return True

        return False

    def _request_body_unread(self, request: Request, context: AuditContext) -> bool:
        """True when the body was never fully delivered to this middleware.

        The capture wraps `receive`, so it only ever sees what the application
        asks for. A request rejected before its body is parsed — an auth
        dependency answering 401, a client that hangs up — leaves the record
        holding a prefix, or nothing at all, with no sign that anything is
        missing. That is worse than an ordinary truncation: an empty
        `request_object` reads as "this request sent no body".
        """
        if not self._capture_request_body or context.request_complete:
            return False

        declared = request.headers.get('content-length')
        if declared is not None:
            try:
                return int(declared) > len(context.request_body)
            except ValueError:
                return True

        # Chunked, or HTTP/2, which has no `Transfer-Encoding` at all and does not require `Content-
        # Length` either.
        return (
            bool(request.headers.get('transfer-encoding'))
            or bool(request.headers.get('content-type'))
            or bool(context.request_body)
        )

    def _response_body_unread(self, context: AuditContext) -> bool:
        """True when the response body was never delivered in full.

        The mirror of `_request_body_unread`. A stream that raises part-way, is
        cancelled, or loses its client never sends the final
        `http.response.body`, so the record holds a prefix that is under
        `max_body_size` and therefore carries no truncation flag of its own — a
        partial response presented as the whole one, on exactly the entries
        that also carry an `error` and most deserve to be read carefully.

        A response that never started is fully described by `error`; there is
        no body to mislabel, so it is not flagged.
        """
        if not self._capture_response_body or context.response_complete:
            return False
        return context.status_code is not None

    def _build_entry(self, request: Request, context: AuditContext) -> AuditLogEntry:
        path = request.scope.get('path', '')
        raw_request_body = context.request_body.decode('utf-8', errors='replace')
        # What served the request wins over what it asked for: an arena request names the arena, the
        # response names the sub-model that ran.
        requested_body = (
            context.model_scan.decode('utf-8', errors='replace') if context.model_scan else raw_request_body
        )
        model = context.response_model or _state_model(request) or _request_model(requested_body)

        # Whether each capture is all there was.
        request_complete = not (context.request_truncated or self._request_body_unread(request, context))
        response_complete = not (context.response_truncated or self._response_body_unread(context))

        request_body = _redact(raw_request_body, path, complete=request_complete)
        # Responses carry secrets too — a sign-in response body holds the JWT.
        response_body = _redact(
            context.response_body.decode('utf-8', errors='replace'), path, complete=response_complete
        )

        usage = None
        usage_truncated = False
        if AUDIT_USAGE_ENABLED:
            recorded = getattr(request.state, 'audit_usage', None)
            if not (isinstance(recorded, dict) and recorded):
                # Nothing reported this route's usage, so fall back to what the
                # response itself carried.
                recorded = context.response_usage
            if isinstance(recorded, dict) and recorded:
                usage, usage_truncated = _bounded_redacted_usage(recorded, normalize=False)

        # Bounded before redaction, so an oversized message costs one slice
        # rather than a full regex pass over megabytes of provider payload.
        error_text, error_truncated = _truncate_error(context.error)

        return AuditLogEntry(
            id=str(uuid.uuid4()),
            user=self._resolve_user(request),
            audit_level=self.audit_level.value,
            verb=request.method,
            request_uri=_redact_uri(str(request.url)),
            response_status_code=context.status_code,
            source_ip=request.client.host if request.client else None,
            user_agent=request.headers.get('user-agent'),
            request_object=request_body,
            response_object=response_body,
            model=model,
            usage=usage,
            usage_truncated=usage_truncated,
            duration_ms=context.duration_ms,
            request_object_truncated=not request_complete,
            response_object_truncated=not response_complete,
            error=_redact_error(error_text, path, complete=not error_truncated),
            error_truncated=error_truncated,
        )

    def _log_audit_entry(self, request: Request, context: AuditContext):
        try:
            entry = self._build_entry(request, context)
        except BaseException as exc:
            # Losing the event is not an option; degrade to what can be read
            # straight off the ASGI scope and record why.
            try:
                scope = request.scope
                entry = AuditLogEntry(
                    id=str(uuid.uuid4()),
                    user=None,
                    audit_level=self.audit_level.value,
                    verb=scope.get('method', ''),
                    request_uri=scope.get('path', ''),
                    response_status_code=context.status_code,
                    duration_ms=context.duration_ms,
                    model=context.response_model,
                    error=f'audit entry build failed: {type(exc).__name__}: {exc}',
                )
            except BaseException:
                _emit_last_resort({'audit_error': 'failed to build audit entry'}, exc)
                return

        # Work finishing after the response (the UI chat path) can no longer be folded into this
        # entry, so leave what a follow-up needs to reference it.
        try:
            request.scope.setdefault('state', {})['audit_receipt'] = {
                'id': entry.id,
                'user': entry.user,
                'audit_level': entry.audit_level,
                'verb': entry.verb,
                'request_uri': entry.request_uri,
                'source_ip': entry.source_ip,
                'user_agent': entry.user_agent,
                'model': entry.model,
            }
        except Exception:
            pass

        self.audit_logger.write(entry)
