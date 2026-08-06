"""DNS resolver selection for aiohttp.

Merely having ``aiodns`` installed flips aiohttp's ``DefaultResolver`` from
``ThreadedResolver`` (``socket.getaddrinfo``, i.e. the platform resolver stack)
to ``AsyncResolver`` (c-ares, resolving on the event loop).  That keeps DNS off
the shared executor thread pool, but c-ares only reads ``/etc/resolv.conf`` and
the hosts file -- it does not go through ``nsswitch.conf``, mDNS/``.local``,
NetBIOS, or the Windows resolver, and it snapshots ``resolv.conf`` once per
process instead of re-reading it per lookup.

Names that only the OS resolver knows about therefore stop resolving: Docker
Compose service names served by the embedded resolver at 127.0.0.11, hosts
behind a DNS64/NAT64 translator, and anything the platform stack resolves
outside plain DNS.

``AIOHTTP_CLIENT_RESOLVER`` picks the strategy:

    auto      (default) c-ares first, transparently falling back to
              ``getaddrinfo`` for names c-ares cannot resolve
    aiodns    c-ares only -- aiohttp's own behaviour once aiodns is installed
    threaded  ``getaddrinfo`` only -- the behaviour from before aiodns was added

``install()`` points aiohttp's ``DefaultResolver`` at the configured strategy so
that every ``ClientSession`` picks it up, including the many that build a
connector with no explicit ``resolver=``.
"""

import asyncio
import logging
import socket
import time
from collections import OrderedDict
from typing import Any

import aiohttp
import aiohttp.connector
import aiohttp.resolver
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import ThreadedResolver
from open_webui.env import AIOHTTP_CLIENT_RESOLVER, AIOHTTP_POOL_DNS_TTL

log = logging.getLogger(__name__)

# True when aiodns is importable, i.e. when aiohttp would default to c-ares.
AIODNS_AVAILABLE: bool = aiohttp.resolver.aiodns_default

# What counts as "c-ares could not resolve this, try the OS instead".
# AsyncResolver.resolve() converts the DNSError out of getaddrinfo() into an
# OSError, but not the one out of the getnameinfo() call it makes for
# link-local IPv6, so the c-ares errors have to be caught in their own right.
_RESOLVE_ERRORS: tuple[type[BaseException], ...] = (OSError,)
if AIODNS_AVAILABLE:
    import aiodns.error
    import pycares

    _RESOLVE_ERRORS = (OSError, aiodns.error.DNSError, pycares.AresError)

# Names that needed the getaddrinfo fallback, mapped to a monotonic expiry, in
# least-recently-used order.  Shared across resolver instances: aiohttp builds
# one resolver per connector, and the whole point is to not re-pay the c-ares
# timeout on every request.
#
# The entry is re-stamped on every hit, so a host stays on getaddrinfo for as
# long as it keeps being used and only ages out after a full TTL of no traffic.
# Expiring an in-use entry would put a c-ares timeout back in front of a user
# request once per TTL, forever, which is the cost this map exists to avoid.
_FALLBACK_HOSTS: OrderedDict[str, float] = OrderedDict()
_FALLBACK_TTL = AIOHTTP_POOL_DNS_TTL
_FALLBACK_MAX_HOSTS = 1024


class FallbackResolver(AbstractResolver):
    """c-ares resolver that hands names it cannot resolve to ``getaddrinfo``.

    c-ares is tried first so DNS stays off the executor thread pool.  When it
    fails, the name goes to the platform resolver, which is the one that knows
    about Docker's embedded DNS, mDNS, NetBIOS and everything else reached
    through ``nsswitch.conf``.

    A name that needed the fallback is remembered so later lookups skip c-ares
    instead of paying its timeout again, and stays remembered for as long as it
    keeps being used, ageing out after ``AIOHTTP_POOL_DNS_TTL`` seconds of no
    traffic.  A name that neither resolver can resolve is *not* remembered -- a
    host that genuinely does not exist should keep failing fast.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self._loop = loop
        # Built lazily: AsyncResolver/ThreadedResolver both want a running loop.
        self._async: AbstractResolver | None = None
        self._threaded: AbstractResolver | None = None

    def _async_resolver(self) -> AbstractResolver:
        if self._async is None:
            self._async = aiohttp.resolver.AsyncResolver(loop=self._loop)
        return self._async

    def _threaded_resolver(self) -> AbstractResolver:
        if self._threaded is None:
            self._threaded = ThreadedResolver(loop=self._loop)
        return self._threaded

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[ResolveResult]:
        if _needs_fallback(host):
            return await self._threaded_resolver().resolve(host, port, family)

        try:
            return await self._async_resolver().resolve(host, port, family)
        except _RESOLVE_ERRORS as exc:
            log.debug('c-ares could not resolve %r (%s), retrying with getaddrinfo', host, exc)

        results = await self._threaded_resolver().resolve(host, port, family)
        # Reached only when getaddrinfo succeeded where c-ares did not.
        _remember_fallback(host)
        log.info(
            'Resolved %r via getaddrinfo after c-ares failed; keeping it on getaddrinfo while '
            'it stays in use. Set AIOHTTP_CLIENT_RESOLVER=threaded to skip c-ares entirely.',
            host,
        )
        return results

    async def close(self) -> None:
        for resolver in (self._async, self._threaded):
            if resolver is not None:
                await resolver.close()
        self._async = None
        self._threaded = None


def _needs_fallback(host: str) -> bool:
    """Whether ``host`` is known to need ``getaddrinfo``, re-stamping it if so."""
    expiry = _FALLBACK_HOSTS.get(host)
    if expiry is None:
        return False
    now = time.monotonic()
    if expiry <= now:
        _FALLBACK_HOSTS.pop(host, None)
        return False
    _FALLBACK_HOSTS[host] = now + _FALLBACK_TTL
    _FALLBACK_HOSTS.move_to_end(host)
    return True


def _remember_fallback(host: str) -> None:
    now = time.monotonic()
    _FALLBACK_HOSTS[host] = now + _FALLBACK_TTL
    _FALLBACK_HOSTS.move_to_end(host)

    for stale in [h for h, expiry in _FALLBACK_HOSTS.items() if expiry <= now]:
        del _FALLBACK_HOSTS[stale]
    # Evict least-recently-used rather than clearing: the names reaching this
    # map include user-supplied ones (the SSRF-safe resolver runs its global-IP
    # check on the result, i.e. after the name is recorded), so a flood of junk
    # hostnames must not be able to drop the entries doing real work.
    while len(_FALLBACK_HOSTS) > _FALLBACK_MAX_HOSTS:
        _FALLBACK_HOSTS.popitem(last=False)


def get_resolver_class() -> type[AbstractResolver]:
    """The resolver class ``AIOHTTP_CLIENT_RESOLVER`` selects."""
    if AIOHTTP_CLIENT_RESOLVER == 'threaded':
        return ThreadedResolver

    if not AIODNS_AVAILABLE:
        # aiohttp would fall back to getaddrinfo anyway; say so once rather than
        # letting an explicit `aiodns` request silently do something else.
        if AIOHTTP_CLIENT_RESOLVER == 'aiodns':
            log.warning('AIOHTTP_CLIENT_RESOLVER=aiodns but aiodns is not installed; using getaddrinfo')
        return ThreadedResolver

    if AIOHTTP_CLIENT_RESOLVER == 'aiodns':
        return aiohttp.resolver.AsyncResolver

    return FallbackResolver


#: Resolver class every aiohttp connector in the app should use.  Subclass this
#: rather than ``aiohttp.resolver.DefaultResolver`` so the choice holds no matter
#: when the subclassing module is imported.
DEFAULT_RESOLVER_CLASS: type[AbstractResolver] = get_resolver_class()


def make_resolver(*args: Any, **kwargs: Any) -> AbstractResolver:
    """Build a resolver of the configured kind."""
    return DEFAULT_RESOLVER_CLASS(*args, **kwargs)


def install() -> None:
    """Make ``DEFAULT_RESOLVER_CLASS`` the default for every aiohttp connector.

    ``TCPConnector`` reads ``DefaultResolver`` from ``aiohttp.connector``'s own
    namespace at construction time, so that binding is the one that matters.
    ``aiohttp.resolver`` and the ``aiohttp.DefaultResolver`` alias re-exported
    from ``aiohttp/__init__.py`` are patched too, so code reaching for either of
    those gets the configured resolver rather than aiohttp's own default.  Call
    this before the first connector is built.
    """
    aiohttp.resolver.DefaultResolver = DEFAULT_RESOLVER_CLASS
    aiohttp.connector.DefaultResolver = DEFAULT_RESOLVER_CLASS
    aiohttp.DefaultResolver = DEFAULT_RESOLVER_CLASS
    log.info(
        'aiohttp DNS resolver: %s (AIOHTTP_CLIENT_RESOLVER=%s, aiodns %s)',
        DEFAULT_RESOLVER_CLASS.__name__,
        AIOHTTP_CLIENT_RESOLVER,
        'available' if AIODNS_AVAILABLE else 'not installed',
    )


install()
