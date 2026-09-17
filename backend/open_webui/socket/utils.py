"""Redis-backed distributed data structures for WebSocket state management.

Everything here talks to Redis through the async client. The sync client that
was used before blocked the event loop for a full round trip on every socket
connect, heartbeat, usage report and disconnect, and for a whole ``HGETALL`` of
the model registry on every chat request.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import suppress

import pycrdt as Y
from open_webui.env import REDIS_KEY_PREFIX
from open_webui.utils.json_codec import JSONCodec
from open_webui.utils.redis import get_redis_connection
from redis.exceptions import RedisClusterException, RedisError

log = logging.getLogger(__name__)

YDOC_KEY_PREFIX = f'{REDIS_KEY_PREFIX}:ydoc:documents'
SCAN_BATCH_SIZE = 200

# ReplicatedDict re-checks the shared signature this often even when no
# invalidation arrives: it covers a dropped pub/sub connection and writers that
# predate the invalidation channel (a rolling upgrade).
REPLICATION_POLL_INTERVAL = 5.0
REPLICATION_RECONNECT_INTERVAL = 1.0
REPLICATION_MAX_RECONNECT_INTERVAL = 30.0

_MISSING = object()


class RedisLock:
    """Distributed lock backed by a Redis SET with NX/EX semantics."""

    _RENEW_SCRIPT = """
    if redis.call('get', KEYS[1]) == ARGV[1] then
        return redis.call('expire', KEYS[1], ARGV[2])
    end
    return 0
    """
    _RELEASE_SCRIPT = """
    if redis.call('get', KEYS[1]) == ARGV[1] then
        return redis.call('del', KEYS[1])
    end
    return 0
    """

    def __init__(
        self,
        redis_url,
        lock_name,
        timeout_secs,
        redis_sentinels=[],
        redis_cluster=False,
    ):
        self.lock_name = lock_name
        self.lock_id = str(uuid.uuid4())
        self.timeout_secs = timeout_secs
        self.lock_obtained = False
        self.redis = get_redis_connection(
            redis_url,
            redis_sentinels,
            redis_cluster=redis_cluster,
            async_mode=True,
            decode_responses=True,
        )

    async def aquire_lock(self) -> bool:
        # nx=True will only set this key if it _hasn't_ already been set
        self.lock_obtained = bool(await self.redis.set(self.lock_name, self.lock_id, nx=True, ex=self.timeout_secs))
        return self.lock_obtained

    async def renew_lock(self) -> bool:
        return bool(await self.redis.eval(self._RENEW_SCRIPT, 1, self.lock_name, self.lock_id, self.timeout_secs))

    async def release_lock(self) -> None:
        try:
            await self.redis.eval(self._RELEASE_SCRIPT, 1, self.lock_name, self.lock_id)
        except (RedisClusterException, RedisError) as e:
            log.warning('Failed to release lock %s; it expires on its own: %s', self.lock_name, e)


class LocalLock:
    """Single-process stand-in for RedisLock: there is nobody to contend with."""

    async def aquire_lock(self) -> bool:
        return True

    async def renew_lock(self) -> bool:
        return True

    async def release_lock(self) -> None:
        return None


class RedisDict:
    """Awaitable dict-like view of one Redis hash, for state shared across instances."""

    def __init__(
        self,
        name,
        redis_url,
        redis_sentinels=[],
        redis_cluster=False,
    ):
        self.name = name
        self.redis = get_redis_connection(
            redis_url,
            redis_sentinels,
            redis_cluster=redis_cluster,
            async_mode=True,
            decode_responses=True,
        )

    async def get(self, key, default=None):
        value = await self.redis.hget(self.name, key)
        return default if value is None else JSONCodec.loads(value)

    async def set(self, key, value) -> None:
        await self.redis.hset(self.name, key, JSONCodec.dumps(value))

    async def delete(self, key) -> bool:
        """Remove ``key``; False when it was not there."""
        return bool(await self.redis.hdel(self.name, key))

    async def delete_many(self, *keys) -> None:
        """Delete fields in one HDEL; no keys is a no-op (HDEL rejects an empty field list)."""
        if keys:
            await self.redis.hdel(self.name, *keys)

    async def contains(self, key) -> bool:
        return bool(await self.redis.hexists(self.name, key))

    async def keys(self) -> list:
        return await self.redis.hkeys(self.name)

    async def values(self) -> list:
        return [JSONCodec.loads(v) for v in await self.redis.hvals(self.name)]

    async def items(self) -> list[tuple]:
        return [(k, JSONCodec.loads(v)) for k, v in (await self.redis.hgetall(self.name)).items()]

    async def scan_batches(self) -> AsyncIterator[list[tuple]]:
        """Yield lists of (key, value) pairs via incremental HSCAN; a field may repeat across batches."""
        cursor = 0
        while True:
            cursor, batch = await self.redis.hscan(self.name, cursor, count=SCAN_BATCH_SIZE)
            if batch:
                yield [(k, JSONCodec.loads(v)) for k, v in batch.items()]
            if cursor == 0:
                break

    async def clear(self) -> None:
        await self.redis.delete(self.name)


class LocalDict:
    """In-process counterpart of RedisDict with the same awaitable API."""

    def __init__(self):
        self._data: dict = {}

    async def get(self, key, default=None):
        return self._data.get(key, default)

    async def set(self, key, value) -> None:
        self._data[key] = value

    async def delete(self, key) -> bool:
        return self._data.pop(key, _MISSING) is not _MISSING

    async def delete_many(self, *keys) -> None:
        for key in keys:
            self._data.pop(key, None)

    async def contains(self, key) -> bool:
        return key in self._data

    async def keys(self) -> list:
        return list(self._data)

    async def values(self) -> list:
        return list(self._data.values())

    async def items(self) -> list[tuple]:
        return list(self._data.items())

    async def scan_batches(self) -> AsyncIterator[list[tuple]]:
        yield list(self._data.items())

    async def clear(self) -> None:
        self._data.clear()


class ReplicatedDict:
    """A read-mostly dict shared through Redis and replicated into every instance.

    Reads (``get``, ``in``, ``[]``, ``items`` …) are plain lookups on a local
    snapshot, so they never touch Redis and never block the event loop. ``set``
    writes the whole mapping to Redis and publishes an invalidation; ``run``
    keeps the snapshot current by following those invalidations and by
    re-checking the shared signature every ``poll_interval`` seconds.

    Snapshots are replaced, never mutated, so an iteration that is under way
    keeps seeing one consistent mapping while a refresh lands.
    """

    def __init__(
        self,
        name,
        redis_url,
        redis_sentinels=[],
        redis_cluster=False,
        poll_interval: float = REPLICATION_POLL_INTERVAL,
    ):
        self.name = name
        self._signature_name = f'{name}:signature'
        self._channel = f'{name}:invalidations'
        self._poll_interval = poll_interval
        self.redis = get_redis_connection(
            redis_url,
            redis_sentinels,
            redis_cluster=redis_cluster,
            async_mode=True,
            decode_responses=True,
        )
        self._data: dict = {}
        self._signature: str | None = None

    # -- local snapshot: synchronous, no I/O --------------------------------

    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key) -> bool:
        return key in self._data

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    # -- replication ---------------------------------------------------------

    @staticmethod
    def _fingerprint(serialized: dict[str, str]) -> str:
        digest = hashlib.sha256()
        for key in sorted(serialized):
            digest.update(key.encode())
            digest.update(b'\0')
            digest.update(serialized[key].encode())
            digest.update(b'\0')
        return digest.hexdigest()

    async def set(self, mapping: dict) -> None:
        """Replace the whole mapping, locally first and then in Redis.

        The snapshot is swapped before any I/O, so this instance serves what it
        just computed even when replication fails; the error is re-raised for
        the caller to report, and the next ``set`` or ``refresh`` re-syncs.
        """
        serialized = {k: JSONCodec.dumps(v) for k, v in mapping.items()}
        signature = self._fingerprint(serialized)
        self._data = dict(mapping)
        if signature == self._signature:
            return

        self._signature = None
        if await self.redis.get(self._signature_name) != signature:
            await self._write(serialized, signature)
        self._signature = signature

    async def _write(self, serialized: dict[str, str], signature: str) -> None:
        # HSET first (add/update), then HDEL the stale fields. The hash is never
        # DELeted outright, so a concurrent reader never sees an empty registry.
        stale = set(await self.redis.hkeys(self.name)) - serialized.keys()
        if serialized:
            await self.redis.hset(self.name, mapping=serialized)
        if stale:
            await self.redis.hdel(self.name, *stale)
        await self.redis.set(self._signature_name, signature)
        await self.redis.publish(self._channel, signature)

    async def refresh(self) -> bool:
        """Reload the snapshot if the shared signature moved; True when it did."""
        signature = await self.redis.get(self._signature_name)
        if signature == self._signature:
            return False
        # Signature before data: a write that lands in between leaves the data
        # newer than the signature we keep, so the next check reloads again.
        raw = await self.redis.hgetall(self.name)
        self._data = {k: JSONCodec.loads(v) for k, v in raw.items()}
        self._signature = signature
        return True

    async def run(self) -> None:
        """Keep the snapshot current until cancelled, reconnecting with backoff."""
        reconnect_interval = REPLICATION_RECONNECT_INTERVAL
        while True:
            try:
                await self._follow()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception('%s replication failed; retrying in %.1fs', self.name, reconnect_interval)
            await asyncio.sleep(reconnect_interval)
            reconnect_interval = min(reconnect_interval * 2, REPLICATION_MAX_RECONNECT_INTERVAL)

    async def _follow(self) -> None:
        await self.refresh()
        # RedisCluster can't route a pubsub subscribe until initialize() fills its slot cache.
        await self.redis.initialize()
        pubsub = self.redis.pubsub()
        try:
            await pubsub.subscribe(self._channel)
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=self._poll_interval)
                # A timeout is the periodic backstop; our own publish echoes back and is skipped.
                if message is None or message.get('data') != self._signature:
                    await self.refresh()
        finally:
            with suppress(Exception):
                await pubsub.aclose()


class YdocManager:
    COMPACTION_THRESHOLD = 500

    def __init__(
        self,
        redis=None,
        redis_key_prefix: str = YDOC_KEY_PREFIX,
    ):
        self._updates = {}
        self._users = {}
        self._redis = redis
        self._redis_key_prefix = redis_key_prefix

    async def append_to_updates(self, document_id: str, update: bytes):
        document_id = document_id.replace(':', '_')
        if self._redis:
            redis_key = f'{self._redis_key_prefix}:{document_id}:updates'
            await self._redis.rpush(redis_key, JSONCodec.dumps(list(update)))
            list_len = await self._redis.llen(redis_key)
            if list_len >= self.COMPACTION_THRESHOLD:
                await self._compact_updates_redis(document_id)
        else:
            if document_id not in self._updates:
                self._updates[document_id] = []
            self._updates[document_id].append(update)
            if len(self._updates[document_id]) >= self.COMPACTION_THRESHOLD:
                self._compact_updates_memory(document_id)

    async def _compact_updates_redis(self, document_id: str):
        """Rolling compaction: squash oldest half into one snapshot."""
        redis_key = f'{self._redis_key_prefix}:{document_id}:updates'
        all_updates = await self._redis.lrange(redis_key, 0, -1)
        if len(all_updates) <= 1:
            return
        mid = len(all_updates) // 2
        ydoc = Y.Doc()
        for raw in all_updates[:mid]:
            ydoc.apply_update(bytes(JSONCodec.loads(raw)))
        snapshot = JSONCodec.dumps(list(ydoc.get_update()))
        pipe = self._redis.pipeline()
        pipe.delete(redis_key)
        pipe.rpush(redis_key, snapshot, *all_updates[mid:])
        await pipe.execute()

    def _compact_updates_memory(self, document_id: str):
        """Rolling compaction: squash oldest half into one snapshot."""
        updates = self._updates.get(document_id, [])
        if len(updates) <= 1:
            return
        mid = len(updates) // 2
        ydoc = Y.Doc()
        for update in updates[:mid]:
            ydoc.apply_update(bytes(update))
        self._updates[document_id] = [ydoc.get_update()] + updates[mid:]

    async def get_updates(self, document_id: str) -> list[bytes]:
        document_id = document_id.replace(':', '_')

        if self._redis:
            redis_key = f'{self._redis_key_prefix}:{document_id}:updates'
            updates = await self._redis.lrange(redis_key, 0, -1)
            return [bytes(JSONCodec.loads(update)) for update in updates]
        else:
            return self._updates.get(document_id, [])

    async def document_exists(self, document_id: str) -> bool:
        document_id = document_id.replace(':', '_')

        if self._redis:
            redis_key = f'{self._redis_key_prefix}:{document_id}:updates'
            return await self._redis.exists(redis_key) > 0
        else:
            return document_id in self._updates

    async def get_users(self, document_id: str) -> list[str]:
        document_id = document_id.replace(':', '_')

        if self._redis:
            redis_key = f'{self._redis_key_prefix}:{document_id}:users'
            users = await self._redis.smembers(redis_key)
            return list(users)
        else:
            return self._users.get(document_id, [])

    async def add_user(self, document_id: str, user_id: str):
        document_id = document_id.replace(':', '_')

        if self._redis:
            redis_key = f'{self._redis_key_prefix}:{document_id}:users'
            await self._redis.sadd(redis_key, user_id)
            # Maintain a per-session reverse index so disconnect cleanup
            # can look up only the documents this session joined, instead
            # of issuing a cluster-wide SCAN over the entire keyspace.
            session_key = f'{self._redis_key_prefix}:session:{user_id}:documents'
            await self._redis.sadd(session_key, document_id)
        else:
            if document_id not in self._users:
                self._users[document_id] = set()
            self._users[document_id].add(user_id)

    async def remove_user(self, document_id: str, user_id: str):
        document_id = document_id.replace(':', '_')

        if self._redis:
            redis_key = f'{self._redis_key_prefix}:{document_id}:users'
            await self._redis.srem(redis_key, user_id)
            # Keep the reverse index in sync.
            session_key = f'{self._redis_key_prefix}:session:{user_id}:documents'
            await self._redis.srem(session_key, document_id)
        else:
            if document_id in self._users and user_id in self._users[document_id]:
                self._users[document_id].remove(user_id)

    async def remove_user_from_all_documents(self, user_id: str):
        if self._redis:
            # Use the per-session reverse index instead of a cluster-wide
            # SCAN.  This set contains only the document IDs that this
            # session actually joined, so the cost is proportional to
            # the session's footprint — not the total number of documents.
            session_key = f'{self._redis_key_prefix}:session:{user_id}:documents'
            document_ids = await self._redis.smembers(session_key)

            for document_id in document_ids:
                users_key = f'{self._redis_key_prefix}:{document_id}:users'
                await self._redis.srem(users_key, user_id)

                if len(await self.get_users(document_id)) == 0:
                    await self.clear_document(document_id)

            # Clean up the reverse index itself.
            await self._redis.delete(session_key)

        else:
            for document_id in list(self._users.keys()):
                if user_id in self._users[document_id]:
                    self._users[document_id].remove(user_id)
                    if not self._users[document_id]:
                        del self._users[document_id]

                        await self.clear_document(document_id)

    async def clear_document(self, document_id: str):
        document_id = document_id.replace(':', '_')

        if self._redis:
            redis_key = f'{self._redis_key_prefix}:{document_id}:updates'
            await self._redis.delete(redis_key)
            redis_users_key = f'{self._redis_key_prefix}:{document_id}:users'
            await self._redis.delete(redis_users_key)
        else:
            if document_id in self._updates:
                del self._updates[document_id]
            if document_id in self._users:
                del self._users[document_id]
