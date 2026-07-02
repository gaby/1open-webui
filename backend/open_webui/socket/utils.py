"""Redis-backed distributed data structures for WebSocket state management."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid

import pycrdt as Y
from open_webui.env import REDIS_KEY_PREFIX

log = logging.getLogger(__name__)

YDOC_KEY_PREFIX = f'{REDIS_KEY_PREFIX}:ydoc:documents'


class AsyncRedisLock:
    """Distributed lock backed by a Redis SET with NX/EX semantics.

    All methods are coroutines running on an async Redis client, so lock
    operations never block the event loop.
    """

    def __init__(self, redis, lock_name, timeout_secs):
        self.redis = redis
        self.lock_name = lock_name
        self.lock_id = str(uuid.uuid4())
        self.timeout_secs = timeout_secs

    async def acquire(self) -> bool:
        # nx=True will only set this key if it _hasn't_ already been set
        return bool(await self.redis.set(self.lock_name, self.lock_id, nx=True, ex=self.timeout_secs))

    async def renew(self) -> bool:
        # xx=True will only set this key if it _has_ already been set
        return bool(await self.redis.set(self.lock_name, self.lock_id, xx=True, ex=self.timeout_secs))

    async def release(self):
        lock_value = await self.redis.get(self.lock_name)
        if lock_value and lock_value == self.lock_id:
            await self.redis.delete(self.lock_name)


class AsyncNoopLock:
    """Single-node twin of AsyncRedisLock: always succeeds, holds no state."""

    async def acquire(self) -> bool:
        return True

    async def renew(self) -> bool:
        return True

    async def release(self):
        pass


class AsyncRedisDict:
    """Async dict-like store over a single Redis hash. All methods are coroutines."""

    def __init__(self, name, redis):
        self.name = name
        self.redis = redis

    async def get(self, key, default=None):
        value = await self.redis.hget(self.name, key)
        return default if value is None else json.loads(value)

    async def set(self, key, value):
        await self.redis.hset(self.name, key, json.dumps(value))

    async def delete(self, key) -> bool:
        return bool(await self.redis.hdel(self.name, key))

    async def contains(self, key) -> bool:
        return bool(await self.redis.hexists(self.name, key))

    async def keys(self) -> list:
        return list(await self.redis.hkeys(self.name))

    async def items(self) -> list:
        return [(k, json.loads(v)) for k, v in (await self.redis.hgetall(self.name)).items()]

    async def mget(self, keys: list) -> dict:
        """Batch fetch — a single HMGET round trip; missing keys are omitted."""
        if not keys:
            return {}
        values = await self.redis.hmget(self.name, keys)
        return {k: json.loads(v) for k, v in zip(keys, values) if v is not None}

    async def clear(self):
        await self.redis.delete(self.name)


class AsyncInMemoryDict:
    """Single-node twin of AsyncRedisDict backed by a plain dict."""

    def __init__(self):
        self._data = {}

    async def get(self, key, default=None):
        return self._data.get(key, default)

    async def set(self, key, value):
        self._data[key] = value

    async def delete(self, key) -> bool:
        return self._data.pop(key, None) is not None

    async def contains(self, key) -> bool:
        return key in self._data

    async def keys(self) -> list:
        return list(self._data.keys())

    async def items(self) -> list:
        return list(self._data.items())

    async def mget(self, keys: list) -> dict:
        return {k: self._data[k] for k in keys if k in self._data}

    async def clear(self):
        self._data.clear()


class LocalCachedRedisDict:
    """Redis-backed dict with a per-process read replica.

    Reads use the plain sync dict interface served entirely from process
    memory, so hot read paths (`in`, `[]`, `**`-unpacking) never touch Redis
    or block the event loop. Writes go through async `set()` on the shared
    async Redis client, and `periodic_refresh()` keeps the replica in sync
    with writes from other pods (eventually consistent, one refresh interval
    of lag at most).
    """

    REFRESH_INTERVAL = 5  # seconds between replica refreshes from Redis

    def __init__(self, name, redis):
        self.name = name
        self.redis = redis
        self._local: dict = {}
        # Per-process cache of the last payload fingerprint written by set().
        # Used to skip redundant HSET round-trips when the model list hasn't
        # changed — the dominant Redis write source on busy multi-pod setups.
        self._last_signature: str | None = None

    def __getitem__(self, key):
        return self._local[key]

    def __contains__(self, key):
        return key in self._local

    def __len__(self):
        return len(self._local)

    def __iter__(self):
        return iter(self._local)

    def get(self, key, default=None):
        return self._local.get(key, default)

    def keys(self):
        return self._local.keys()

    def values(self):
        return self._local.values()

    def items(self):
        return self._local.items()

    async def set(self, mapping: dict):
        # The local replica is updated first so this pod reads fresh data
        # immediately, even if the Redis write below fails.
        self._local = dict(mapping)

        if not mapping:
            await self.redis.delete(self.name)
            self._last_signature = None
            return

        # Serialize values once — reused for both the fingerprint and the write.
        serialized = {k: json.dumps(v) for k, v in mapping.items()}

        # Skip the write when the prepared mapping is identical to the last one
        # this process wrote.  The check is per-instance (not distributed), but
        # still eliminates the majority of redundant writes because each pod
        # typically produces the same model list on consecutive refreshes.
        signature = hashlib.sha256(json.dumps(serialized, sort_keys=True).encode()).hexdigest()
        if signature == self._last_signature:
            return

        # Fetch existing keys before writing so we know which ones to remove.
        # HKEYS is cheap — it transfers only short key strings, not large JSON values.
        existing_keys = set(await self.redis.hkeys(self.name))
        keys_to_remove = existing_keys - set(mapping.keys())

        # HSET first (add/update all new values), then HDEL (remove stale keys).
        # We never DELETE the whole hash — this eliminates the race window
        # where concurrent readers would see an empty models dict.
        await self.redis.hset(self.name, mapping=serialized)
        if keys_to_remove:
            await self.redis.hdel(self.name, *keys_to_remove)

        self._last_signature = signature

    async def refresh(self):
        raw = await self.redis.hgetall(self.name)
        self._local = {k: json.loads(v) for k, v in raw.items()}

    async def periodic_refresh(self):
        while True:
            # Refresh-first so a freshly started pod serves models cached by
            # its peers before its own get_all_models() run completes.
            try:
                await self.refresh()
            except Exception:
                log.exception(f'Failed to refresh local replica of {self.name} from Redis')
            await asyncio.sleep(self.REFRESH_INTERVAL)


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
            await self._redis.rpush(redis_key, json.dumps(list(update)))
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
            ydoc.apply_update(bytes(json.loads(raw)))
        snapshot = json.dumps(list(ydoc.get_update()))
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
            return [bytes(json.loads(update)) for update in updates]
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
