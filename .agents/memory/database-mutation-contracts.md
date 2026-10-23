---
name: Database mutation contracts
description: Durable rules for product and inventory write idempotency and numeric serialization.
---

Database mutations must be idempotent in the database transaction, not in a process-local cache. Persist the authenticated user, company, command, key, normalized request payload, and original response together with the business change and audit event. On a lost response, do not auto-retry; report uncertainty and allow a retry only with the same identity, scope, command, key, and payload.

**Why:** A process-local idempotency record is lost on restart and cannot protect against concurrent workers; retrying a committed stock adjustment with a new key can double-count inventory.

**How to apply:** Use one narrowly authorized database command per business mutation, store/replay its result atomically, and serialize PostgreSQL `NUMERIC`/`BIGINT` API values as decimal strings so JavaScript does not silently round them.
