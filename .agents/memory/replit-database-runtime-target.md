---
name: Replit database runtime target
description: Environment-specific separation between the managed database tool and shell PostgreSQL connection.
---

The Replit-managed development database available through the database tool is PostgreSQL 17.11, while the workspace shell's `PG*` connection reached a separate PostgreSQL 16.10 instance. They are not interchangeable. The existing `DATABASE_URL` is reserved for the project's Supabase connection and must not be used as a fallback for Replit development persistence.

**Why:** Applying a schema through the managed database tool does not make it visible to the app's existing shell/runtime connection. Assuming the two targets match could send application queries to the wrong database or to Supabase.

**How to apply:** Before wiring a repository into request handling, verify the runtime connection target using a separately named server-side connection setting and confirm its role is non-superuser and does not bypass RLS. Never overwrite `DATABASE_URL` to resolve this mismatch.
