# StockWise MY

## Run on Replit
- Click Run to start the **Start application** workflow.
- Command: `npm start`
- Express binds to `0.0.0.0:5000`, serves the existing `index.html`, and provides
  the database health endpoint at `/api/health/db`.
- Node.js 20, Express, and `pg` are configured. `server.py` remains available
  as the original standalone static server.

## Project structure
- `index.html` is the original single-file HTML/CSS/JavaScript app.
- `server.js` serves only the existing page and the database health API; it does
  not expose repository files.
- `server.py` serves only `/` and `/index.html` when run separately.
- Keep the imported structure and stack intact unless explicitly asked otherwise.

## Database connection check
- Set `DATABASE_URL` in Replit Secrets to the PostgreSQL connection URL from
  Supabase. The server reads it at runtime and never returns it from the API.
- Optional: set `SUPABASE_DB_CA_CERT` to the Supabase project's root CA
  certificate in PEM format if your connection requires that certificate for
  verification. Do not put a connection URL or password in source files.
- The Node `pg` client requires TLS and verifies the server certificate.
- Open `/api/health/db` in the Replit preview. Success returns
  `{"success":true,"database":"connected"}`. Failures return a generic safe
  response; the server log records only the error class and diagnostic code.
- This endpoint runs `SELECT NOW()` only. It does not create or change tables.

## Existing prototype limitations
- Inventory and invoice records are stored in this browser's localStorage,
  not on the server. They are not shared between browsers/devices and can be
  lost if browser storage is cleared.
- E-invoices are drafts only. There is no official LHDN MyInvois submission,
  real OCR, authentication, or secure server-side business-data storage.
- Do not use this prototype as a compliant production invoicing system.
