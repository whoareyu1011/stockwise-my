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
- Shared pooler hosts ending in `.pooler.supabase.com` use the bundled public
  Supabase Root 2021 CA at `certs/supabase-ca.crt` unless the CA environment
  override above is set. This is a public certificate, not a private key.
- The Node `pg` client requires TLS and verifies the server certificate.
- Open `/api/health/db` in the Replit preview. Success returns
  `{"success":true,"database":"connected"}`. Failures return a generic safe
  response; the server logs sanitized errors and the hostname, port, and username,
  never the password or full connection URL.
- This endpoint runs `SELECT NOW()` only. It does not create or change tables.

### CA certificate source and renewal
- Official guidance: https://supabase.com/docs/guides/platform/ssl-enforcement
- Manual download: open the Supabase project dashboard, go to Database Settings,
  find **SSL Configuration**, and select **Download certificate**. Replace the
  bundled public CA only with the certificate from that official source.
- The official dashboard's production download URL is
  https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt
  (verified against Supabase's dashboard custom-content source).
- Current certificate subject: Supabase Root 2021 CA; expires April 26, 2031.
- SHA-256 fingerprint:
  `80:70:25:AD:50:D4:ED:21:9D:2C:9C:7D:29:9C:00:4F:82:4E:B0:0C:F7:F6:5A:FE:F6:07:D0:7B:72:E6:CA:FA`.
- This public CA can be tracked with the server code. It is not served by the
  Express routes. Never store a database password or private key alongside it.
- Restart the app after updating the CA; do not bypass certificate verification.

## Existing prototype limitations
- Inventory and invoice records are stored in this browser's localStorage,
  not on the server. They are not shared between browsers/devices and can be
  lost if browser storage is cleared.
- E-invoices are drafts only. There is no official LHDN MyInvois submission,
  real OCR, authentication, or secure server-side business-data storage.
- Do not use this prototype as a compliant production invoicing system.
