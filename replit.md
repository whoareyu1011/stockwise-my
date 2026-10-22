# StockWise MY

## Run on Replit
- Click Run to start the **Start application** workflow.
- Command: `python3 server.py`
- The server binds to `0.0.0.0:5000`; open Preview to use the app.
- Python 3.12 is configured through Replit. No third-party packages, secrets,
  database, or external services are required for this prototype.

## Project structure
- `index.html` is the original single-file HTML/CSS/JavaScript app.
- `server.py` serves only `/` and `/index.html`, not repository files.
- Keep the imported structure and stack intact unless explicitly asked otherwise.

## Existing prototype limitations
- Inventory and invoice records are stored in this browser's localStorage,
  not on the server. They are not shared between browsers/devices and can be
  lost if browser storage is cleared.
- E-invoices are drafts only. There is no official LHDN MyInvois submission,
  real OCR, authentication, or secure server-side business-data storage.
- Do not use this prototype as a compliant production invoicing system.
