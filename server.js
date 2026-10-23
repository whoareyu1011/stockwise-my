const express = require("express");
const path = require("node:path");

const indexPath = path.join(__dirname, "index.html");

function createApp() {
  const app = express();

  app.get("/api/health/live", (_request, response) => {
    response.set("Cache-Control", "no-store");
    response.json({
      success: true,
      status: "ok",
      check: "application-only",
    });
  });

  // Retain a clear response for clients of the old path without touching PostgreSQL.
  app.get("/api/health/db", (_request, response) => {
    response.set("Cache-Control", "no-store");
    response.status(410).json({
      success: false,
      code: "DATABASE_HEALTH_DISABLED",
      error: "Database health checks are disabled; use /api/health/live for application liveness.",
    });
  });

  // Secure database-backed product reads are not configured yet.
  // Fail explicitly instead of returning demo data or using DATABASE_URL.
  app.get("/api/products", (_request, response) => {
    response.set("Cache-Control", "no-store");
    response.status(501).json({
      success: false,
      code: "PRODUCTS_API_NOT_CONFIGURED",
      error: "Secure product reads are not configured.",
    });
  });

  app.get(["/", "/index.html"], (_request, response) => {
    response.sendFile(indexPath);
  });

  app.get("/favicon.ico", (_request, response) => response.sendStatus(204));

  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 5000;
  createApp().listen(port, "0.0.0.0", () => {
    console.log(`StockWise MY server listening on port ${port}`);
  });
}

module.exports = { createApp };
