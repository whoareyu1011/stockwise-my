const express = require("express");
const fs = require("node:fs");
const path = require("node:path");
const { Pool } = require("pg");

const app = express();
const port = Number(process.env.PORT) || 5000;
const indexPath = path.join(__dirname, "index.html");
let pool;

function safeDatabaseTarget() {
  try {
    const url = new URL(process.env.DATABASE_URL);
    return {
      hostname: url.hostname,
      port: Number(url.port) || 5432,
      username: decodeURIComponent(url.username),
    };
  } catch {
    return {};
  }
}

function safeDatabaseError(error) {
  const message = String(error.message || "Unknown database error")
    .replace(/postgres(?:ql)?:\/\/[^\s"'<>]+/gi, "[REDACTED_DATABASE_URL]")
    .replace(/\b(password|passwd|pwd)\s*[:=]\s*([^\s,;]+)/gi, "$1=[REDACTED]");

  return {
    ...safeDatabaseTarget(),
    name: error.name || "Error",
    code: error.code || "UNKNOWN",
    message,
  };
}

function getPool() {
  if (pool) return pool;

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    const error = new Error("DATABASE_URL is not configured");
    error.code = "DATABASE_URL_MISSING";
    throw error;
  }

  let connectionUrl;
  try {
    connectionUrl = new URL(databaseUrl);
  } catch {
    const error = new Error("DATABASE_URL is not a valid PostgreSQL URL");
    error.code = "DATABASE_URL_INVALID";
    throw error;
  }

  if (!["postgres:", "postgresql:"].includes(connectionUrl.protocol)) {
    const error = new Error("DATABASE_URL must use PostgreSQL");
    error.code = "DATABASE_URL_INVALID";
    throw error;
  }

  // Require encrypted connections and verify the server certificate.
  // Remove URL SSL options so pg cannot weaken or override this TLS policy.
  for (const option of ["sslmode", "sslrootcert", "sslcert", "sslkey"]) {
    connectionUrl.searchParams.delete(option);
  }
  const ssl = { rejectUnauthorized: true };
  if (process.env.SUPABASE_DB_CA_CERT) {
    ssl.ca = process.env.SUPABASE_DB_CA_CERT;
  } else if (connectionUrl.hostname.endsWith(".pooler.supabase.com")) {
    // Public Supabase root CA, downloaded from the official dashboard source.
    // Keep normal chain and hostname verification enabled.
    ssl.ca = fs.readFileSync(path.join(__dirname, "certs", "supabase-ca.crt"), "utf8");
  }

  pool = new Pool({
    connectionString: connectionUrl.toString(),
    ssl,
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 10000,
    max: 5,
  });

  pool.on("error", (error) => {
    console.error("[database] Idle connection error", safeDatabaseError(error));
  });

  return pool;
}

app.get("/api/health/db", async (_request, response) => {
  try {
    await getPool().query("SELECT NOW()");
    response.json({ success: true, database: "connected" });
  } catch (error) {
    // Report sanitized driver details and parsed connection target fields only.
    // Never log the full URL or password.
    console.error("[database] Health check failed", safeDatabaseError(error));
    response.status(503).json({
      success: false,
      database: "disconnected",
      error: "Database connection check failed",
    });
  }
});

app.get(["/", "/index.html"], (_request, response) => {
  response.sendFile(indexPath);
});

app.get("/favicon.ico", (_request, response) => response.sendStatus(204));

app.listen(port, "0.0.0.0", () => {
  console.log(`StockWise MY server listening on port ${port}`);
});
