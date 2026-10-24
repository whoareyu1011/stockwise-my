"use strict";

function isPublicSupabaseKey(value) {
  if (typeof value !== "string" || value.length > 4096 || /\s/.test(value)) {
    return false;
  }

  if (/^sb_publishable_[A-Za-z0-9_-]+$/.test(value)) return true;

  // Supabase's legacy public anon key is a JWT. Reject service-role JWTs.
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return payload?.iss === "supabase" && payload?.role === "anon";
  } catch {
    return false;
  }
}

function readSupabasePublicConfig(env = process.env) {
  if (!env || typeof env !== "object" || Array.isArray(env)) return null;
  const projectUrl = typeof env.SUPABASE_URL === "string"
    ? env.SUPABASE_URL.trim()
    : "";
  const publishableKey = typeof env.SUPABASE_PUBLISHABLE_KEY === "string"
    ? env.SUPABASE_PUBLISHABLE_KEY.trim()
    : "";
  if (!projectUrl || !isPublicSupabaseKey(publishableKey)) return null;

  try {
    const parsed = new URL(projectUrl);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password ||
        parsed.search || parsed.hash || !["", "/"].includes(parsed.pathname) ||
        parsed.hostname.length < 3) {
      return null;
    }
    return Object.freeze({
      projectUrl: parsed.origin,
      publishableKey,
    });
  } catch {
    return null;
  }
}

module.exports = { isPublicSupabaseKey, readSupabasePublicConfig };
