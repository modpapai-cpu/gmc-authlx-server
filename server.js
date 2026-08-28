import express from "express";
import crypto from "node:crypto";

const app = express();
app.use(express.json({ limit: "20kb" }));
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST,GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const AUTHLX_URL = (process.env.AUTHLX_URL || "https://api.authlx.com/api/v2/client/").replace(/\/$/, "");
const NAME = process.env.AUTHLX_NAME || "SteamTool";
const OWNERID = process.env.AUTHLX_OWNERID || "c90b8793-0c53-4d57-b8ad-5edaf6dcf0db";
const VERSION = process.env.AUTHLX_VERSION || "1.0";
const SECRET = process.env.AUTHLX_SECRET || "";

function nonce(n = 32) { return crypto.randomBytes(n / 2).toString("hex"); }
function hmac(key, msg) { return crypto.createHmac("sha256", key).update(msg, "utf8").digest("hex"); }
function escapeJson(s) { return String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\b/g, "\\b").replace(/\f/g, "\\f").replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t"); }
function canonical(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "boolean" || typeof v === "number") return String(v);
  return JSON.stringify(String(v));
}

async function authlx(endpoint, payload) {
  const requestNonce = nonce(32);
  const response = await fetch(`${AUTHLX_URL}/${endpoint}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Accept": "application/json",
      "User-Agent": `AuthLX-SDK-Render/1.0 (${NAME})`,
      "X-Request-Nonce": requestNonce
    },
    body: JSON.stringify(payload)
  });

  const text = await response.text();
  let data = null;
  try { data = JSON.parse(text); } catch (_) {}

  // AuthLX SDK treats non-2xx responses as a failed request, but the body
  // can still contain the useful failure message. Preserve it for our client.
  if (!response.ok) {
    const msg = data?.message || text || `AuthLX HTTP ${response.status}`;
    const err = new Error(`AuthLX HTTP ${response.status}: ${msg}`);
    err.status = response.status;
    err.data = data;
    throw err;
  }
  if (!data) throw new Error("Invalid AuthLX JSON response");

  const sig = response.headers.get("x-response-sig");
  const nonceHeader = response.headers.get("x-response-nonce");
  if (SECRET && sig && nonceHeader) {
    if (nonceHeader.toLowerCase() !== requestNonce.toLowerCase()) {
      throw new Error("AuthLX response nonce mismatch");
    }
    const expected = hmac(SECRET, canonical(data) + ":" + requestNonce);
    const a = Buffer.from(expected.toLowerCase());
    const b = Buffer.from(sig.toLowerCase());
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      throw new Error("AuthLX response signature mismatch");
    }
  }
  return data;
}

function authPayload(hwid, extra = {}) {
  return { app_id: OWNERID, name: NAME, version: VERSION, hwid: hwid || "", ...extra };
}

app.get("/", (_, res) => res.json({ ok: true, service: "gmc-authlx", endpoint: "/api/license" }));
app.get("/health", (_, res) => res.json({ ok: true }));

function isExpired(value) {
  if (!value || String(value).toLowerCase() === "lifetime") return false;
  const n = Number(value);
  if (Number.isFinite(n)) {
    const ms = n < 1e12 ? n * 1000 : n;
    return ms <= Date.now();
  }
  const t = Date.parse(String(value));
  return Number.isFinite(t) ? t <= Date.now() : false;
}

async function postAuthCheck(sessionToken, hwid) {
  if (!sessionToken) return { banned: false };
  try {
    const r = await authlx("check_ban", authPayload(hwid, { session_token: sessionToken }));
    return { banned: !!r?.is_banned || String(r?.status || "").toLowerCase() === "banned" };
  } catch (_) {
    return { banned: false };
  }
}

function entitlementValid(info) {
  const u = info || {};
  if (u.is_banned === true) return false;
  const subs = Array.isArray(u.subscriptions) ? u.subscriptions : [];
  if (subs.length > 0) return subs.some(s => !isExpired(s?.expiry));
  const exp = u.expiration_date ?? u.expires ?? u.expiry;
  if (exp !== undefined && exp !== null && String(exp) !== "") return !isExpired(exp);
  return true;
}

app.post("/api/license", async (req, res) => {
  const license = String(req.body?.license || "").trim();
  const hwid = String(req.body?.hwid || "");
  if (!license) return res.status(400).json({ valid: false, message: "License key is required" });

  try {
    // This follows the unified license() flow from the supplied AuthLX Java SDK:
    // init -> login(key,key) -> register(key,key,key) -> login(key,key).
    const init = await authlx("init", { app_id: OWNERID, name: NAME, version: VERSION });
    if (String(init.status || "").toLowerCase() !== "success") {
      return res.status(403).json({ valid: false, message: init.message || "AuthLX initialization failed" });
    }
    const sessionToken = init.session_token || "";

    const loginPayload = authPayload(hwid, { username: license, password: license, ...(sessionToken ? { session_token: sessionToken } : {}) });
    try {
      const login = await authlx("login", loginPayload);
      if (String(login.status || "").toLowerCase() === "success") {
        const token = login.session_token || login.data?.token || sessionToken;
        const info = login.info || login.data?.user || {};
        const ban = await postAuthCheck(token, hwid);
        if (ban.banned || !entitlementValid(info)) return res.status(403).json({ valid: false, message: "License revoked or expired" });
        return res.json({ valid: true, message: login.message || "License valid", session_token: token, expires: info.expiration_date || info.expires || info.expiry || "", info });
      }
    } catch (loginErr) {
      console.log("AuthLX login attempt failed; trying registration:", loginErr.message);
    }

    const registerPayload = authPayload(hwid, {
      username: license,
      password: license,
      license_key: license,
      license,
      ...(sessionToken ? { session_token: sessionToken } : {})
    });

    try {
      const registration = await authlx("register", registerPayload);
      if (String(registration.status || "").toLowerCase() === "success") {
        const token = registration.session_token || registration.data?.token || sessionToken;
        const info = registration.info || registration.data?.user || {};
        const ban = await postAuthCheck(token, hwid);
        if (ban.banned || !entitlementValid(info)) return res.status(403).json({ valid: false, message: "License revoked or expired" });
        return res.json({ valid: true, message: registration.message || "License valid", session_token: token, expires: info.expiration_date || info.expires || info.expiry || "", info });
      }
    } catch (registerErr) {
      console.log("AuthLX register attempt failed; retrying login:", registerErr.message);
    }

    // The supplied SDK also has a direct /license fallback. Some AuthLX
    // configurations do not expose this route (404), so ignore that case.
    try {
      const direct = await authlx("license", authPayload(hwid, { license, ...(sessionToken ? { session_token: sessionToken } : {}) }));
      if (String(direct.status || "").toLowerCase() === "success") {
        return res.json({ valid: true, message: direct.message || "License valid", session_token: direct.session_token || sessionToken, info: direct.info || direct.user_data || {} });
      }
    } catch (directErr) {
      console.log("AuthLX direct /license fallback:", directErr.message);
    }

    return res.status(403).json({ valid: false, message: "License invalid or not accepted" });
  } catch (e) {
    console.error(e);
    return res.status(502).json({ valid: false, message: e.message || "License service error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`GMC AuthLX proxy listening on ${port}`));
