"use strict";
// Atlas gateway. Auth: email/password or wallet signature -> short-lived JWT. Access: license checked on every protected call.
require("dotenv").config();
const express = require("express"), helmet = require("helmet"), cors = require("cors");
const rateLimit = require("express-rate-limit"), multer = require("multer");
const crypto = require("crypto"), fs = require("fs"), path = require("path"), dns = require("dns"), net = require("net");
const jwt = require("jsonwebtoken"), Database = require("better-sqlite3");
const { ethers } = require("ethers"), { Agent, fetch: ufetch } = require("undici");
const { pipeline } = require("stream/promises");
const { address, abi } = require("./contract.json");

const env = process.env, PROD = env.NODE_ENV === "production";
const BRAND = "Atlas";
const CHAIN_ID = Number(env.CHAIN_ID || 31337);
const ORIGINS = (env.ALLOWED_ORIGINS || "http://localhost:5173").split(",").map((s) => s.trim());
const HOSTS = ORIGINS.map((o) => new URL(o).host);
const FRONTEND_URL = (env.FRONTEND_URL || ORIGINS[0]).replace(/\/+$/, "");
const ALLOW_PRIVATE = env.ALLOW_PRIVATE_ENDPOINTS === "true" && !PROD; // dev only, ignored in production
const PORT = Number(env.PORT || 4000);
const PUBLIC_URL = (env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const HF_API_URL = (env.HF_API_URL || "https://huggingface.co/api/models").replace(/\/+$/, "");
const HF_INFERENCE_URL = (env.HF_INFERENCE_URL || "https://api-inference.huggingface.co/models").replace(/\/+$/, "");
const INR_PER_ETH = Number(env.INR_PER_ETH || 0);
const ADMIN_WALLET = (env.ADMIN_WALLET || "").toLowerCase();
const ADMIN_ROLES = new Set(["admin", "moderator", "reviewer"]);
const AUTOMATION_ACTOR = "system:atlas-bot";
// The bot is an internal policy worker, not a login identity. In development it
// is enabled by default for the demo; production must opt in explicitly.
const AUTOMATED_MODERATION_ENABLED = env.ENABLE_AUTOMATED_MODERATION !== "false" && (!PROD || env.ENABLE_AUTOMATED_MODERATION === "true");
const AUTO_TRIAGE_REPORTS = AUTOMATED_MODERATION_ENABLED && env.AUTO_TRIAGE_REPORTS !== "false";
const RAZORPAY_KEY_ID = env.RAZORPAY_KEY_ID || "";
const RAZORPAY_KEY_SECRET = env.RAZORPAY_KEY_SECRET || "";
const RAZORPAY_WEBHOOK_SECRET = env.RAZORPAY_WEBHOOK_SECRET || "";
const RAZORPAY_API_URL = "https://api.razorpay.com/v1";
const INR_PAYMENTS_ENABLED = env.ENABLE_INR_PAYMENTS === "true" && Boolean(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET);
const FIAT_PLATFORM_FEE_BPS = Math.min(Math.max(Number(env.FIAT_PLATFORM_FEE_BPS || 250), 0), 1000);
const ALLOWED_HF_LICENSES = new Set((env.ALLOWED_HF_LICENSES || "apache-2.0,mit,bsd,bsd-2-clause,bsd-3-clause,cc-by,cc-by-4.0,openrail,openrail++,bigscience-openrail-m,creativeml-openrail-m").split(",").map((v) => v.trim().toLowerCase()).filter(Boolean));
const ALLOWED_MODEL_LICENSES = new Set((env.ALLOWED_MODEL_LICENSES || "mit,apache-2.0,bsd,bsd-2-clause,bsd-3-clause,cc-by,cc-by-4.0,openrail,openrail++,bigscience-openrail-m,creativeml-openrail-m,commercial,proprietary,custom").split(",").map((v) => v.trim().toLowerCase()).filter(Boolean));
const AUTO_APPROVE_MODEL_VERIFICATION = AUTOMATED_MODERATION_ENABLED && env.AUTO_APPROVE_MODEL_VERIFICATION !== "false";
const REQUIRE_KYC_FOR_LISTING = PROD || env.REQUIRE_KYC_FOR_LISTING === "true";
const REQUIRE_MALWARE_SCAN = PROD || env.REQUIRE_MALWARE_SCAN === "true";
const CLAMAV_HOST = env.CLAMAV_HOST || "";
const CLAMAV_PORT = Number(env.CLAMAV_PORT || 3310);
const STANDARD_LICENSE_URLS = {
  mit: new Set(["https://opensource.org/license/mit", "https://spdx.org/licenses/mit.html", "https://choosealicense.com/licenses/mit"]),
  "apache-2.0": new Set(["https://www.apache.org/licenses/license-2.0", "https://opensource.org/license/apache-2.0", "https://spdx.org/licenses/apache-2.0.html"]),
  bsd: new Set(["https://opensource.org/license/bsd-3-clause", "https://spdx.org/licenses/bsd-3-clause.html"]),
  "bsd-2-clause": new Set(["https://opensource.org/license/bsd-2-clause", "https://spdx.org/licenses/bsd-2-clause.html"]),
  "bsd-3-clause": new Set(["https://opensource.org/license/bsd-3-clause", "https://spdx.org/licenses/bsd-3-clause.html"]),
  "cc-by": new Set(["https://creativecommons.org/licenses/by/4.0", "https://spdx.org/licenses/cc-by-4.0.html"]),
  "cc-by-4.0": new Set(["https://creativecommons.org/licenses/by/4.0", "https://spdx.org/licenses/cc-by-4.0.html"])
};
const GOOGLE_CLIENT_ID = env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REDIRECT_URI = env.GOOGLE_REDIRECT_URI || `${PUBLIC_URL}/api/auth/google/callback`;
const GOOGLE_OAUTH_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
const RESEND_API_KEY = env.RESEND_API_KEY || "";
const AUTH_EMAIL_FROM = env.AUTH_EMAIL_FROM || "";
const EMAIL_VERIFICATION_REQUIRED = PROD || env.REQUIRE_EMAIL_VERIFICATION === "true";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_COOKIE = "atlas_session";
const SESSION_COOKIE_FLAGS = `Path=/; HttpOnly; SameSite=Lax${PROD ? "; Secure" : ""}`;
if (PROD) {
  if (!env.RPC_URL || !env.PUBLIC_URL || !/^https:\/\//i.test(PUBLIC_URL)) throw new Error("RPC_URL and an https PUBLIC_URL are required in production");
  if (ORIGINS.some((origin) => !/^https:\/\//i.test(origin))) throw new Error("ALLOWED_ORIGINS must contain only https origins in production");
  if (GOOGLE_OAUTH_ENABLED && !/^https:\/\//i.test(GOOGLE_REDIRECT_URI)) throw new Error("GOOGLE_REDIRECT_URI must use https in production");
  if (env.ENABLE_INR_PAYMENTS === "true" && (!INR_PAYMENTS_ENABLED || !RAZORPAY_WEBHOOK_SECRET)) throw new Error("Razorpay credentials and RAZORPAY_WEBHOOK_SECRET are required when INR payments are enabled");
}
function secret(name, bytes) {
  const v = env[name];
  if (v) { const b = Buffer.from(v, "hex"); if (b.length < bytes) throw new Error(`${name} must be ${bytes}+ bytes of hex`); return b.subarray(0, bytes); }
  if (PROD) throw new Error(`${name} is required in production`);
  return crypto.randomBytes(bytes);
}
const JWT_SECRET = secret("JWT_SECRET", 32), ENC_KEY = secret("ENDPOINT_KEY", 32);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const normalizeEmail = (value) => String(value || "").trim().toLowerCase();
const passwordHash = (password, salt = crypto.randomBytes(16)) => new Promise((resolve, reject) => {
  crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 }, (error, derived) => {
    if (error) return reject(error);
    resolve({ salt: salt.toString("hex"), hash: derived.toString("hex") });
  });
});
const passwordMatches = async (password, saltHex, expectedHex) => {
  const result = await passwordHash(password, Buffer.from(saltHex, "hex"));
  const expected = Buffer.from(expectedHex, "hex"), actual = Buffer.from(result.hash, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
};
const sessionToken = (subject, authType, extra = {}) => jwt.sign({ authType, ...extra }, JWT_SECRET, { subject, algorithm: "HS256", issuer: "atlas", expiresIn: "1h" });
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("hex");
const hashToken = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
const getCookie = (req, name) => {
  const cookies = String(req.headers.cookie || "").split(";");
  for (const item of cookies) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
};
const setSessionCookie = (res, subject, authType, userId = null) => {
  const raw = randomToken();
  const now = Date.now();
  db.prepare("INSERT INTO auth_sessions(token_hash,subject,auth_type,user_id,expires_at,created_at) VALUES(?,?,?,?,?,?)").run(hashToken(raw), subject, authType, userId, now + SESSION_TTL_MS, now);
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${encodeURIComponent(raw)}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}; ${SESSION_COOKIE_FLAGS}`);
};
const clearSessionCookie = (res) => res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Max-Age=0; ${SESSION_COOKIE_FLAGS}`);
const issueAuth = (res, subject, authType, userId = null, extra = {}) => {
  setSessionCookie(res, subject, authType, userId);
  return { token: sessionToken(subject, authType, { userId, ...extra }), authType, brand: BRAND };
};
const createAuthToken = (userId, kind, ttlMs) => {
  const raw = randomToken();
  db.prepare("INSERT INTO auth_tokens(token_hash,user_id,kind,expires_at,created_at) VALUES(?,?,?,?,?)").run(hashToken(raw), userId, kind, Date.now() + ttlMs, Date.now());
  return raw;
};
const consumeAuthToken = (raw, kind) => {
  if (typeof raw !== "string" || raw.length < 32 || raw.length > 200) return null;
  const row = db.prepare("SELECT token_hash, user_id FROM auth_tokens WHERE token_hash = ? AND kind = ? AND expires_at > ?").get(hashToken(raw), kind, Date.now());
  if (!row) return null;
  db.prepare("DELETE FROM auth_tokens WHERE token_hash = ?").run(row.token_hash);
  return row;
};
const sendAuthEmail = async ({ to, subject, html, devUrl }) => {
  if (!RESEND_API_KEY || !AUTH_EMAIL_FROM) {
    if (PROD) throw new AppError("Email delivery is not configured", 503);
    console.warn(JSON.stringify({ level: "warn", msg: "email delivery is not configured", to, devUrl }));
    return { developmentUrl: devUrl };
  }
  const response = await ufetch(env.RESEND_API_URL || "https://api.resend.com/emails", {
    method: "POST", headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ from: AUTH_EMAIL_FROM, to: [to], subject, html }), dispatcher: agent, signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) throw new AppError("Email delivery failed", 502);
  return {};
};

const provider = new ethers.JsonRpcProvider(env.RPC_URL || "http://127.0.0.1:8545");
const market = new ethers.Contract(address, abi, provider);
const DATA = env.DATA_DIR || __dirname, UPLOADS = path.join(DATA, "uploads"), TMP = path.join(DATA, "tmp"), EVIDENCE = path.join(DATA, "evidence");
[UPLOADS, TMP, EVIDENCE].forEach((d) => fs.mkdirSync(d, { recursive: true, mode: 0o700 }));
const db = new Database(path.join(DATA, "data.db"));
db.pragma("journal_mode = WAL");
db.exec("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)");
const migrations = [
  [1, `CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, exp INTEGER);
      CREATE TABLE IF NOT EXISTS endpoints(model_id INTEGER PRIMARY KEY, blob BLOB);
      CREATE TABLE IF NOT EXISTS artifacts(hash TEXT PRIMARY KEY, owner TEXT, size INTEGER, name TEXT);
      CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY, model_id INTEGER, user TEXT, ts INTEGER, status INTEGER);`],
  [2, `CREATE TABLE IF NOT EXISTS metadata(id TEXT PRIMARY KEY, owner TEXT NOT NULL, manifest TEXT NOT NULL, created_at INTEGER NOT NULL);`],
  [3, `CREATE INDEX IF NOT EXISTS idx_artifacts_owner ON artifacts(owner);`],
  [4, `CREATE TABLE IF NOT EXISTS favorites(user TEXT NOT NULL, model_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(user, model_id));
      CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT, model_id INTEGER NOT NULL, user TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_comments_model ON comments(model_id, created_at DESC);
      CREATE TABLE IF NOT EXISTS creator_profiles(wallet TEXT PRIMARY KEY, display_name TEXT NOT NULL, bio TEXT NOT NULL, language TEXT NOT NULL, msme TEXT NOT NULL, website TEXT NOT NULL, updated_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, model_id INTEGER NOT NULL, reporter TEXT NOT NULL, reason TEXT NOT NULL, details TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL);`],
  [5, `CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT, provider_order_id TEXT UNIQUE NOT NULL, provider_payment_id TEXT, model_id INTEGER NOT NULL, user TEXT NOT NULL, amount INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, signature TEXT, created_at INTEGER NOT NULL, verified_at INTEGER);
      CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user, created_at DESC);
      CREATE TABLE IF NOT EXISTS fiat_licenses(model_id INTEGER NOT NULL, user TEXT NOT NULL, payment_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(model_id, user));`],
  [6, `CREATE TABLE IF NOT EXISTS fiat_earnings(id INTEGER PRIMARY KEY AUTOINCREMENT, payment_id INTEGER UNIQUE NOT NULL, model_id INTEGER NOT NULL, creator TEXT NOT NULL, gross_paise INTEGER NOT NULL, platform_fee_paise INTEGER NOT NULL, creator_paise INTEGER NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL);`],
  [7, `CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, created_at INTEGER NOT NULL, last_login_at INTEGER);`],
  [8, `ALTER TABLE users ADD COLUMN google_sub TEXT;
      ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
      ALTER TABLE users ADD COLUMN avatar_url TEXT NOT NULL DEFAULT '';
      ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub);
      CREATE TABLE IF NOT EXISTS auth_sessions(token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, auth_type TEXT NOT NULL, user_id INTEGER, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at);
      CREATE TABLE IF NOT EXISTS auth_tokens(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);`
  ],
  [9, `CREATE TABLE IF NOT EXISTS oauth_states(state_hash TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);`]
  , [10, `ALTER TABLE creator_profiles ADD COLUMN avatar_url TEXT NOT NULL DEFAULT '';
      ALTER TABLE creator_profiles ADD COLUMN github_url TEXT NOT NULL DEFAULT '';`]
  , [11, `CREATE TABLE IF NOT EXISTS creator_avatars(wallet TEXT PRIMARY KEY, mime_type TEXT NOT NULL, data BLOB NOT NULL, updated_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS community_posts(id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, category TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_community_posts_created ON community_posts(created_at DESC);
      CREATE TABLE IF NOT EXISTS community_replies(id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, author TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_community_replies_post ON community_replies(post_id, created_at ASC);
      CREATE TABLE IF NOT EXISTS community_likes(post_id INTEGER NOT NULL, user TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(post_id, user));`]
  , [12, `ALTER TABLE artifacts ADD COLUMN scan_status TEXT NOT NULL DEFAULT 'passed_basic';
      ALTER TABLE artifacts ADD COLUMN scan_message TEXT NOT NULL DEFAULT 'Basic upload checks passed';
      ALTER TABLE artifacts ADD COLUMN scanned_at INTEGER;
      CREATE TABLE IF NOT EXISTS model_verifications(
        id TEXT PRIMARY KEY, creator TEXT NOT NULL, metadata_id TEXT NOT NULL, artifact_hash TEXT NOT NULL,
        license TEXT NOT NULL, license_url TEXT NOT NULL, model_card_json TEXT NOT NULL,
        declarations_json TEXT NOT NULL, message TEXT NOT NULL, message_hash TEXT NOT NULL,
        signature TEXT NOT NULL DEFAULT '', scan_status TEXT NOT NULL, status TEXT NOT NULL,
        rejection_reason TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, attested_at INTEGER,
        reviewed_at INTEGER, reviewed_by TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_model_verifications_creator ON model_verifications(creator, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_model_verifications_metadata ON model_verifications(metadata_id, created_at DESC);
      CREATE TABLE IF NOT EXISTS verification_audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, verification_id TEXT NOT NULL, actor TEXT NOT NULL,
        action TEXT NOT NULL, details TEXT NOT NULL, created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_verification_audit_verification ON verification_audit(verification_id, created_at DESC);`]
  , [13, `ALTER TABLE artifacts ADD COLUMN malware_status TEXT NOT NULL DEFAULT 'not_configured';
       ALTER TABLE artifacts ADD COLUMN malware_message TEXT NOT NULL DEFAULT 'ClamAV malware scanning is not configured';
       ALTER TABLE artifacts ADD COLUMN malware_scanned_at INTEGER;
       ALTER TABLE model_verifications ADD COLUMN identity_status TEXT NOT NULL DEFAULT 'unverified';
       ALTER TABLE model_verifications ADD COLUMN provenance_url TEXT NOT NULL DEFAULT '';
       ALTER TABLE model_verifications ADD COLUMN provenance_status TEXT NOT NULL DEFAULT 'pending';
       ALTER TABLE model_verifications ADD COLUMN provenance_message TEXT NOT NULL DEFAULT '';
       CREATE TABLE IF NOT EXISTS creator_identity(
         wallet TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'unverified', provider TEXT NOT NULL DEFAULT 'manual',
         country TEXT NOT NULL DEFAULT '', full_name_hash TEXT NOT NULL DEFAULT '', provider_reference_hash TEXT NOT NULL DEFAULT '',
         document_name TEXT NOT NULL DEFAULT '', document_mime TEXT NOT NULL DEFAULT '', document_sha256 TEXT NOT NULL DEFAULT '',
         document_size INTEGER NOT NULL DEFAULT 0, document_path TEXT NOT NULL DEFAULT '',
         submitted_at INTEGER, reviewed_at INTEGER, reviewed_by TEXT NOT NULL DEFAULT '', rejection_reason TEXT NOT NULL DEFAULT ''
       );
       CREATE TABLE IF NOT EXISTS model_evidence(
         id TEXT PRIMARY KEY, verification_id TEXT NOT NULL, kind TEXT NOT NULL, file_name TEXT NOT NULL,
         mime_type TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, storage_path TEXT NOT NULL,
         status TEXT NOT NULL DEFAULT 'pending_review', reviewer TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
         created_at INTEGER NOT NULL, reviewed_at INTEGER
       );
       CREATE INDEX IF NOT EXISTS idx_model_evidence_verification ON model_evidence(verification_id, kind, created_at DESC);
       CREATE TABLE IF NOT EXISTS model_provenance(
         verification_id TEXT PRIMARY KEY, status TEXT NOT NULL, source_url TEXT NOT NULL DEFAULT '',
         source_revision TEXT NOT NULL DEFAULT '', duplicate_of TEXT NOT NULL DEFAULT '',
         message TEXT NOT NULL DEFAULT '', checked_at INTEGER NOT NULL
       );
       CREATE TABLE IF NOT EXISTS model_moderation(
         model_id INTEGER PRIMARY KEY, status TEXT NOT NULL DEFAULT 'active', reason TEXT NOT NULL DEFAULT '',
         actor TEXT NOT NULL, action TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, restored_at INTEGER
       );
       CREATE TABLE IF NOT EXISTS moderation_audit(
         id INTEGER PRIMARY KEY AUTOINCREMENT, model_id INTEGER NOT NULL, actor TEXT NOT NULL,
         action TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL
       );
       ALTER TABLE reports ADD COLUMN reviewed_by TEXT NOT NULL DEFAULT '';
       ALTER TABLE reports ADD COLUMN resolution TEXT NOT NULL DEFAULT '';
       ALTER TABLE reports ADD COLUMN resolved_at INTEGER;`]
  , [14, `CREATE TABLE IF NOT EXISTS admin_roles(
         subject TEXT PRIMARY KEY, role TEXT NOT NULL, granted_by TEXT NOT NULL,
         created_at INTEGER NOT NULL, revoked_at INTEGER, notes TEXT NOT NULL DEFAULT ''
       );
       CREATE INDEX IF NOT EXISTS idx_admin_roles_active ON admin_roles(role, revoked_at);`]
  , [15, `ALTER TABLE reports ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'normal';
       ALTER TABLE reports ADD COLUMN automated_action TEXT NOT NULL DEFAULT 'queued_for_review';
       CREATE TABLE IF NOT EXISTS automation_events(
         id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
         target_type TEXT NOT NULL, target_id TEXT NOT NULL, outcome TEXT NOT NULL,
         reason TEXT NOT NULL, details TEXT NOT NULL, created_at INTEGER NOT NULL
       );
       CREATE INDEX IF NOT EXISTS idx_automation_events_created ON automation_events(created_at DESC);
       CREATE INDEX IF NOT EXISTS idx_automation_events_target ON automation_events(target_type, target_id, created_at DESC);`]
];
db.transaction(() => {
  for (const [version, sql] of migrations) {
    if (!db.prepare("SELECT 1 FROM schema_migrations WHERE version = ?").get(version)) {
      db.exec(sql);
      db.prepare("INSERT INTO schema_migrations VALUES(?,?)").run(version, Date.now());
    }
  }
})();
if (ADMIN_WALLET && ethers.isAddress(ADMIN_WALLET)) db.prepare("INSERT OR IGNORE INTO admin_roles(subject,role,granted_by,created_at,notes) VALUES(?,?,?,?,?)").run(ADMIN_WALLET, "admin", "environment", Date.now(), "Bootstrap administrator from ADMIN_WALLET");

class AppError extends Error { constructor(m, status = 400) { super(m); this.status = status; } }
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  if (!(e instanceof AppError)) console.error(JSON.stringify({ level: "error", path: req.path, msg: e.message }));
  res.status(e.status || 500).json({ error: e instanceof AppError ? e.message : "Internal error" });
});
const isId = (v) => /^\d{1,9}$/.test(String(v));
const userKey = (v) => String(v).toLowerCase();
const recordAutomationEvent = (action, targetType, targetId, outcome, reason, details = {}) => db.prepare(
  "INSERT INTO automation_events(actor,action,target_type,target_id,outcome,reason,details,created_at) VALUES(?,?,?,?,?,?,?,?)"
).run(AUTOMATION_ACTOR, action, targetType, String(targetId), outcome, cleanText(reason, 1000), JSON.stringify(details), Date.now());
const classifyReport = (reason, details) => {
  const text = `${reason} ${details}`.toLowerCase();
  if (/(malware|virus|trojan|credential|keylogger|copyright|stolen|impersonat|illegal|harmful|privacy|personal data)/.test(text)) return "high";
  if (/(spam|duplicate|misleading|quality|broken|abuse)/.test(text)) return "medium";
  return "normal";
};
const inrPrice = (value) => {
  if (value === null || value === undefined || value === "") return null;
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 100000000) throw new AppError("INR price must be between ₹1 and ₹10 crore");
  return Math.round(amount * 100) / 100;
};
const cleanText = (value, max) => String(value || "").trim().slice(0, max);
const normalizeModelCard = (value) => {
  const card = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    purpose: cleanText(card.purpose, 1000),
    trainingData: cleanText(card.trainingData, 1500),
    limitations: cleanText(card.limitations, 1500),
    intendedUsers: cleanText(card.intendedUsers, 500),
    riskNotes: cleanText(card.riskNotes, 1500)
  };
};
const normalizedLicense = (value) => cleanText(value, 120).toLowerCase();
const verificationId = () => crypto.randomBytes(16).toString("hex");
const privateEvidencePath = (id) => path.join(EVIDENCE, String(id));
const identityFor = (wallet) => db.prepare("SELECT wallet, status, provider, country, document_name AS documentName, document_mime AS documentMime, document_sha256 AS documentSha256, document_size AS documentSize, submitted_at AS submittedAt, reviewed_at AS reviewedAt, reviewed_by AS reviewedBy, rejection_reason AS rejectionReason FROM creator_identity WHERE wallet = ?").get(userKey(wallet)) || { wallet: userKey(wallet), status: "unverified", provider: "manual", country: "", documentName: "", documentMime: "", documentSha256: "", documentSize: 0, submittedAt: null, reviewedAt: null, reviewedBy: "", rejectionReason: "" };
const moderationFor = (modelId) => db.prepare("SELECT model_id AS modelId, status, reason, actor, action, created_at AS createdAt, updated_at AS updatedAt, restored_at AS restoredAt FROM model_moderation WHERE model_id = ?").get(Number(modelId)) || { modelId: Number(modelId), status: "active", reason: "", actor: "", action: "", createdAt: null, updatedAt: null, restoredAt: null };
const modelIsTakedown = (modelId) => moderationFor(modelId).status === "takedown";
const setModelModeration = (modelId, status, actor, reason, action) => {
  const now = Date.now();
  db.prepare(`INSERT INTO model_moderation(model_id,status,reason,actor,action,created_at,updated_at,restored_at) VALUES(?,?,?,?,?,?,?,?)
    ON CONFLICT(model_id) DO UPDATE SET status=excluded.status, reason=excluded.reason, actor=excluded.actor, action=excluded.action, updated_at=excluded.updated_at, restored_at=excluded.restored_at`).run(Number(modelId), status, reason, userKey(actor), action, now, now, status === "active" ? now : null);
  db.prepare("INSERT INTO moderation_audit(model_id,actor,action,reason,created_at) VALUES(?,?,?,?,?)").run(Number(modelId), userKey(actor), action, reason, now);
};
const hashBuffer = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");
const safeEvidenceName = (value) => path.basename(String(value || "evidence")).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120) || "evidence";
const evidenceId = () => crypto.randomBytes(16).toString("hex");
const publicEvidence = (row) => ({ id: row.id, verificationId: row.verification_id || row.verificationId, kind: row.kind, fileName: row.file_name || row.fileName, mimeType: row.mime_type || row.mimeType, sha256: row.sha256, size: row.size, status: row.status, notes: row.notes, createdAt: row.created_at || row.createdAt, reviewedAt: row.reviewed_at || row.reviewedAt });
const modelVerificationForMetadata = (metadataId) => {
  if (!metadataId) return null;
  const row = db.prepare("SELECT id, status, license, license_url AS licenseUrl, scan_status AS scanStatus, identity_status AS identityStatus, provenance_url AS provenanceUrl, provenance_status AS provenanceStatus, provenance_message AS provenanceMessage, rejection_reason AS rejectionReason, created_at AS createdAt, attested_at AS attestedAt, reviewed_at AS reviewedAt FROM model_verifications WHERE metadata_id = ? ORDER BY created_at DESC LIMIT 1").get(metadataId);
  return row || null;
};
const metadataFromURI = (uri) => {
  const match = typeof uri === "string" && uri.match(/\/api\/metadata\/([0-9a-f]{64})$/i);
  if (!match) return {};
  const row = db.prepare("SELECT manifest FROM metadata WHERE id = ?").get(match[1].toLowerCase());
  if (!row) return {};
  try { return JSON.parse(row.manifest); } catch { return {}; }
};
const profileFor = (wallet) => {
  const row = db.prepare("SELECT wallet, display_name AS displayName, bio, language, msme, website, avatar_url AS avatarUrl, github_url AS githubUrl, updated_at AS updatedAt FROM creator_profiles WHERE wallet = ?").get(userKey(wallet));
  return row || null;
};
const publicIdentity = (user) => {
  const key = userKey(user);
  if (ethers.isAddress(key)) {
    const profile = profileFor(key);
    return { displayName: profile?.displayName || `Creator ${key.slice(0, 6)}…${key.slice(-4)}`, avatarUrl: profile?.avatarUrl || null, wallet: key };
  }
  const profile = db.prepare("SELECT display_name AS displayName, avatar_url AS avatarUrl FROM users WHERE email = ?").get(key);
  return { displayName: profile?.displayName || key.split("@")[0], avatarUrl: profile?.avatarUrl || null };
};
const modelJson = (id, m) => {
  const metadata = metadataFromURI(m.metadataURI);
  const creatorProfile = profileFor(String(m.creator).toLowerCase());
  const metadataId = typeof m.metadataURI === "string" && m.metadataURI.match(/\/api\/metadata\/([0-9a-f]{64})$/i)?.[1]?.toLowerCase();
  const verification = modelVerificationForMetadata(metadataId);
  return {
  id: Number(id), creator: m.creator, name: m.name, metadataURI: m.metadataURI,
  contentHash: m.contentHash, price: m.price.toString(), active: m.active,
  sales: m.sales.toString(), ratingSum: m.ratingSum.toString(), ratingCount: m.ratingCount.toString(),
  description: metadata.description || "",
  version: metadata.version || "",
  tags: Array.isArray(metadata.tags) ? metadata.tags : [],
  source: metadata.source || null,
  license: metadata.license || null,
  priceInr: metadata.priceInr || null,
  modelCard: metadata.modelCard || null,
  verification,
  moderation: moderationFor(id),
  creatorTrust: { identityStatus: identityFor(m.creator).status, statement: "Creator attestation and moderation; not automatic legal ownership verification" },
  hfRepo: metadata.source?.type === "huggingface" ? metadata.source.repo : null,
  creatorProfile
  };
};
const getModel = async (id) => {
  if (!isId(id)) throw new AppError("Bad request");
  try { return await market.getModel(Number(id)); }
  catch { throw new AppError("Model not found", 404); }
};
const hasFiatLicense = (id, user) => Boolean(db.prepare("SELECT 1 FROM fiat_licenses WHERE model_id = ? AND user = ?").get(Number(id), userKey(user)));
const hasAccess = async (id, user) => {
  if (hasFiatLicense(id, user)) return true;
  try { return await market.hasLicense(id, user); } catch { return false; }
};
const grantFiatLicense = (paymentId) => {
  const payment = db.prepare("SELECT id, model_id, user, status FROM payments WHERE id = ?").get(paymentId);
  if (!payment || payment.status !== "captured") return false;
  db.prepare("INSERT OR IGNORE INTO fiat_licenses(model_id,user,payment_id,created_at) VALUES(?,?,?,?)").run(payment.model_id, payment.user, payment.id, Date.now());
  return true;
};
const recordFiatEarning = async (paymentId) => {
  const payment = db.prepare("SELECT id, model_id, amount, status FROM payments WHERE id = ?").get(paymentId);
  if (!payment || payment.status !== "captured") return false;
  const existing = db.prepare("SELECT 1 FROM fiat_earnings WHERE payment_id = ?").get(payment.id);
  if (existing) return true;
  const model = await market.getModel(payment.model_id);
  const fee = Math.floor((payment.amount * FIAT_PLATFORM_FEE_BPS) / 10000);
  db.prepare("INSERT INTO fiat_earnings(payment_id,model_id,creator,gross_paise,platform_fee_paise,creator_paise,status,created_at) VALUES(?,?,?,?,?,?,?,?)").run(payment.id, payment.model_id, userKey(model.creator), payment.amount, fee, payment.amount - fee, "pending_payout", Date.now());
  return true;
};

// Endpoint URLs are encrypted at rest (AES-256-GCM)
const enc = (t) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv); const ct = Buffer.concat([c.update(t, "utf8"), c.final()]); return Buffer.concat([iv, c.getAuthTag(), ct]); };
const dec = (b) => { const d = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8"); };

// SSRF defence: block private/loopback/link-local targets, at registration and again at connect time (anti DNS-rebinding)
const priv = (ip) => {
  if (net.isIPv6(ip)) { const l = ip.toLowerCase(); return l === "::1" || l === "::" || /^f[cd]|^fe[89ab]/.test(l) || (l.startsWith("::ffff:") && priv(l.slice(7))); }
  const [a, b] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
};
const lookup = (host, o, cb) => dns.lookup(host, o, (e, a, f) => {
  if (e) return cb(e);
  const list = Array.isArray(a) ? a : [{ address: a, family: f }];
  if (!ALLOW_PRIVATE && list.some((x) => priv(x.address))) return cb(new Error("Blocked address"));
  cb(null, a, f);
});
const agent = new Agent({ connect: { lookup }, headersTimeout: 15000, bodyTimeout: 15000, maxResponseSize: 1e6 });
// Metadata and API calls remain capped, but model weights can be many gigabytes.
// Keep a separate dispatcher without maxResponseSize for the streaming download route.
const downloadAgent = new Agent({ connect: { lookup }, headersTimeout: 30000, bodyTimeout: 120000 });
function checkUrl(raw) {
  let u; try { u = new URL(raw); } catch { throw new AppError("Invalid URL"); }
  if (u.username || u.password) throw new AppError("Credentials in URLs are not allowed");
  if (u.protocol !== "https:" && !(u.protocol === "http:" && !PROD)) throw new AppError("An https endpoint is required");
  const h = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(h) && !ALLOW_PRIVATE && priv(h)) throw new AppError("Private addresses are blocked");
  return u.toString();
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", env.TRUST_PROXY ? 1 : 0);
app.use(helmet());
app.use(cors({ origin: ORIGINS, credentials: true, methods: ["GET", "POST", "DELETE", "OPTIONS"], allowedHeaders: ["Content-Type", "Authorization"] }));
app.use(express.json({ limit: "16kb", verify: (req, res, buf) => { req.rawBody = Buffer.from(buf); } }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
const strict = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const profileUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => cb(/^(image\/jpeg|image\/png|image\/webp|image\/gif)$/.test(file.mimetype) ? null : new Error("Only PNG, JPEG, WebP, or GIF images are allowed"), true)
});
const profileUploadMiddleware = (req, res, next) => profileUpload.single("avatar")(req, res, (error) => {
  if (error) return res.status(422).json({ error: error.message || "Profile image upload failed" });
  next();
});
const evidenceUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const allowed = new Set(["application/pdf", "text/plain", "text/markdown", "application/json", "image/jpeg", "image/png", "image/webp"]);
    cb(allowed.has(file.mimetype) ? null : new Error("Evidence must be a PDF, text file, JSON file, or image"), true);
  }
});
const evidenceUploadMiddleware = (req, res, next) => evidenceUpload.single("file")(req, res, (error) => {
  if (error) return res.status(422).json({ error: error.message || "Evidence upload failed" });
  next();
});

const authed = (req, res, next) => {
  try {
    db.prepare("DELETE FROM auth_sessions WHERE expires_at <= ?").run(Date.now());
    const session = getCookie(req, SESSION_COOKIE);
    if (session) {
      const row = db.prepare("SELECT subject, auth_type AS authType, user_id AS userId FROM auth_sessions WHERE token_hash = ? AND expires_at > ?").get(hashToken(session), Date.now());
      if (row) { req.user = row.subject; req.authType = row.authType; req.userId = row.userId || null; return next(); }
    }
    const t = (req.headers.authorization || "").replace(/^Bearer /, "");
    const payload = jwt.verify(t, JWT_SECRET, { algorithms: ["HS256"], issuer: ["atlas", "neuralbazaar"] });
    req.user = payload.sub;
    req.authType = payload.authType || (ethers.isAddress(payload.sub) ? "wallet" : "email");
    req.userId = payload.userId || null;
    next();
  } catch { res.status(401).json({ error: "Sign in again" }); }
};
const walletAuthed = (req, res, next) => authed(req, res, () => {
  if (req.authType !== "wallet" || !ethers.isAddress(req.user)) return res.status(403).json({ error: "Connect a wallet for blockchain creator actions" });
  next();
});
const adminRoleFor = (subject) => {
  const row = db.prepare("SELECT subject, role, granted_by AS grantedBy, created_at AS createdAt, revoked_at AS revokedAt, notes FROM admin_roles WHERE subject = ? AND revoked_at IS NULL").get(userKey(subject));
  return row || null;
};
const adminAuthed = (req, res, next) => authed(req, res, () => {
  const role = adminRoleFor(req.user);
  if (!role || !ADMIN_ROLES.has(role.role)) return res.status(403).json({ error: "Admin role required" });
  req.adminRole = role.role;
  next();
});
const adminOwnerAuthed = (req, res, next) => adminAuthed(req, res, () => {
  if (req.adminRole !== "admin") return res.status(403).json({ error: "Administrator role required" });
  next();
});
const moderationAuthed = (req, res, next) => adminAuthed(req, res, () => {
  if (!["admin", "moderator"].includes(req.adminRole)) return res.status(403).json({ error: "Moderator role required" });
  next();
});
const perUser = (limit, windowMs = 60000) => rateLimit({ windowMs, limit, keyGenerator: (req) => req.user, standardHeaders: true, legacyHeaders: false });

const accountInput = (body) => {
  const email = normalizeEmail(body?.email), password = typeof body?.password === "string" ? body.password : "";
  if (!EMAIL_RE.test(email) || email.length > 254) throw new AppError("Enter a valid Gmail or email address", 422);
  if (password.length < 8 || password.length > 128) throw new AppError("Password must be 8 to 128 characters", 422);
  return { email, password };
};
const emailInput = (body) => {
  const email = normalizeEmail(body?.email);
  if (!EMAIL_RE.test(email) || email.length > 254) throw new AppError("Enter a valid Gmail or email address", 422);
  return email;
};
const verificationUrl = (token) => `${PUBLIC_URL}/api/auth/verify-email?token=${encodeURIComponent(token)}`;
const resetUrl = (token) => `${FRONTEND_URL}/?reset=${encodeURIComponent(token)}`;

const sendVerificationMessage = (email, token) => sendAuthEmail({
  to: email, subject: "Verify your Atlas account", devUrl: verificationUrl(token),
  html: `<p>Welcome to Atlas.</p><p>Verify your email address by clicking <a href="${verificationUrl(token)}">this link</a>.</p><p>This link expires in 24 hours.</p>`
});
const sendResetMessage = (email, token) => sendAuthEmail({
  to: email, subject: "Reset your Atlas password", devUrl: resetUrl(token),
  html: `<p>We received a request to reset your Atlas password.</p><p>Choose a new password <a href="${resetUrl(token)}">here</a>.</p><p>This link expires in one hour. If you did not request it, you can ignore this email.</p>`
});

app.post("/api/auth/register", strict, wrap(async (req, res) => {
  const { email, password } = accountInput(req.body);
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) throw new AppError("An account with that email already exists", 409);
  const credentials = await passwordHash(password);
  const now = Date.now(), verified = EMAIL_VERIFICATION_REQUIRED ? 0 : 1;
  const result = db.prepare("INSERT INTO users(email,password_hash,password_salt,created_at,last_login_at,email_verified) VALUES(?,?,?,?,?,?)").run(email, credentials.hash, credentials.salt, now, now, verified);
  const userId = Number(result.lastInsertRowid);
  if (EMAIL_VERIFICATION_REQUIRED) {
    const token = createAuthToken(userId, "email_verification", 24 * 60 * 60 * 1000);
    const delivery = await sendVerificationMessage(email, token);
    return res.status(201).json({ email, authType: "email", verificationRequired: true, ...(delivery.developmentUrl ? { developmentVerificationUrl: delivery.developmentUrl } : {}), brand: BRAND });
  }
  res.status(201).json({ ...issueAuth(res, email, "email", userId), email });
}));

app.post("/api/auth/login", strict, wrap(async (req, res) => {
  const { email, password } = accountInput(req.body);
  const user = db.prepare("SELECT id, email, password_hash, password_salt, email_verified FROM users WHERE email = ?").get(email);
  if (!user || !(await passwordMatches(password, user.password_salt, user.password_hash))) throw new AppError("Invalid email or password", 401);
  if (EMAIL_VERIFICATION_REQUIRED && !user.email_verified) throw new AppError("Verify your email before signing in", 403);
  db.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").run(Date.now(), user.id);
  res.json({ ...issueAuth(res, user.email, "email", user.id), email: user.email });
}));

app.post("/api/auth/password-reset/request", strict, wrap(async (req, res) => {
  const email = emailInput(req.body), user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  let developmentResetUrl;
  if (user) {
    db.prepare("DELETE FROM auth_tokens WHERE user_id = ? AND kind = 'password_reset'").run(user.id);
    const token = createAuthToken(user.id, "password_reset", 60 * 60 * 1000);
    const delivery = await sendResetMessage(email, token);
    developmentResetUrl = delivery.developmentUrl;
  }
  res.json({ ok: true, message: "If an account exists for that email, password-reset instructions have been sent", ...(developmentResetUrl ? { developmentResetUrl } : {}) });
}));

app.post("/api/auth/password-reset/confirm", strict, wrap(async (req, res) => {
  const token = String(req.body?.token || ""), password = typeof req.body?.password === "string" ? req.body.password : "";
  if (password.length < 8 || password.length > 128) throw new AppError("Password must be 8 to 128 characters", 422);
  const authToken = consumeAuthToken(token, "password_reset");
  if (!authToken) throw new AppError("This password-reset link is invalid or expired", 400);
  const credentials = await passwordHash(password);
  db.prepare("UPDATE users SET password_hash = ?, password_salt = ?, last_login_at = ? WHERE id = ?").run(credentials.hash, credentials.salt, Date.now(), authToken.user_id);
  const user = db.prepare("SELECT id, email FROM users WHERE id = ?").get(authToken.user_id);
  res.json({ ...issueAuth(res, user.email, "email", user.id), email: user.email, message: "Password updated" });
}));

app.get("/api/auth/verify-email", wrap(async (req, res) => {
  const authToken = consumeAuthToken(String(req.query.token || ""), "email_verification");
  if (!authToken) throw new AppError("This email-verification link is invalid or expired", 400);
  db.prepare("UPDATE users SET email_verified = 1 WHERE id = ?").run(authToken.user_id);
  res.redirect(`${FRONTEND_URL}/?verified=1`);
}));

app.get("/api/auth/google", strict, (req, res) => {
  if (!GOOGLE_OAUTH_ENABLED) return res.status(503).json({ error: "Google sign-in is not configured" });
  db.prepare("DELETE FROM oauth_states WHERE expires_at <= ?").run(Date.now());
  const state = randomToken(), nonce = randomToken(16);
  db.prepare("INSERT INTO oauth_states(state_hash,nonce,expires_at,created_at) VALUES(?,?,?,?)").run(hashToken(state), nonce, Date.now() + 10 * 60 * 1000, Date.now());
  const query = new URLSearchParams({ client_id: GOOGLE_CLIENT_ID, redirect_uri: GOOGLE_REDIRECT_URI, response_type: "code", scope: "openid email profile", state, nonce, prompt: "select_account" });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${query}`);
});

app.get("/api/auth/google/callback", wrap(async (req, res) => {
  if (!GOOGLE_OAUTH_ENABLED) throw new AppError("Google sign-in is not configured", 503);
  const state = String(req.query.state || ""), code = String(req.query.code || "");
  const saved = db.prepare("SELECT state_hash, nonce FROM oauth_states WHERE state_hash = ? AND expires_at > ?").get(hashToken(state), Date.now());
  if (!saved || !code) throw new AppError("Google sign-in could not be verified", 400);
  db.prepare("DELETE FROM oauth_states WHERE state_hash = ?").run(saved.state_hash);
  const tokenResponse = await ufetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body: new URLSearchParams({ code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, redirect_uri: GOOGLE_REDIRECT_URI, grant_type: "authorization_code" }).toString(), dispatcher: agent, signal: AbortSignal.timeout(12000) });
  if (!tokenResponse.ok) throw new AppError("Google token exchange failed", 502);
  const tokenData = await tokenResponse.json();
  if (!tokenData.id_token || !tokenData.access_token) throw new AppError("Google did not return a valid identity", 502);
  const tokenInfoResponse = await ufetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(tokenData.id_token)}`, { dispatcher: agent, signal: AbortSignal.timeout(12000) });
  if (!tokenInfoResponse.ok) throw new AppError("Google identity verification failed", 401);
  const claims = await tokenInfoResponse.json();
  if (claims.aud !== GOOGLE_CLIENT_ID || !["accounts.google.com", "https://accounts.google.com"].includes(claims.iss) || claims.nonce !== saved.nonce || !["true", true].includes(claims.email_verified)) throw new AppError("Google identity verification failed", 401);
  const profileResponse = await ufetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: "application/json" }, dispatcher: agent, signal: AbortSignal.timeout(12000) });
  if (!profileResponse.ok) throw new AppError("Google profile lookup failed", 502);
  const profile = await profileResponse.json(), email = normalizeEmail(profile.email || claims.email);
  if (!EMAIL_RE.test(email) || profile.sub !== claims.sub) throw new AppError("Google returned an invalid profile", 401);
  let user = db.prepare("SELECT id, email, google_sub FROM users WHERE google_sub = ? OR email = ?").get(profile.sub, email);
  if (!user) {
    const dummy = { hash: randomToken(64), salt: randomToken(16) }, now = Date.now();
    const result = db.prepare("INSERT INTO users(email,password_hash,password_salt,created_at,last_login_at,google_sub,display_name,avatar_url,email_verified) VALUES(?,?,?,?,?,?,?,?,?)").run(email, dummy.hash, dummy.salt, now, now, profile.sub, String(profile.name || "").slice(0, 120), String(profile.picture || "").slice(0, 500), 1);
    user = { id: Number(result.lastInsertRowid), email };
  } else {
    db.prepare("UPDATE users SET google_sub = ?, email_verified = 1, display_name = ?, avatar_url = ?, last_login_at = ? WHERE id = ?").run(profile.sub, String(profile.name || "").slice(0, 120), String(profile.picture || "").slice(0, 500), Date.now(), user.id);
  }
  const response = issueAuth(res, email, "google", user.id);
  res.redirect(`${FRONTEND_URL}/?auth=google-success`);
}));

app.post("/api/auth/logout", (req, res) => {
  const session = getCookie(req, SESSION_COOKIE);
  if (session) db.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").run(hashToken(session));
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get("/api/auth/me", authed, (req, res) => {
  res.json(req.authType === "wallet" ? { address: req.user, authType: req.authType, brand: BRAND } : { email: req.user, authType: req.authType, userId: req.userId, brand: BRAND });
});

// Sign-in: one-time nonce, domain + chain bound, so a signature cannot be replayed or phished from another site
app.get("/api/nonce", strict, (req, res) => {
  db.prepare("DELETE FROM nonces WHERE exp < ?").run(Date.now());
  const nonce = crypto.randomBytes(16).toString("hex");
  db.prepare("INSERT INTO nonces VALUES(?,?)").run(nonce, Date.now() + 5 * 60 * 1000);
  res.json({ nonce });
});
app.post("/api/login", strict, wrap(async (req, res) => {
  const { message, signature } = req.body;
  if (typeof message !== "string" || typeof signature !== "string" || message.length > 300) throw new AppError("Invalid request");
  const m = /^(?:Atlas|NeuralBazaar) sign-in\nDomain: (.+)\nChain: (\d+)\nNonce: ([0-9a-f]{32})$/.exec(message);
  if (!m || !HOSTS.includes(m[1]) || Number(m[2]) !== CHAIN_ID) throw new AppError("Invalid sign-in message");
  if (!db.prepare("DELETE FROM nonces WHERE nonce = ? AND exp > ?").run(m[3], Date.now()).changes) throw new AppError("Sign-in expired, try again");
  let user; try { user = ethers.verifyMessage(message, signature); } catch { throw new AppError("Invalid signature"); }
  res.json({ ...issueAuth(res, user, "wallet"), address: user });
}));

// Public catalog reads are bounded so clients do not need a wallet just to browse.
app.get("/api/models", wrap(async (req, res) => {
  const offset = Number(req.query.offset || 0), limit = Math.min(Number(req.query.limit || 24), 50);
  const query = String(req.query.q || "").trim().toLowerCase().slice(0, 80);
  const tag = String(req.query.tag || "").trim().toLowerCase().slice(0, 40);
  const source = String(req.query.source || "").trim().toLowerCase().slice(0, 30);
  if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(limit) || limit < 1) throw new AppError("Bad pagination");
  const total = Number(await market.modelCount());
  const filtered = [];
  for (let id = 0; id < total; id++) {
    const m = modelJson(id, await market.getModel(id));
    if (!m.active || m.moderation.status !== "active") continue; // Delisted/taken-down models remain on-chain for history but leave the public catalogue.
    const haystack = `${m.name} ${m.description} ${(m.tags || []).join(" ")}`.toLowerCase();
    const matchesQuery = !query || haystack.includes(query);
    const matchesTag = !tag || (m.tags || []).some((item) => item.toLowerCase() === tag);
    const matchesSource = !source || (m.source?.type || "direct") === source;
    if (matchesQuery && matchesTag && matchesSource) filtered.push(m);
  }
  res.json({ models: filtered.slice(offset, offset + limit), total: filtered.length, offset, limit, filters: { q: query, tag, source } });
}));

app.get("/api/models/:id", wrap(async (req, res) => {
  res.json(modelJson(req.params.id, await getModel(req.params.id)));
}));

// Metadata is intentionally separate from the protected artifact download route.
app.get("/api/metadata/:id", wrap(async (req, res) => {
  if (!/^[0-9a-f]{64}$/.test(req.params.id)) throw new AppError("Bad request");
  const row = db.prepare("SELECT manifest FROM metadata WHERE id = ?").get(req.params.id);
  if (!row) throw new AppError("Metadata not found", 404);
  res.type("application/json").send(row.manifest);
}));

const publicComment = (row) => ({ id: row.id, modelId: row.model_id, user: row.user, body: row.body, createdAt: row.created_at });
app.get("/api/models/:id/comments", wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad request");
  await getModel(req.params.id);
  const limit = Math.min(Math.max(Number(req.query.limit || 20), 1), 50);
  const rows = db.prepare("SELECT id, model_id, user, body, created_at FROM comments WHERE model_id = ? ORDER BY created_at DESC LIMIT ?").all(Number(req.params.id), limit);
  res.json({ comments: rows.map(publicComment) });
}));
app.post("/api/models/:id/comments", authed, perUser(12), wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad request");
  await getModel(req.params.id);
  const body = String(req.body?.body || "").trim();
  if (!body || body.length > 1000) throw new AppError("Comment must be 1 to 1,000 characters");
  const result = db.prepare("INSERT INTO comments(model_id,user,body,created_at) VALUES(?,?,?,?)").run(Number(req.params.id), userKey(req.user), body, Date.now());
  res.status(201).json({ comment: publicComment({ id: result.lastInsertRowid, model_id: Number(req.params.id), user: userKey(req.user), body, created_at: Date.now() }) });
}));

const communityCategories = new Set(["General", "Model showcase", "MSME", "Help", "Jobs"]);
const publicCommunityPost = (row, viewer) => ({
  id: row.id, title: row.title, body: row.body, category: row.category,
  createdAt: row.created_at, replyCount: Number(row.reply_count || 0), likeCount: Number(row.like_count || 0),
  liked: Boolean(viewer && db.prepare("SELECT 1 FROM community_likes WHERE post_id = ? AND user = ?").get(row.id, userKey(viewer))),
  author: publicIdentity(row.author)
});
const publicCommunityReply = (row) => ({ id: row.id, postId: row.post_id, body: row.body, createdAt: row.created_at, author: publicIdentity(row.author) });
app.get("/api/community/posts", wrap(async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 20), 1), 50), offset = Math.max(Number(req.query.offset || 0), 0);
  if (!Number.isInteger(limit) || !Number.isInteger(offset)) throw new AppError("Bad community pagination");
  const rows = db.prepare(`SELECT p.id, p.author, p.title, p.body, p.category, p.created_at,
    COUNT(DISTINCT r.id) AS reply_count, COUNT(DISTINCT l.user) AS like_count
    FROM community_posts p LEFT JOIN community_replies r ON r.post_id = p.id
    LEFT JOIN community_likes l ON l.post_id = p.id
    GROUP BY p.id ORDER BY p.created_at DESC LIMIT ? OFFSET ?`).all(limit, offset);
  const total = db.prepare("SELECT COUNT(*) AS count FROM community_posts").get().count;
  let viewer = null;
  const session = getCookie(req, SESSION_COOKIE);
  if (session) viewer = db.prepare("SELECT subject FROM auth_sessions WHERE token_hash = ? AND expires_at > ?").get(hashToken(session), Date.now())?.subject || null;
  if (!viewer && req.headers.authorization) { try { viewer = jwt.verify(req.headers.authorization.replace(/^Bearer /, ""), JWT_SECRET, { algorithms: ["HS256"], issuer: ["atlas", "neuralbazaar"] }).sub; } catch { viewer = null; } }
  res.json({ posts: rows.map((row) => publicCommunityPost(row, viewer)), total: Number(total) });
}));
app.post("/api/community/posts", authed, perUser(8, 3600000), wrap(async (req, res) => {
  const title = String(req.body?.title || "").trim().slice(0, 120), body = String(req.body?.body || "").trim().slice(0, 2500), category = String(req.body?.category || "General").trim();
  if (!title || title.length < 3) throw new AppError("Community post title must be at least 3 characters");
  if (!body || body.length < 3) throw new AppError("Community post must be at least 3 characters");
  if (!communityCategories.has(category)) throw new AppError("Choose a valid community category");
  const createdAt = Date.now(), result = db.prepare("INSERT INTO community_posts(author,title,body,category,created_at) VALUES(?,?,?,?,?)").run(userKey(req.user), title, body, category, createdAt);
  res.status(201).json({ post: { id: Number(result.lastInsertRowid), title, body, category, createdAt, replyCount: 0, likeCount: 0, liked: false, author: publicIdentity(req.user) } });
}));
app.get("/api/community/posts/:id/replies", wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad community post id");
  const rows = db.prepare("SELECT id, post_id, author, body, created_at FROM community_replies WHERE post_id = ? ORDER BY created_at ASC LIMIT 100").all(Number(req.params.id));
  res.json({ replies: rows.map(publicCommunityReply) });
}));
app.post("/api/community/posts/:id/replies", authed, perUser(20), wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad community post id");
  if (!db.prepare("SELECT 1 FROM community_posts WHERE id = ?").get(Number(req.params.id))) throw new AppError("Community post not found", 404);
  const body = String(req.body?.body || "").trim().slice(0, 1500);
  if (!body || body.length < 1) throw new AppError("Reply cannot be empty");
  const createdAt = Date.now(), result = db.prepare("INSERT INTO community_replies(post_id,author,body,created_at) VALUES(?,?,?,?)").run(Number(req.params.id), userKey(req.user), body, createdAt);
  res.status(201).json({ reply: publicCommunityReply({ id: result.lastInsertRowid, post_id: Number(req.params.id), author: userKey(req.user), body, created_at: createdAt }) });
}));
app.post("/api/community/posts/:id/like", authed, perUser(60), wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad community post id");
  if (!db.prepare("SELECT 1 FROM community_posts WHERE id = ?").get(Number(req.params.id))) throw new AppError("Community post not found", 404);
  db.prepare("INSERT OR IGNORE INTO community_likes(post_id,user,created_at) VALUES(?,?,?)").run(Number(req.params.id), userKey(req.user), Date.now());
  res.json({ liked: true });
}));
app.delete("/api/community/posts/:id/like", authed, perUser(60), wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad community post id");
  db.prepare("DELETE FROM community_likes WHERE post_id = ? AND user = ?").run(Number(req.params.id), userKey(req.user));
  res.json({ liked: false });
}));

app.get("/api/favorites", authed, wrap(async (req, res) => {
  const rows = db.prepare("SELECT model_id FROM favorites WHERE user = ? ORDER BY created_at DESC").all(userKey(req.user));
  res.json({ modelIds: rows.map((row) => row.model_id) });
}));
app.post("/api/favorites/:id", authed, perUser(60), wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad request");
  await getModel(req.params.id);
  db.prepare("INSERT OR IGNORE INTO favorites(user,model_id,created_at) VALUES(?,?,?)").run(userKey(req.user), Number(req.params.id), Date.now());
  res.status(201).json({ favorited: true });
}));
app.delete("/api/favorites/:id", authed, perUser(60), wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad request");
  db.prepare("DELETE FROM favorites WHERE user = ? AND model_id = ?").run(userKey(req.user), Number(req.params.id));
  res.json({ favorited: false });
}));

app.get("/api/creators/:wallet", wrap(async (req, res) => {
  if (!ethers.isAddress(req.params.wallet)) throw new AppError("Bad wallet address");
  const wallet = userKey(req.params.wallet);
  const profile = profileFor(wallet) || { displayName: "Atlas creator", bio: "", language: "", msme: "", website: "", avatarUrl: "", githubUrl: "" };
  const uploads = db.prepare("SELECT COUNT(*) AS count FROM artifacts WHERE owner = ?").get(wallet).count;
  res.json({ wallet, profile, uploads: Number(uploads) });
}));
app.post("/api/creator-profile", walletAuthed, perUser(10, 3600000), wrap(async (req, res) => {
  const clean = (value, max) => String(value || "").trim().slice(0, max);
  const displayName = clean(req.body?.displayName, 80), bio = clean(req.body?.bio, 500), language = clean(req.body?.language, 80), msme = clean(req.body?.msme, 160), website = clean(req.body?.website, 200), githubUrl = clean(req.body?.githubUrl, 200), avatarUrl = clean(req.body?.avatarUrl, 500);
  if (!displayName) throw new AppError("A creator display name is required");
  if (website && !/^https:\/\//i.test(website)) throw new AppError("Creator websites must use HTTPS");
  if (githubUrl && !/^https:\/\/((www\.)?github\.com)\//i.test(githubUrl)) throw new AppError("GitHub link must point to github.com");
  if (avatarUrl && !/^https:\/\//i.test(avatarUrl) && !avatarUrl.startsWith(`${PUBLIC_URL}/api/creator-avatar/`)) throw new AppError("Profile photo must use HTTPS");
  const wallet = userKey(req.user);
  db.prepare("INSERT OR REPLACE INTO creator_profiles(wallet,display_name,bio,language,msme,website,avatar_url,github_url,updated_at) VALUES(?,?,?,?,?,?,?,?,?)").run(wallet, displayName, bio, language, msme, website, avatarUrl, githubUrl, Date.now());
  res.json({ ok: true, profile: profileFor(wallet) });
}));
app.get("/api/creator-profile", walletAuthed, wrap(async (req, res) => {
  res.json({ profile: profileFor(req.user) || { wallet: userKey(req.user), displayName: "", bio: "", language: "", msme: "", website: "", avatarUrl: "", githubUrl: "" } });
}));
app.post("/api/creator-profile/avatar", walletAuthed, perUser(6, 3600000), profileUploadMiddleware, wrap(async (req, res) => {
  if (!req.file) throw new AppError("Choose a profile image", 422);
  const wallet = userKey(req.user), now = Date.now(), avatarUrl = `${PUBLIC_URL}/api/creator-avatar/${wallet}`;
  db.prepare("INSERT OR REPLACE INTO creator_avatars(wallet,mime_type,data,updated_at) VALUES(?,?,?,?)").run(wallet, req.file.mimetype, req.file.buffer, now);
  if (profileFor(wallet)) db.prepare("UPDATE creator_profiles SET avatar_url = ?, updated_at = ? WHERE wallet = ?").run(avatarUrl, now, wallet);
  else db.prepare("INSERT INTO creator_profiles(wallet,display_name,bio,language,msme,website,avatar_url,github_url,updated_at) VALUES(?,?,?,?,?,?,?,?,?)").run(wallet, "Atlas creator", "", "", "", "", avatarUrl, "", now);
  res.json({ ok: true, avatarUrl });
}));
app.get("/api/creator-avatar/:wallet", wrap(async (req, res) => {
  if (!ethers.isAddress(req.params.wallet)) throw new AppError("Bad wallet address");
  const avatar = db.prepare("SELECT mime_type, data FROM creator_avatars WHERE wallet = ?").get(userKey(req.params.wallet));
  if (!avatar) throw new AppError("Profile image not found", 404);
  res.set("Cache-Control", "public, max-age=3600");
  res.type(avatar.mime_type).send(avatar.data);
}));
app.get("/api/creator-dashboard", walletAuthed, wrap(async (req, res) => {
  const wallet = userKey(req.user), total = Number(await market.modelCount()), models = [];
  let onchainSales = 0;
  for (let id = 0; id < total; id++) {
    const model = await market.getModel(id);
    if (String(model.creator).toLowerCase() !== wallet) continue;
    onchainSales += Number(model.sales);
    models.push(modelJson(id, model));
  }
  const onchainEarnings = await market.earnings(req.user);
  const fiat = db.prepare("SELECT COUNT(*) AS payments, COALESCE(SUM(gross_paise),0) AS gross, COALESCE(SUM(platform_fee_paise),0) AS platformFee, COALESCE(SUM(creator_paise),0) AS creatorNet FROM fiat_earnings WHERE creator = ?").get(wallet);
  const recentFiat = db.prepare("SELECT model_id AS modelId, gross_paise AS grossPaise, platform_fee_paise AS platformFeePaise, creator_paise AS creatorPaise, status, created_at AS createdAt FROM fiat_earnings WHERE creator = ? ORDER BY created_at DESC LIMIT 10").all(wallet);
  res.json({ profile: profileFor(wallet), stats: { modelCount: models.length, onchainSales, onchainEarningsWei: onchainEarnings.toString(), fiatPayments: Number(fiat.payments || 0), fiatGrossPaise: Number(fiat.gross || 0), fiatPlatformFeePaise: Number(fiat.platformFee || 0), fiatCreatorNetPaise: Number(fiat.creatorNet || 0) }, models, recentFiat });
}));

app.get("/api/admin/me", adminAuthed, wrap(async (req, res) => {
  res.json({ subject: userKey(req.user), role: req.adminRole, permissions: { reviewIdentity: true, reviewEvidence: true, reviewModels: true, moderateReports: ["admin", "moderator"].includes(req.adminRole), manageRoles: req.adminRole === "admin" } });
}));
app.get("/api/admin/overview", adminAuthed, wrap(async (req, res) => {
  const count = (sql, ...args) => Number(db.prepare(sql).get(...args)?.count || 0);
  res.json({ role: req.adminRole, counts: {
    pendingIdentity: count("SELECT COUNT(*) AS count FROM creator_identity WHERE status = 'pending_review'"),
    pendingVerifications: count("SELECT COUNT(*) AS count FROM model_verifications WHERE status = 'pending_review'"),
    pendingEvidence: count("SELECT COUNT(*) AS count FROM model_evidence WHERE status = 'pending_review'"),
    openReports: count("SELECT COUNT(*) AS count FROM reports WHERE status = 'open'"),
    activeTakedowns: count("SELECT COUNT(*) AS count FROM model_moderation WHERE status = 'takedown'"),
    automationFlags: count("SELECT COUNT(*) AS count FROM automation_events WHERE outcome = 'flagged_for_human_review'")
  }, automation: { enabled: AUTOMATED_MODERATION_ENABLED, autoApproveLowRisk: AUTO_APPROVE_MODEL_VERIFICATION, triageReports: AUTO_TRIAGE_REPORTS, actor: AUTOMATION_ACTOR, humanReviewRequired: true } });
}));
app.get("/api/admin/automation", adminAuthed, wrap(async (req, res) => {
  const rows = db.prepare("SELECT id, action, target_type AS targetType, target_id AS targetId, outcome, reason, details, created_at AS createdAt FROM automation_events ORDER BY created_at DESC LIMIT 50").all().map((row) => {
    let details = {}; try { details = JSON.parse(row.details); } catch { /* Keep malformed legacy details private. */ }
    return { ...row, details };
  });
  res.json({ enabled: AUTOMATED_MODERATION_ENABLED, actor: AUTOMATION_ACTOR, capabilities: { artifactScanning: true, provenanceChecks: true, lowRiskModelApproval: AUTO_APPROVE_MODEL_VERIFICATION, reportTriage: AUTO_TRIAGE_REPORTS, kycFinalDecision: false, evidenceFinalDecision: false, takedown: false, roleManagement: false, payments: false }, humanReviewRequired: true, events: rows });
}));
app.get("/api/admin/roles", adminOwnerAuthed, wrap(async (req, res) => {
  const rows = db.prepare("SELECT subject, role, granted_by AS grantedBy, created_at AS createdAt, revoked_at AS revokedAt, notes FROM admin_roles ORDER BY created_at ASC").all();
  res.json({ roles: rows });
}));
app.post("/api/admin/roles", adminOwnerAuthed, wrap(async (req, res) => {
  const subject = userKey(cleanText(req.body?.subject, 254)), role = String(req.body?.role || "moderator").toLowerCase(), notes = cleanText(req.body?.notes, 500);
  if (!(ethers.isAddress(subject) || EMAIL_RE.test(subject))) throw new AppError("Role subject must be a wallet address or email", 422);
  if (!ethers.isAddress(subject) && !db.prepare("SELECT 1 FROM users WHERE email = ? AND email_verified = 1").get(subject)) throw new AppError("The email must belong to an existing verified Atlas account", 422);
  if (!ADMIN_ROLES.has(role)) throw new AppError("Role must be admin, moderator, or reviewer", 422);
  db.prepare(`INSERT INTO admin_roles(subject,role,granted_by,created_at,revoked_at,notes) VALUES(?,?,?,?,NULL,?)
    ON CONFLICT(subject) DO UPDATE SET role=excluded.role, granted_by=excluded.granted_by, created_at=excluded.created_at, revoked_at=NULL, notes=excluded.notes`).run(subject, role, userKey(req.user), Date.now(), notes);
  res.status(201).json({ ok: true, subject, role, message: "Admin role granted" });
}));
app.delete("/api/admin/roles/:subject", adminOwnerAuthed, wrap(async (req, res) => {
  const subject = userKey(decodeURIComponent(String(req.params.subject || "")));
  if (subject === userKey(req.user)) throw new AppError("The current administrator cannot revoke their own role", 422);
  const result = db.prepare("UPDATE admin_roles SET revoked_at = ? WHERE subject = ? AND revoked_at IS NULL").run(Date.now(), subject);
  if (!result.changes) throw new AppError("Active admin role not found", 404);
  res.json({ ok: true, subject, message: "Admin role revoked" });
}));

app.post("/api/reports", authed, perUser(10, 3600000), wrap(async (req, res) => {
  if (!isId(req.body?.modelId)) throw new AppError("Bad model id");
  await getModel(req.body.modelId);
  const reason = String(req.body?.reason || "other").trim().slice(0, 80), details = String(req.body?.details || "").trim().slice(0, 1000);
  if (!reason) throw new AppError("A report reason is required");
  const riskLevel = classifyReport(reason, details), automatedAction = AUTO_TRIAGE_REPORTS && riskLevel === "high" ? "flagged_for_human_review" : "queued_for_review";
  const result = db.prepare("INSERT INTO reports(model_id,reporter,reason,details,status,created_at,risk_level,automated_action) VALUES(?,?,?,?,?,?,?,?)").run(Number(req.body.modelId), userKey(req.user), reason, details, "open", Date.now(), riskLevel, automatedAction);
  const reportId = Number(result.lastInsertRowid);
  if (AUTO_TRIAGE_REPORTS) recordAutomationEvent("report_triage", "report", reportId, automatedAction, riskLevel === "high" ? "High-risk report routed to human moderation" : "Report queued for human moderation", { modelId: Number(req.body.modelId), riskLevel, reason });
  res.status(201).json({ ok: true, reportId, status: "open", riskLevel, automatedAction, message: riskLevel === "high" ? "High-risk report flagged for human Atlas moderation" : "Report queued for Atlas moderation" });
}));
app.get("/api/admin/reports", moderationAuthed, wrap(async (req, res) => {
  const rows = db.prepare("SELECT id, model_id AS modelId, reporter, reason, details, status, risk_level AS riskLevel, automated_action AS automatedAction, reviewed_by AS reviewedBy, resolution, created_at AS createdAt, resolved_at AS resolvedAt FROM reports ORDER BY created_at DESC LIMIT 100").all();
  res.json({ reports: rows });
}));
app.post("/api/admin/reports/:id/review", moderationAuthed, wrap(async (req, res) => {
  if (!/^\d+$/.test(String(req.params.id || ""))) throw new AppError("Bad report id", 422);
  const action = String(req.body?.action || "dismiss").toLowerCase(), reason = cleanText(req.body?.reason, 1000), report = db.prepare("SELECT id, model_id AS modelId FROM reports WHERE id = ?").get(Number(req.params.id));
  if (!report) throw new AppError("Report not found", 404);
  if (!["dismiss", "resolve", "takedown", "restore"].includes(action)) throw new AppError("Action must be dismiss, resolve, takedown, or restore", 422);
  if (["takedown", "restore"].includes(action) && !reason) throw new AppError("Add a moderation reason", 422);
  if (action === "takedown") setModelModeration(report.modelId, "takedown", req.user, reason, "report_takedown");
  if (action === "restore") setModelModeration(report.modelId, "active", req.user, reason, "report_restore");
  const status = action === "dismiss" ? "dismissed" : action === "resolve" ? "resolved" : action === "takedown" ? "actioned" : "restored";
  db.prepare("UPDATE reports SET status = ?, reviewed_by = ?, resolution = ?, resolved_at = ? WHERE id = ?").run(status, userKey(req.user), reason, Date.now(), report.id);
  res.json({ ok: true, reportId: report.id, modelId: report.modelId, status, action });
}));
app.post("/api/admin/models/:id/takedown", moderationAuthed, wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad model id", 422);
  await getModel(req.params.id);
  const reason = cleanText(req.body?.reason, 1000);
  if (!reason) throw new AppError("A takedown reason is required", 422);
  setModelModeration(Number(req.params.id), "takedown", req.user, reason, "manual_takedown");
  res.json({ ok: true, modelId: Number(req.params.id), status: "takedown", message: "Model hidden from the catalogue and API access blocked" });
}));
app.post("/api/admin/models/:id/restore", moderationAuthed, wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad model id", 422);
  await getModel(req.params.id);
  const reason = cleanText(req.body?.reason, 1000);
  if (!reason) throw new AppError("A restoration reason is required", 422);
  setModelModeration(Number(req.params.id), "active", req.user, reason, "manual_restore");
  res.json({ ok: true, modelId: Number(req.params.id), status: "active" });
}));
app.get("/api/admin/models/:id/moderation-audit", moderationAuthed, wrap(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError("Bad model id", 422);
  const rows = db.prepare("SELECT id, model_id AS modelId, actor, action, reason, created_at AS createdAt FROM moderation_audit WHERE model_id = ? ORDER BY created_at ASC").all(Number(req.params.id));
  res.json({ audit: rows });
}));

app.get("/api/usage", authed, wrap(async (req, res) => {
  const modelId = req.query.model;
  if (modelId !== undefined && !isId(modelId)) throw new AppError("Bad model id");
  const where = modelId === undefined ? "user = ?" : "user = ? AND model_id = ?";
  const args = modelId === undefined ? [userKey(req.user)] : [userKey(req.user), Number(modelId)];
  const summary = db.prepare(`SELECT COUNT(*) AS calls, SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) AS successful, MAX(ts) AS lastCall FROM usage WHERE ${where}`).get(...args);
  res.json({ calls: Number(summary.calls || 0), successful: Number(summary.successful || 0), lastCall: summary.lastCall || null });
}));

// INR is a display/quote layer only. The licence is still settled by the wallet
// on the configured testnet, so the demo cannot accidentally imply fiat settlement.
app.get("/api/payments/quote", wrap(async (req, res) => {
  if (!/^\d+$/.test(String(req.query.wei || ""))) throw new AppError("Provide a wei amount");
  const wei = BigInt(req.query.wei);
  res.json({ currency: "INR", enabled: INR_PER_ETH > 0, inrPerEth: INR_PER_ETH || null, amountInr: INR_PER_ETH > 0 ? Number(ethers.formatEther(wei)) * INR_PER_ETH : null, settlement: INR_PAYMENTS_ENABLED ? "razorpay" : "on-chain-testnet", note: INR_PAYMENTS_ENABLED ? "Razorpay orders are verified server-side before access is granted" : "Configure Razorpay test credentials to enable INR/UPI checkout" });
}));

const razorpayRequest = async (method, endpoint, body) => {
  if (!INR_PAYMENTS_ENABLED) throw new AppError("INR checkout is not configured. Add Razorpay test credentials to the server environment", 503);
  const response = await ufetch(`${RAZORPAY_API_URL}${endpoint}`, {
    method, dispatcher: agent, headers: { Authorization: `Basic ${Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString("base64")}`, "Content-Type": "application/json", Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000)
  });
  const text = await response.text(); let result = {};
  try { result = JSON.parse(text); } catch { /* provider returned a non-JSON error */ }
  if (!response.ok) throw new AppError(result.error?.description || "Payment provider request failed", 502);
  return result;
};
const verifyHmac = (message, signature, secret) => {
  if (typeof signature !== "string" || !/^[0-9a-f]{64}$/i.test(signature)) return false;
  const expected = crypto.createHmac("sha256", secret).update(message).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(signature, "hex"));
};

// Razorpay Orders API: the server owns the amount and order id, so the browser
// cannot change the INR price. Access is granted only after signature + captured
// status verification, and webhook processing makes the flow resilient to tab closes.
app.post("/api/payments/order", authed, perUser(10, 60000), wrap(async (req, res) => {
  if (!INR_PAYMENTS_ENABLED) throw new AppError("INR checkout is not configured on this Atlas deployment", 503);
  if (!isId(req.body?.modelId)) throw new AppError("Bad model id");
  const modelId = Number(req.body.modelId), m = await getModel(modelId);
  if (!m.active || modelIsTakedown(modelId)) throw new AppError("This model is unavailable for new purchases", 410);
  if (await hasAccess(modelId, req.user)) throw new AppError("This wallet already has access", 409);
  const metadata = metadataFromURI(m.metadataURI), price = inrPrice(metadata.priceInr);
  if (!price) throw new AppError("This model has no INR price. The creator must publish one before UPI checkout", 422);
  const amount = Math.round(price * 100), receipt = `atlas_${modelId}_${crypto.randomBytes(6).toString("hex")}`;
  const order = await razorpayRequest("POST", "/orders", { amount, currency: "INR", receipt, notes: { model_id: String(modelId), wallet: userKey(req.user) }, partial_payment: false });
  if (!order.id || Number(order.amount) !== amount || order.currency !== "INR") throw new AppError("Payment provider returned an invalid order", 502);
  db.prepare("INSERT INTO payments(provider_order_id,model_id,user,amount,currency,status,created_at) VALUES(?,?,?,?,?,?,?)").run(order.id, modelId, userKey(req.user), amount, "INR", "created", Date.now());
  res.status(201).json({ keyId: RAZORPAY_KEY_ID, orderId: order.id, amount, currency: "INR", modelId, name: m.name, description: metadata.description || `Atlas licence for ${m.name}` });
}));

app.post("/api/payments/verify", authed, perUser(20, 60000), wrap(async (req, res) => {
  const { razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature } = req.body || {};
  if (!orderId || !paymentId || !signature || !verifyHmac(`${orderId}|${paymentId}`, signature, RAZORPAY_KEY_SECRET)) throw new AppError("Payment signature could not be verified", 400);
  const payment = db.prepare("SELECT * FROM payments WHERE provider_order_id = ? AND user = ?").get(orderId, userKey(req.user));
  if (!payment) throw new AppError("Payment order not found", 404);
  if (req.body?.modelId !== undefined && Number(req.body.modelId) !== payment.model_id) throw new AppError("Payment model does not match the order", 400);
  if (payment.provider_payment_id && payment.provider_payment_id !== paymentId) throw new AppError("Payment id does not match the order", 400);
  const providerPayment = await razorpayRequest("GET", `/payments/${encodeURIComponent(paymentId)}`);
  if (providerPayment.order_id !== orderId || Number(providerPayment.amount) !== payment.amount || providerPayment.currency !== payment.currency) throw new AppError("Payment details do not match the Atlas order", 400);
  if (providerPayment.status !== "captured") throw new AppError(`Payment is ${providerPayment.status}; access will activate after capture`, 409);
  db.prepare("UPDATE payments SET provider_payment_id = ?, signature = ?, status = 'captured', verified_at = ? WHERE id = ?").run(paymentId, signature, Date.now(), payment.id);
  grantFiatLicense(payment.id);
  try { await recordFiatEarning(payment.id); } catch (error) { console.error(JSON.stringify({ level: "error", msg: "fiat earning ledger failed", paymentId: payment.id, error: error.message })); }
  res.json({ ok: true, access: true, modelId: payment.model_id, paymentId });
}));

app.get("/api/payments/access", authed, wrap(async (req, res) => {
  const rows = db.prepare("SELECT model_id AS modelId, created_at AS createdAt FROM fiat_licenses WHERE user = ? ORDER BY created_at DESC").all(userKey(req.user));
  res.json({ modelIds: rows.map((row) => row.modelId), licenses: rows });
}));
app.get("/api/fiat-earnings", walletAuthed, wrap(async (req, res) => {
  const wallet = userKey(req.user);
  const summary = db.prepare("SELECT COALESCE(SUM(gross_paise),0) AS gross, COALESCE(SUM(platform_fee_paise),0) AS platformFee, COALESCE(SUM(creator_paise),0) AS creatorNet FROM fiat_earnings WHERE creator = ?").get(wallet);
  const rows = db.prepare("SELECT model_id AS modelId, gross_paise AS grossPaise, platform_fee_paise AS platformFeePaise, creator_paise AS creatorPaise, status, created_at AS createdAt FROM fiat_earnings WHERE creator = ? ORDER BY created_at DESC LIMIT 100").all(wallet);
  res.json({ currency: "INR", grossPaise: Number(summary.gross), platformFeePaise: Number(summary.platformFee), creatorNetPaise: Number(summary.creatorNet), rows });
}));

app.post("/api/payments/webhook", wrap(async (req, res) => {
  if (!RAZORPAY_WEBHOOK_SECRET || !verifyHmac(req.rawBody || Buffer.from(""), req.headers["x-razorpay-signature"], RAZORPAY_WEBHOOK_SECRET)) throw new AppError("Invalid webhook signature", 401);
  const event = req.body?.event, paymentEntity = req.body?.payload?.payment?.entity;
  if (paymentEntity?.order_id && paymentEntity?.id && event === "payment.captured") {
    const payment = db.prepare("SELECT id FROM payments WHERE provider_order_id = ?").get(paymentEntity.order_id);
    if (payment) {
      db.prepare("UPDATE payments SET provider_payment_id = ?, status = 'captured', verified_at = ? WHERE id = ?").run(paymentEntity.id, Date.now(), payment.id);
      grantFiatLicense(payment.id);
      try { await recordFiatEarning(payment.id); } catch (error) { console.error(JSON.stringify({ level: "error", msg: "fiat earning ledger failed", paymentId: payment.id, error: error.message })); }
    }
  } else if (paymentEntity?.order_id && paymentEntity?.id && event === "payment.failed") {
    db.prepare("UPDATE payments SET provider_payment_id = ?, status = 'failed', verified_at = ? WHERE provider_order_id = ?").run(paymentEntity.id, Date.now(), paymentEntity.order_id);
  }
  res.json({ ok: true });
}));

const upload = multer({ dest: TMP, limits: { fileSize: Number(env.MAX_UPLOAD_MB || 100) * 1048576, files: 1 },
  fileFilter: (r, f, cb) => cb(/\.(onnx|safetensors|gguf|tflite)$/i.test(f.originalname) ? null : new Error("type"), /\.(onnx|safetensors|gguf|tflite)$/i.test(f.originalname)) });
const sha = (p) => new Promise((ok, no) => { const h = crypto.createHash("sha256"); fs.createReadStream(p).on("data", (d) => h.update(d)).on("end", () => ok(h.digest("hex"))).on("error", no); });
const basicModelScan = (filePath, originalName) => {
  const name = String(originalName || "");
  if (name.includes("..") || /[\\/]/.test(name)) throw new AppError("The model filename is not safe", 422);
  const ext = path.extname(name).toLowerCase();
  const stat = fs.statSync(filePath);
  if (!stat.isFile() || stat.size === 0) throw new AppError("The uploaded model is empty", 422);
  // These lightweight checks catch common corrupt or mislabelled uploads without
  // pretending to replace a production malware scanner such as ClamAV.
  if (ext === ".gguf") {
    const header = Buffer.alloc(4), fd = fs.openSync(filePath, "r");
    try { fs.readSync(fd, header, 0, 4, 0); } finally { fs.closeSync(fd); }
    if (header.toString("ascii") !== "GGUF") throw new AppError("The GGUF file header is invalid", 422);
  }
  if (ext === ".safetensors") {
    const header = Buffer.alloc(8), fd = fs.openSync(filePath, "r");
    try { fs.readSync(fd, header, 0, 8, 0); } finally { fs.closeSync(fd); }
    const headerLength = Number(header.readBigUInt64LE(0));
    if (!Number.isSafeInteger(headerLength) || headerLength < 2 || headerLength > Math.min(stat.size - 8, 100 * 1024 * 1024)) throw new AppError("The SafeTensors header is invalid", 422);
  }
  return { status: "passed_basic", message: "Extension, filename, size, and format checks passed" };
};
const malwareScan = (filePath) => {
  if (!CLAMAV_HOST) return Promise.resolve({ status: "not_configured", message: "ClamAV is not configured; only the basic format scan ran" });
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: CLAMAV_HOST, port: CLAMAV_PORT });
    let output = "", settled = false;
    const finish = (result) => { if (settled) return; settled = true; socket.destroy(); resolve(result); };
    socket.setTimeout(30000, () => finish({ status: "error", message: "ClamAV scan timed out" }));
    socket.on("error", () => finish({ status: "error", message: "ClamAV scanner was unavailable" }));
    socket.on("data", (chunk) => {
      output += chunk.toString("utf8");
      if (/FOUND/i.test(output)) finish({ status: "infected", message: "ClamAV detected a threat" });
      else if (/OK\s*$/i.test(output.trim())) finish({ status: "passed", message: "ClamAV malware scan passed" });
    });
    socket.on("connect", () => {
      socket.write(Buffer.from("zINSTREAM\0", "ascii"));
      const stream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
      stream.on("data", (chunk) => { const size = Buffer.alloc(4); size.writeUInt32BE(chunk.length, 0); socket.write(size); socket.write(chunk); });
      stream.on("end", () => { const end = Buffer.alloc(4); socket.write(end); });
      stream.on("error", () => finish({ status: "error", message: "Model could not be read by ClamAV" }));
    });
  });
};

app.post("/api/upload", walletAuthed, perUser(5, 3600000), upload.single("file"), wrap(async (req, res) => {
  if (!req.file) throw new AppError("Upload an .onnx, .safetensors, .gguf or .tflite file");
  const owner = userKey(req.user);
  try {
    if (db.prepare("SELECT COUNT(*) c FROM artifacts WHERE owner = ?").get(owner).c >= 20) throw new AppError("Upload quota reached", 429);
    const scan = basicModelScan(req.file.path, req.file.originalname), malware = await malwareScan(req.file.path);
    if (malware.status === "infected") throw new AppError("The model was rejected because malware scanning found a threat", 422);
    if (REQUIRE_MALWARE_SCAN && malware.status !== "passed") throw new AppError(`The production malware scan is unavailable (${malware.message})`, 503);
    const hash = await sha(req.file.path);
    const destination = path.join(UPLOADS, hash);
    if (fs.existsSync(destination)) fs.unlinkSync(req.file.path); else fs.renameSync(req.file.path, destination);
    db.prepare("INSERT OR IGNORE INTO artifacts(hash,owner,size,name,scan_status,scan_message,scanned_at,malware_status,malware_message,malware_scanned_at) VALUES(?,?,?,?,?,?,?,?,?,?)").run(hash, owner, req.file.size, path.basename(req.file.originalname).slice(0, 120), scan.status, scan.message, Date.now(), malware.status, malware.message, CLAMAV_HOST ? Date.now() : null);
    if (AUTOMATED_MODERATION_ENABLED) recordAutomationEvent("artifact_scan", "artifact", hash, malware.status === "passed" || malware.status === "not_configured" ? "passed" : malware.status, malware.message, { scanStatus: scan.status, malwareStatus: malware.status, owner });
    res.json({ contentHash: "0x" + hash, artifactURI: `${PUBLIC_URL}/api/artifact/${hash}`, scan, malware });
  } catch (error) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    throw error;
  }
}));

app.post("/api/metadata", walletAuthed, perUser(30), wrap(async (req, res) => {
  const { name, description = "", version = "1.0.0", artifactHash = null, inputSchema = {}, outputSchema = {}, tags = [], source = null, license = null, licenseUrl = null, provenanceUrl = null, priceInr = null, modelCard = {} } = req.body || {};
  if (typeof name !== "string" || !name.trim() || name.length > 80) throw new AppError("A model name is required");
  if (typeof description !== "string" || description.length > 2000) throw new AppError("Description is too long");
  if (typeof version !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(version)) throw new AppError("Invalid version");
  if (!Array.isArray(tags) || tags.length > 20 || tags.some((t) => typeof t !== "string" || t.length > 40)) throw new AppError("Invalid tags");
  let normalizedHash = null;
  if (artifactHash !== null) {
    if (typeof artifactHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(artifactHash)) throw new AppError("Invalid artifact hash");
    normalizedHash = artifactHash.slice(2).toLowerCase();
    const artifact = db.prepare("SELECT owner FROM artifacts WHERE hash = ?").get(normalizedHash);
    if (!artifact || artifact.owner !== userKey(req.user)) throw new AppError("Artifact ownership mismatch", 403);
  }
  if (source !== null && (typeof source !== "object" || Array.isArray(source))) throw new AppError("Invalid source metadata");
  if (license !== null && (typeof license !== "string" || license.length > 120)) throw new AppError("Invalid licence metadata");
  if (licenseUrl !== null && licenseUrl !== "" && !/^https:\/\//i.test(String(licenseUrl))) throw new AppError("Licence proof URL must use HTTPS");
  if (provenanceUrl !== null && provenanceUrl !== "" && !/^https:\/\//i.test(String(provenanceUrl))) throw new AppError("Provenance URL must use HTTPS");
  const normalizedCard = normalizeModelCard(modelCard);
  const normalizedPriceInr = inrPrice(priceInr);
  const manifest = JSON.stringify({
    name: name.trim(), description, version, creator: userKey(req.user),
    artifactHash: normalizedHash ? "0x" + normalizedHash : null,
    inputSchema, outputSchema, tags, source, license: license ? normalizedLicense(license) : null, licenseUrl: licenseUrl ? cleanText(licenseUrl, 500) : null, provenanceUrl: provenanceUrl ? cleanText(provenanceUrl, 500) : null, priceInr: normalizedPriceInr, modelCard: normalizedCard
  });
  const id = crypto.createHash("sha256").update(manifest).digest("hex");
  db.prepare("INSERT OR IGNORE INTO metadata VALUES(?,?,?,?)").run(id, userKey(req.user), manifest, Date.now());
  res.json({ metadataURI: `${PUBLIC_URL}/api/metadata/${id}`, id });
}));

const proofUrlKey = (value) => cleanText(value, 500).replace(/\/+$/, "").toLowerCase();
const verificationInput = (body, sourceType, manifest) => {
  const license = normalizedLicense(body?.license);
  if (!license || !ALLOWED_MODEL_LICENSES.has(license)) throw new AppError(`Choose an approved model licence: ${Array.from(ALLOWED_MODEL_LICENSES).join(", ")}`, 422);
  const licenseUrl = cleanText(body?.licenseUrl, 500);
  if (!/^https:\/\//i.test(licenseUrl)) throw new AppError("Provide an HTTPS licence or proof URL", 422);
  if (sourceType === "huggingface") {
    const expected = proofUrlKey(manifest?.licenseUrl), supplied = proofUrlKey(licenseUrl);
    if (!expected || supplied !== expected || license !== normalizedLicense(manifest?.license)) throw new AppError("The Hugging Face licence and model-card URL must match the imported repository", 422);
  } else if (STANDARD_LICENSE_URLS[license] && !STANDARD_LICENSE_URLS[license].has(proofUrlKey(licenseUrl))) {
    throw new AppError("Use the official licence URL for this standard licence; custom URLs require admin review", 422);
  }
  const provenanceUrl = cleanText(body?.provenanceUrl || manifest?.provenanceUrl, 500);
  if (provenanceUrl && !/^https:\/\//i.test(provenanceUrl)) throw new AppError("Provenance URL must use HTTPS", 422);
  const modelCard = normalizeModelCard(body?.modelCard);
  if (!modelCard.purpose || !modelCard.trainingData || !modelCard.limitations || !modelCard.intendedUsers) throw new AppError("Complete the model card: purpose, training data, limitations, and intended users are required", 422);
  const declarations = body?.declarations;
  if (!declarations || declarations.ownership !== true || declarations.safety !== true || declarations.responsibility !== true) throw new AppError("Accept all creator verification declarations before continuing", 422);
  return { license, licenseUrl, provenanceUrl, modelCard, declarations: { ownership: true, safety: true, responsibility: true } };
};
const verificationMessage = ({ creator, metadataId, artifactHash, license, licenseUrl, provenanceUrl, modelCard, identityStatus, nonce }) => [
  "Atlas model verification",
  `Creator: ${creator}`,
  `Metadata: ${metadataId}`,
  `Artifact: ${artifactHash}`,
  `Licence: ${license}`,
  `Licence URL: ${licenseUrl || "none"}`,
  `Provenance URL: ${provenanceUrl || "none"}`,
  `Identity review status: ${identityStatus}`,
  `Purpose: ${modelCard.purpose}`,
  `Training data: ${modelCard.trainingData}`,
  `Limitations: ${modelCard.limitations}`,
  `Intended users: ${modelCard.intendedUsers}`,
  `Nonce: ${nonce}`,
  "I attest that I own or can distribute this model, have disclosed material risks, and accept responsibility for the submitted information."
].join("\n");
const auditVerification = (id, actor, action, details = {}) => db.prepare("INSERT INTO verification_audit(verification_id,actor,action,details,created_at) VALUES(?,?,?,?,?)").run(id, userKey(actor), action, JSON.stringify(details), Date.now());
const automatedVerificationDecision = (row, evidence) => {
  const reasons = [];
  if (!AUTOMATED_MODERATION_ENABLED) reasons.push("Automated moderation is disabled");
  if (!AUTO_APPROVE_MODEL_VERIFICATION) reasons.push("Model auto-approval is disabled");
  if (row.provenance_status !== "passed") reasons.push("Provenance requires human review");
  if (REQUIRE_KYC_FOR_LISTING && row.identity_status !== "verified") reasons.push("Creator identity is not verified");
  if (REQUIRE_MALWARE_SCAN && !["passed_clamav", "passed_upstream"].includes(row.scan_status)) reasons.push("Required malware scan is not complete");
  const evidenceRequired = ["commercial", "proprietary", "custom"].includes(row.license);
  if (evidenceRequired) reasons.push("Commercial, proprietary, and custom licences require human evidence review");
  if (evidence && evidence.status !== "approved") reasons.push("Submitted evidence requires human review");
  return { status: reasons.length ? "pending_review" : "approved", reasons };
};
const provenanceCheck = ({ creator, artifactHash, sourceType, manifest }) => {
  if (sourceType === "huggingface") return { status: "passed", sourceUrl: manifest?.provenanceUrl || manifest?.licenseUrl || "", sourceRevision: manifest?.source?.revision || "", duplicateOf: "", message: "Upstream Hugging Face repository and revision recorded; this is not a semantic plagiarism verdict" };
  const rows = db.prepare("SELECT id, owner, manifest FROM metadata WHERE owner <> ? LIMIT 5000").all(userKey(creator));
  for (const row of rows) {
    try {
      const other = JSON.parse(row.manifest);
      if (String(other.artifactHash || "").toLowerCase() === artifactHash.toLowerCase()) return { status: "needs_review", sourceUrl: other.provenanceUrl || "", sourceRevision: "", duplicateOf: row.id, message: "The exact SHA-256 is already registered by another creator; human provenance review is required" };
    } catch { /* Ignore malformed historical manifests during this check. */ }
  }
  return { status: "passed", sourceUrl: manifest?.provenanceUrl || "", sourceRevision: "", duplicateOf: "", message: "No exact SHA-256 duplicate found in the Atlas registry; this is not a semantic plagiarism verdict" };
};

// A creator submits a model card and legal/safety declarations before the wallet
// signs the exact facts that will be attached to the model listing.
app.post("/api/model-verifications/prepare", walletAuthed, perUser(10, 3600000), wrap(async (req, res) => {
  const metadataId = String(req.body?.metadataId || "").toLowerCase(), artifactHash = String(req.body?.artifactHash || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(metadataId) || !/^0x[0-9a-f]{64}$/.test(artifactHash)) throw new AppError("A valid metadata id and artifact hash are required", 422);
  const metadataRow = db.prepare("SELECT owner, manifest FROM metadata WHERE id = ?").get(metadataId);
  if (!metadataRow || metadataRow.owner !== userKey(req.user)) throw new AppError("Metadata ownership mismatch", 403);
  let manifest = {}; try { manifest = JSON.parse(metadataRow.manifest); } catch { throw new AppError("Model metadata is invalid", 422); }
  const sourceType = String(req.body?.sourceType || "direct").toLowerCase();
  if (!["direct", "huggingface"].includes(sourceType)) throw new AppError("Unsupported model source", 422);
  const identity = identityFor(req.user);
  if (REQUIRE_KYC_FOR_LISTING && identity.status !== "verified") throw new AppError("Complete creator identity verification before listing a model", 403);
  let artifact = null;
  if (sourceType === "direct") {
    artifact = db.prepare("SELECT owner, scan_status AS scanStatus, malware_status AS malwareStatus, malware_message AS malwareMessage FROM artifacts WHERE hash = ?").get(artifactHash.slice(2));
    if (!artifact || artifact.owner !== userKey(req.user)) throw new AppError("Upload the model through Atlas before verifying it", 403);
    if (artifact.scanStatus !== "passed_basic") throw new AppError("The model has not passed the upload safety scan", 422);
    if (REQUIRE_MALWARE_SCAN && artifact.malwareStatus !== "passed") throw new AppError(`The model must pass the malware scan before listing (${artifact.malwareMessage || "scan unavailable"})`, 422);
  }
  const supplied = verificationInput({ ...req.body, license: req.body?.license || manifest.license, licenseUrl: req.body?.licenseUrl || manifest.licenseUrl, provenanceUrl: req.body?.provenanceUrl || manifest.provenanceUrl, modelCard: req.body?.modelCard || manifest.modelCard }, sourceType, manifest);
  const provenance = provenanceCheck({ creator: req.user, artifactHash, sourceType, manifest: { ...manifest, provenanceUrl: supplied.provenanceUrl } });
  const scanStatus = sourceType === "huggingface" ? "passed_upstream" : (artifact.malwareStatus === "passed" ? "passed_clamav" : "passed_basic_only");
  const id = verificationId(), nonce = randomToken(16), message = verificationMessage({ creator: userKey(req.user), metadataId, artifactHash, identityStatus: identity.status, ...supplied, nonce });
  db.prepare("INSERT INTO model_verifications(id,creator,metadata_id,artifact_hash,license,license_url,model_card_json,declarations_json,message,message_hash,signature,scan_status,status,created_at,identity_status,provenance_url,provenance_status,provenance_message) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").run(id, userKey(req.user), metadataId, artifactHash, supplied.license, supplied.licenseUrl, JSON.stringify(supplied.modelCard), JSON.stringify(supplied.declarations), message, hashToken(message), "", scanStatus, "awaiting_signature", Date.now(), identity.status, supplied.provenanceUrl, provenance.status, provenance.message);
  db.prepare("INSERT INTO model_provenance(verification_id,status,source_url,source_revision,duplicate_of,message,checked_at) VALUES(?,?,?,?,?,?,?)").run(id, provenance.status, provenance.sourceUrl, provenance.sourceRevision, provenance.duplicateOf, provenance.message, Date.now());
  auditVerification(id, req.user, "prepared", { sourceType, artifactHash, identityStatus: identity.status, provenanceStatus: provenance.status, scanStatus });
  if (AUTOMATED_MODERATION_ENABLED) recordAutomationEvent("provenance_check", "verification", id, provenance.status === "passed" ? "passed" : "flagged", provenance.message, { sourceType, artifactHash, provenanceStatus: provenance.status });
  res.status(201).json({ verificationId: id, status: "awaiting_signature", message, scanStatus, identityStatus: identity.status, provenanceStatus: provenance.status, provenanceMessage: provenance.message, autoApproval: AUTO_APPROVE_MODEL_VERIFICATION && provenance.status === "passed" && !["commercial", "proprietary", "custom"].includes(supplied.license) });
}));

app.post("/api/model-verifications/:id/attest", walletAuthed, perUser(10, 3600000), wrap(async (req, res) => {
  const id = String(req.params.id || ""), row = db.prepare("SELECT * FROM model_verifications WHERE id = ? AND creator = ?").get(id, userKey(req.user));
  if (!row) throw new AppError("Verification request not found", 404);
  if (row.status !== "awaiting_signature") throw new AppError(`Verification is already ${row.status}`, 409);
  const signature = String(req.body?.signature || "");
  let recovered; try { recovered = ethers.verifyMessage(row.message, signature); } catch { throw new AppError("The wallet signature is invalid", 422); }
  if (userKey(recovered) !== userKey(req.user) || hashToken(row.message) !== row.message_hash) throw new AppError("The wallet signature does not match this verification request", 422);
  const evidence = db.prepare("SELECT status FROM model_evidence WHERE verification_id = ? AND kind = 'license' ORDER BY created_at DESC LIMIT 1").get(id);
  const evidenceRequired = ["commercial", "proprietary", "custom"].includes(row.license);
  if (evidenceRequired && !evidence) throw new AppError("Upload the licence document before signing a custom, proprietary, or commercial listing", 422);
  const decision = automatedVerificationDecision(row, evidence), status = decision.status, now = Date.now();
  db.prepare("UPDATE model_verifications SET signature = ?, status = ?, attested_at = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?").run(signature, status, now, status === "approved" ? now : null, status === "approved" ? AUTOMATION_ACTOR : "", id);
  auditVerification(id, req.user, "attested", { status });
  if (AUTOMATED_MODERATION_ENABLED) {
    const outcome = status === "approved" ? "auto_approved" : "flagged_for_human_review";
    recordAutomationEvent("model_verification", "verification", id, outcome, decision.reasons.join("; ") || "Low-risk verification checks passed", { status, reasons: decision.reasons, license: row.license, provenanceStatus: row.provenance_status, scanStatus: row.scan_status });
    auditVerification(id, AUTOMATION_ACTOR, "automation_decision", { status, reasons: decision.reasons });
  }
  res.json({ ok: true, verificationId: id, status, message: status === "approved" ? "Model verification auto-approved by Atlas checks" : "Model submitted for human admin review", adminReviewRequired: status !== "approved", automation: { enabled: AUTOMATED_MODERATION_ENABLED, outcome: status === "approved" ? "auto_approved" : "human_review_required", reasons: decision.reasons } });
}));

app.get("/api/model-verifications/:id", walletAuthed, wrap(async (req, res) => {
  const row = db.prepare("SELECT id, status, license, license_url AS licenseUrl, scan_status AS scanStatus, identity_status AS identityStatus, provenance_url AS provenanceUrl, provenance_status AS provenanceStatus, provenance_message AS provenanceMessage, rejection_reason AS rejectionReason, created_at AS createdAt, attested_at AS attestedAt, reviewed_at AS reviewedAt FROM model_verifications WHERE id = ? AND creator = ?").get(String(req.params.id || ""), userKey(req.user));
  if (!row) throw new AppError("Verification request not found", 404);
  const evidence = db.prepare("SELECT id, verification_id, kind, file_name, mime_type, sha256, size, status, notes, created_at, reviewed_at FROM model_evidence WHERE verification_id = ? ORDER BY created_at DESC").all(row.id);
  res.json({ verification: row, evidence: evidence.map(publicEvidence) });
}));

app.post("/api/model-verifications/:id/evidence", walletAuthed, perUser(10, 3600000), evidenceUploadMiddleware, wrap(async (req, res) => {
  const id = String(req.params.id || ""), row = db.prepare("SELECT id FROM model_verifications WHERE id = ? AND creator = ?").get(id, userKey(req.user));
  if (!row) throw new AppError("Verification request not found", 404);
  if (!req.file) throw new AppError("Choose a licence or provenance evidence file", 422);
  const kind = String(req.body?.kind || "license").toLowerCase();
  if (!["license", "provenance"].includes(kind)) throw new AppError("Evidence kind must be licence or provenance", 422);
  const idForFile = evidenceId(), digest = hashBuffer(req.file.buffer), destination = privateEvidencePath(idForFile);
  fs.writeFileSync(destination, req.file.buffer, { mode: 0o600 });
  db.prepare("INSERT INTO model_evidence(id,verification_id,kind,file_name,mime_type,sha256,size,storage_path,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)").run(idForFile, id, kind, safeEvidenceName(req.file.originalname), req.file.mimetype, digest, req.file.size, destination, "pending_review", Date.now());
  auditVerification(id, req.user, "evidence_uploaded", { evidenceId: idForFile, kind, sha256: digest });
  res.status(201).json({ ok: true, evidence: { id: idForFile, verificationId: id, kind, fileName: safeEvidenceName(req.file.originalname), mimeType: req.file.mimetype, sha256: digest, size: req.file.size, status: "pending_review" } });
}));

app.get("/api/model-verifications/:id/evidence", walletAuthed, wrap(async (req, res) => {
  const id = String(req.params.id || "");
  if (!db.prepare("SELECT 1 FROM model_verifications WHERE id = ? AND creator = ?").get(id, userKey(req.user))) throw new AppError("Verification request not found", 404);
  const rows = db.prepare("SELECT id, verification_id, kind, file_name, mime_type, sha256, size, status, notes, created_at, reviewed_at FROM model_evidence WHERE verification_id = ? ORDER BY created_at DESC").all(id);
  res.json({ evidence: rows.map(publicEvidence) });
}));

app.get("/api/admin/model-verifications", adminAuthed, wrap(async (req, res) => {
  const status = String(req.query.status || "pending_review");
  const allowed = new Set(["awaiting_signature", "pending_review", "approved", "rejected"]);
  if (!allowed.has(status)) throw new AppError("Invalid verification status", 422);
  const rows = db.prepare("SELECT id, creator, metadata_id AS metadataId, artifact_hash AS artifactHash, license, license_url AS licenseUrl, model_card_json AS modelCard, scan_status AS scanStatus, identity_status AS identityStatus, provenance_url AS provenanceUrl, provenance_status AS provenanceStatus, provenance_message AS provenanceMessage, status, rejection_reason AS rejectionReason, created_at AS createdAt, attested_at AS attestedAt FROM model_verifications WHERE status = ? ORDER BY created_at ASC LIMIT 100").all(status).map((row) => ({ ...row, modelCard: JSON.parse(row.modelCard), evidence: db.prepare("SELECT id, kind, file_name AS fileName, mime_type AS mimeType, sha256, size, status, notes, created_at AS createdAt, reviewed_at AS reviewedAt FROM model_evidence WHERE verification_id = ? ORDER BY created_at DESC").all(row.id) }));
  res.json({ verifications: rows });
}));

app.post("/api/admin/model-verifications/:id/review", adminAuthed, wrap(async (req, res) => {
  const status = String(req.body?.status || "").toLowerCase();
  if (!["approved", "rejected"].includes(status)) throw new AppError("Review status must be approved or rejected", 422);
  const id = String(req.params.id || ""), row = db.prepare("SELECT id, status FROM model_verifications WHERE id = ?").get(id);
  if (!row) throw new AppError("Verification request not found", 404);
  if (row.status !== "pending_review") throw new AppError("Only pending verifications can be reviewed", 409);
  const reason = cleanText(req.body?.reason, 1000);
  if (status === "rejected" && !reason) throw new AppError("A rejection reason is required", 422);
  if (status === "approved") {
    const verification = db.prepare("SELECT license, scan_status AS scanStatus, identity_status AS identityStatus, provenance_status AS provenanceStatus FROM model_verifications WHERE id = ?").get(id);
    const evidence = db.prepare("SELECT status FROM model_evidence WHERE verification_id = ? AND kind = 'license' ORDER BY created_at DESC LIMIT 1").get(id);
    if (REQUIRE_KYC_FOR_LISTING && verification.identityStatus !== "verified") throw new AppError("Creator identity must be verified before approving this model", 422);
    if (REQUIRE_MALWARE_SCAN && verification.scanStatus !== "passed_clamav") throw new AppError("The model has not passed ClamAV malware scanning", 422);
    if (verification.provenanceStatus !== "passed") throw new AppError("Provenance review must pass before approving this model", 422);
    if (["commercial", "proprietary", "custom"].includes(verification.license) && evidence?.status !== "approved") throw new AppError("The licence evidence must be reviewed and approved first", 422);
  }
  const now = Date.now();
  db.prepare("UPDATE model_verifications SET status = ?, rejection_reason = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?").run(status, reason, now, userKey(req.user), id);
  auditVerification(id, req.user, status, { reason });
  res.json({ ok: true, verificationId: id, status, reason });
}));
app.post("/api/admin/model-verifications/:id/provenance-review", adminAuthed, wrap(async (req, res) => {
  const id = String(req.params.id || ""), status = String(req.body?.status || "").toLowerCase(), reason = cleanText(req.body?.reason, 1000);
  if (!["passed", "rejected"].includes(status)) throw new AppError("Provenance status must be passed or rejected", 422);
  if (status === "rejected" && !reason) throw new AppError("A reason is required when rejecting provenance", 422);
  if (!db.prepare("SELECT 1 FROM model_verifications WHERE id = ?").get(id)) throw new AppError("Verification request not found", 404);
  db.prepare("UPDATE model_verifications SET provenance_status = ?, provenance_message = ?, rejection_reason = CASE WHEN ? = 'rejected' THEN ? ELSE rejection_reason END WHERE id = ?").run(status, reason || "Moderator marked provenance as passed", status, reason, id);
  db.prepare("UPDATE model_provenance SET status = ?, message = ?, checked_at = ? WHERE verification_id = ?").run(status, reason || "Moderator marked provenance as passed", Date.now(), id);
  auditVerification(id, req.user, `provenance_${status}`, { reason });
  res.json({ ok: true, verificationId: id, provenanceStatus: status, reason });
}));
app.get("/api/admin/model-verifications/:id/audit", adminAuthed, wrap(async (req, res) => {
  const rows = db.prepare("SELECT id, verification_id AS verificationId, actor, action, details, created_at AS createdAt FROM verification_audit WHERE verification_id = ? ORDER BY created_at ASC").all(String(req.params.id || ""));
  res.json({ audit: rows.map((row) => ({ ...row, details: JSON.parse(row.details) })) });
}));
app.get("/api/admin/model-evidence/:id", adminAuthed, wrap(async (req, res) => {
  const row = db.prepare("SELECT storage_path AS storagePath, file_name AS fileName, mime_type AS mimeType FROM model_evidence WHERE id = ?").get(String(req.params.id || ""));
  if (!row || !fs.existsSync(row.storagePath)) throw new AppError("Evidence not found", 404);
  res.type(row.mimeType).set("Content-Disposition", `attachment; filename="${safeEvidenceName(row.fileName)}"`).send(fs.readFileSync(row.storagePath));
}));
app.post("/api/admin/model-evidence/:id/review", adminAuthed, wrap(async (req, res) => {
  const status = String(req.body?.status || "").toLowerCase(), notes = cleanText(req.body?.notes, 1000), id = String(req.params.id || "");
  if (!["approved", "rejected"].includes(status)) throw new AppError("Evidence review status must be approved or rejected", 422);
  if (status === "rejected" && !notes) throw new AppError("Add a reason when rejecting evidence", 422);
  const row = db.prepare("SELECT id, verification_id AS verificationId FROM model_evidence WHERE id = ?").get(id);
  if (!row) throw new AppError("Evidence not found", 404);
  db.prepare("UPDATE model_evidence SET status = ?, reviewer = ?, notes = ?, reviewed_at = ? WHERE id = ?").run(status, userKey(req.user), notes, Date.now(), id);
  auditVerification(row.verificationId, req.user, `evidence_${status}`, { evidenceId: id, notes });
  res.json({ ok: true, evidenceId: id, status, notes });
}));

// Identity/KYC is intentionally a review queue. Atlas stores hashes and private
// evidence metadata, not raw identity numbers, and does not claim automatic KYC.
app.get("/api/creator-identity", walletAuthed, wrap(async (req, res) => {
  res.json({ identity: identityFor(req.user), statement: "Identity review is a moderation signal, not a legal identity guarantee" });
}));
app.post("/api/creator-identity", walletAuthed, perUser(5, 3600000), wrap(async (req, res) => {
  const fullName = cleanText(req.body?.fullName, 120), country = cleanText(req.body?.country, 80), provider = cleanText(req.body?.provider || "manual", 80), reference = cleanText(req.body?.providerReference, 200);
  if (fullName.length < 2 || !country) throw new AppError("Full name and country are required for identity review", 422);
  if (reference.length < 6) throw new AppError("Provide the KYC provider reference or manual case ID", 422);
  const wallet = userKey(req.user), now = Date.now();
  db.prepare(`INSERT INTO creator_identity(wallet,status,provider,country,full_name_hash,provider_reference_hash,submitted_at,reviewed_at,reviewed_by,rejection_reason)
    VALUES(?,?,?,?,?,?,? ,NULL,'','') ON CONFLICT(wallet) DO UPDATE SET status='pending_review', provider=excluded.provider, country=excluded.country, full_name_hash=excluded.full_name_hash, provider_reference_hash=excluded.provider_reference_hash, submitted_at=excluded.submitted_at, reviewed_at=NULL, reviewed_by='', rejection_reason=''`).run(wallet, "pending_review", provider, country, hashToken(fullName), hashToken(reference), now);
  res.status(201).json({ ok: true, identity: identityFor(wallet), message: "Identity case submitted for manual review" });
}));
app.post("/api/creator-identity/document", walletAuthed, perUser(3, 3600000), evidenceUploadMiddleware, wrap(async (req, res) => {
  if (!req.file) throw new AppError("Choose an identity document", 422);
  const wallet = userKey(req.user), current = identityFor(wallet);
  if (current.status === "unverified") throw new AppError("Submit the identity form before uploading a document", 409);
  const digest = hashBuffer(req.file.buffer), idForFile = `kyc-${wallet}-${randomToken(8)}`, destination = privateEvidencePath(idForFile);
  fs.writeFileSync(destination, req.file.buffer, { mode: 0o600 });
  db.prepare("UPDATE creator_identity SET document_name = ?, document_mime = ?, document_sha256 = ?, document_size = ?, document_path = ?, status = 'pending_review', submitted_at = ? WHERE wallet = ?").run(safeEvidenceName(req.file.originalname), req.file.mimetype, digest, req.file.size, destination, Date.now(), wallet);
  res.status(201).json({ ok: true, identity: identityFor(wallet), document: { sha256: digest, size: req.file.size, status: "pending_review" } });
}));
app.get("/api/admin/creator-identities", adminAuthed, wrap(async (req, res) => {
  const status = String(req.query.status || "pending_review");
  if (!["unverified", "pending_review", "verified", "rejected"].includes(status)) throw new AppError("Invalid identity status", 422);
  const rows = db.prepare("SELECT wallet, status, provider, country, document_name AS documentName, document_mime AS documentMime, document_sha256 AS documentSha256, document_size AS documentSize, submitted_at AS submittedAt, reviewed_at AS reviewedAt, reviewed_by AS reviewedBy, rejection_reason AS rejectionReason FROM creator_identity WHERE status = ? ORDER BY submitted_at ASC LIMIT 100").all(status);
  res.json({ identities: rows });
}));
app.get("/api/admin/creator-identities/:wallet/document", adminAuthed, wrap(async (req, res) => {
  if (!ethers.isAddress(req.params.wallet)) throw new AppError("Bad wallet address", 422);
  const row = db.prepare("SELECT document_path AS documentPath, document_name AS documentName, document_mime AS documentMime FROM creator_identity WHERE wallet = ?").get(userKey(req.params.wallet));
  if (!row || !row.documentPath || !fs.existsSync(row.documentPath)) throw new AppError("Identity document not found", 404);
  res.type(row.documentMime).set("Content-Disposition", `attachment; filename="${safeEvidenceName(row.documentName)}"`).send(fs.readFileSync(row.documentPath));
}));
app.post("/api/admin/creator-identities/:wallet/review", adminAuthed, wrap(async (req, res) => {
  if (!ethers.isAddress(req.params.wallet)) throw new AppError("Bad wallet address", 422);
  const status = String(req.body?.status || "").toLowerCase(), reason = cleanText(req.body?.reason, 1000), wallet = userKey(req.params.wallet);
  if (!["verified", "rejected"].includes(status)) throw new AppError("Identity review status must be verified or rejected", 422);
  if (status === "rejected" && !reason) throw new AppError("A rejection reason is required", 422);
  if (!db.prepare("SELECT 1 FROM creator_identity WHERE wallet = ?").get(wallet)) throw new AppError("Identity case not found", 404);
  db.prepare("UPDATE creator_identity SET status = ?, reviewed_at = ?, reviewed_by = ?, rejection_reason = ? WHERE wallet = ?").run(status, Date.now(), userKey(req.user), reason, wallet);
  res.json({ ok: true, wallet, status, reason });
}));

// Hugging Face integration: import metadata only after verifying that the upstream
// repository declares a redistribution-compatible licence. Atlas never silently
// republishes weights whose licence is missing or unknown.
const normalizeHFRepo = (value) => {
  const raw = String(value || "").trim().replace(/^https?:\/\/huggingface\.co\//i, "").replace(/\?.*$/, "").replace(/\/$/, "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$/.test(raw)) throw new AppError("Use a Hugging Face repository such as org/model", 422);
  return raw;
};
const hfLicense = (info) => String(info?.cardData?.license || info?.license || (info?.tags || []).find((tag) => /^license:/i.test(tag))?.split(":")[1] || "").trim().toLowerCase();
const hfUrl = (repo) => `${HF_API_URL}/${repo.split("/").map(encodeURIComponent).join("/")}`;
const hfHeaders = () => ({ Accept: "application/json", ...(env.HF_API_TOKEN ? { Authorization: `Bearer ${env.HF_API_TOKEN}` } : {}) });
const hfRevision = (value) => /^[a-f0-9]{7,64}$/i.test(String(value || "")) ? String(value) : "main";
const hfWeightFile = (value) => {
  const name = String(value || "").trim();
  if (!name || name.length > 500 || name.includes("\\") || name.split("/").some((part) => !part || part === "." || part === "..")) return false;
  return /\.(safetensors|bin|gguf|onnx|tflite|pt|pth|ckpt|msgpack)$/i.test(name);
};
const hfModelInfo = async (repo) => {
  let response;
  try { response = await ufetch(hfUrl(repo), { dispatcher: agent, headers: hfHeaders(), signal: AbortSignal.timeout(12000) }); }
  catch (error) { throw new AppError(`Unable to inspect Hugging Face repository: ${error.message}`, 502); }
  if (!response.ok) throw new AppError(`Unable to inspect Hugging Face repository: HTTP ${response.status}`, 502);
  try { return await response.json(); } catch { throw new AppError("Hugging Face returned invalid repository metadata", 502); }
};
const hfFiles = (info) => (Array.isArray(info?.siblings) ? info.siblings : [])
  .map((file) => ({ name: String(file.rfilename || ""), size: Number.isFinite(Number(file.size)) ? Number(file.size) : null, sha256: file.lfs?.sha256 || file.sha256 || "" }))
  .filter((file) => hfWeightFile(file.name));
const hfResolveUrl = (repo, revision, file) => `https://huggingface.co/${repo}/resolve/${encodeURIComponent(hfRevision(revision))}/${file.split("/").map(encodeURIComponent).join("/")}?download=true`;

app.post("/api/huggingface/import", walletAuthed, perUser(10, 3600000), wrap(async (req, res) => {
  const repo = normalizeHFRepo(req.body?.repo);
  const info = await hfModelInfo(repo);
  const license = hfLicense(info);
  if (!license) throw new AppError("This repository does not declare a licence; ask the creator to provide proof before listing it", 422);
  if (!ALLOWED_HF_LICENSES.has(license)) throw new AppError(`Licence ${license} is not in Atlas's approved allowlist`, 422);
  const name = String(req.body?.name || info.modelId || repo).trim().slice(0, 80);
  const priceInr = inrPrice(req.body?.priceInr);
  const description = String(req.body?.description || info.cardData?.language?.join?.(", ") || `Imported from Hugging Face: ${repo}`).slice(0, 2000);
  const modelCard = normalizeModelCard(req.body?.modelCard || { purpose: `Imported Hugging Face model: ${repo}`, trainingData: "See the upstream Hugging Face model card", limitations: "Review the upstream model card before production use", intendedUsers: "Atlas buyers and MSMEs" });
  const tags = Array.from(new Set([...(Array.isArray(info.tags) ? info.tags.filter((tag) => typeof tag === "string" && !tag.startsWith("license:")) : []), ...(Array.isArray(req.body?.tags) ? req.body.tags : [])])).slice(0, 20);
  const revision = hfRevision(info.sha || "main");
  const commitment = crypto.createHash("sha256").update(`huggingface:${repo}:${revision}`).digest("hex");
  const manifest = JSON.stringify({
    name, description, version: "imported", creator: userKey(req.user), artifactHash: `0x${commitment}`,
    inputSchema: { type: "string" }, outputSchema: { type: "object" }, tags,
    license, licenseUrl: `https://huggingface.co/${repo}`, provenanceUrl: `https://huggingface.co/${repo}`, priceInr, modelCard, source: { type: "huggingface", repo, revision, pipelineTag: info.pipeline_tag || null },
    inference: { provider: "huggingface", gpuCapable: true }
  });
  const id = crypto.createHash("sha256").update(manifest).digest("hex");
  db.prepare("INSERT OR REPLACE INTO metadata VALUES(?,?,?,?)").run(id, userKey(req.user), manifest, Date.now());
  res.json({ metadataURI: `${PUBLIC_URL}/api/metadata/${id}`, id, contentHash: `0x${commitment}`, name, repo, license, licenseUrl: `https://huggingface.co/${repo}`, priceInr, revision, source: "huggingface" });
}));

const licensedHFModel = async (req) => {
  if (!isId(req.params.id)) throw new AppError("Bad model id", 422);
  const model = await getModel(req.params.id);
  if (modelIsTakedown(req.params.id)) throw new AppError("This model is unavailable while Atlas reviews a moderation case", 410);
  if (!model.active) throw new AppError("This model is delisted", 410);
  if (!(await hasAccess(req.params.id, req.user))) throw new AppError("License required", 403);
  const metadata = metadataFromURI(model.metadataURI), repo = metadata.source?.type === "huggingface" ? normalizeHFRepo(metadata.source.repo) : null;
  if (!repo) throw new AppError("This model does not have Hugging Face weights", 404);
  return { model, metadata, repo };
};

app.get("/api/huggingface/files/:id", authed, wrap(async (req, res) => {
  const { metadata, repo } = await licensedHFModel(req), info = await hfModelInfo(repo), files = hfFiles(info);
  if (!files.length) throw new AppError("No downloadable weight files were found in the Hugging Face repository", 404);
  res.json({ repo, revision: hfRevision(metadata.source.revision), files, note: "Atlas streams these upstream files after licence access is checked; it does not copy them into Atlas storage" });
}));

app.get("/api/huggingface/download/:id", authed, wrap(async (req, res) => {
  const { metadata, repo } = await licensedHFModel(req), requested = cleanText(req.query.file, 500);
  if (!hfWeightFile(requested)) throw new AppError("Choose a valid Hugging Face weight file", 422);
  const info = await hfModelInfo(repo), file = hfFiles(info).find((item) => item.name === requested);
  if (!file) throw new AppError("That weight file is not available in the imported repository", 404);
  let upstream;
  try {
    upstream = await ufetch(hfResolveUrl(repo, metadata.source.revision, file.name), {
      dispatcher: downloadAgent,
      redirect: "follow",
      headers: { Accept: "application/octet-stream", "Accept-Encoding": "identity", ...(env.HF_API_TOKEN ? { Authorization: `Bearer ${env.HF_API_TOKEN}` } : {}) },
      signal: AbortSignal.timeout(120000)
    });
  }
  catch (error) { throw new AppError(`Unable to download the upstream weight file: ${error.message}`, 502); }
  if (!upstream.ok || !upstream.body) {
    if ([401, 403].includes(upstream.status)) throw new AppError("Hugging Face rejected this file because the repository is gated or private; configure HF_API_TOKEN on the API server", 502);
    throw new AppError(`Hugging Face could not serve that file: HTTP ${upstream.status}`, 502);
  }
  const downloadName = safeEvidenceName(path.basename(file.name));
  res.status(200).set({ "Content-Type": upstream.headers.get("content-type") || "application/octet-stream", "Content-Disposition": `attachment; filename="${downloadName}"`, "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" });
  const length = upstream.headers.get("content-length"); if (length) res.set("Content-Length", length);
  const source = require("stream").Readable.fromWeb(upstream.body), abort = new AbortController();
  let finished = false;
  const cancel = () => { if (!finished) abort.abort(); };
  req.once("aborted", cancel);
  res.once("finish", () => { finished = true; });
  res.once("close", cancel);
  try {
    await pipeline(source, res, { signal: abort.signal });
  } catch (error) {
    if (!finished && !["ABORT_ERR", "ERR_STREAM_PREMATURE_CLOSE"].includes(error.code)) console.error(JSON.stringify({ level: "error", path: req.path, msg: `Hugging Face download stream failed: ${error.message}` }));
  } finally {
    finished = true;
    req.off("aborted", cancel);
    res.off("close", cancel);
  }
}));

// Download requires: valid session + artifact hash matches the on-chain model + on-chain license
app.get("/api/artifact/:hash", authed, wrap(async (req, res) => {
  const { hash } = req.params, id = req.query.model;
  if (!/^[0-9a-f]{64}$/.test(hash) || !isId(id)) throw new AppError("Bad request");
  const m = await getModel(id);
  if (modelIsTakedown(id)) throw new AppError("This model is unavailable while Atlas reviews a moderation case", 410);
  if (m.contentHash !== "0x" + hash) throw new AppError("Not found", 404);
  if (!(await hasAccess(id, req.user))) throw new AppError("License required", 403);
  const row = db.prepare("SELECT owner, name FROM artifacts WHERE hash = ?").get(hash);
  if (!row || row.owner !== userKey(m.creator)) throw new AppError("Not found", 404);
  res.set("X-Content-Type-Options", "nosniff").download(path.join(UPLOADS, hash), row.name);
}));

app.post("/api/endpoint/:id", walletAuthed, perUser(10), wrap(async (req, res) => {
  const m = await getModel(req.params.id);
  if (m.creator.toLowerCase() !== req.user.toLowerCase()) throw new AppError("Only the creator can set the endpoint", 403);
  const providerName = String(req.body?.provider || "creator").toLowerCase();
  if (providerName === "huggingface") {
    const metadata = metadataFromURI(m.metadataURI), repo = normalizeHFRepo(req.body?.repo || metadata.source?.repo);
    if (metadata.source?.type !== "huggingface" || metadata.source.repo !== repo) throw new AppError("The endpoint repository must match the imported model", 422);
    db.prepare("INSERT OR REPLACE INTO endpoints VALUES(?,?)").run(req.params.id, enc(JSON.stringify({ type: "huggingface", repo })));
    return res.json({ ok: true, provider: "huggingface", gpuCapable: true });
  }
  db.prepare("INSERT OR REPLACE INTO endpoints VALUES(?,?)").run(req.params.id, enc(JSON.stringify({ type: "creator", url: checkUrl(req.body?.url) })));
  res.json({ ok: true, provider: "creator" });
}));

app.post("/api/infer/:id", authed, perUser(20), wrap(async (req, res) => {
  const id = req.params.id, { input } = req.body;
  if (!isId(id) || typeof input !== "string" || !input || input.length > 10000) throw new AppError("Input must be 1 to 10,000 characters");
  const [m, licensed] = await Promise.all([getModel(id), hasAccess(id, req.user)]);
  if (!licensed) throw new AppError("Buy a license to run this model", 403);
  if (!m.active) throw new AppError("This model is delisted", 410);
  if (modelIsTakedown(id)) throw new AppError("This model is unavailable while Atlas reviews a moderation case", 410);
  const row = db.prepare("SELECT blob FROM endpoints WHERE model_id = ?").get(id);
  const metadata = metadataFromURI(m.metadataURI);
  let config = row ? null : (metadata.source?.type === "huggingface" ? { type: "huggingface", repo: metadata.source.repo } : null);
  if (row) {
    try { config = JSON.parse(dec(row.blob)); } catch { config = { type: "creator", url: dec(row.blob) }; }
  }
  if (!config) throw new AppError("The creator has not connected an endpoint yet", 409);
  let status = 502, data;
  try {
    const isHF = config.type === "huggingface";
    if (isHF && !env.HF_API_TOKEN) throw new AppError("Managed Hugging Face inference is not configured; set HF_API_TOKEN on the API server", 503);
    const target = isHF ? `${HF_INFERENCE_URL}/${normalizeHFRepo(config.repo).split("/").map(encodeURIComponent).join("/")}` : checkUrl(config.url);
    const headers = { "Content-Type": "application/json", Accept: "application/json" };
    if (isHF && env.HF_API_TOKEN) headers.Authorization = `Bearer ${env.HF_API_TOKEN}`;
    const body = isHF ? { inputs: input, options: { wait_for_model: true } } : { input };
    const r = await ufetch(target, { method: "POST", headers, body: JSON.stringify(body), dispatcher: agent, redirect: "error", signal: AbortSignal.timeout(30000) });
    status = r.status;
    const text = await r.text();
    try { data = JSON.parse(text); } catch { data = { output: text }; }
  } catch { throw new AppError("The model endpoint did not respond correctly", 502); }
  finally { db.prepare("INSERT INTO usage(model_id,user,ts,status) VALUES(?,?,?,?)").run(id, req.user, Date.now(), status); }
  res.json(data);
}));

app.get("/api/health", wrap(async (req, res) => { await provider.getBlockNumber(); res.json({ ok: true, service: BRAND, contract: address, chainId: CHAIN_ID, capabilities: { googleAuth: GOOGLE_OAUTH_ENABLED, emailVerification: EMAIL_VERIFICATION_REQUIRED, passwordReset: true, sessionCookies: true, huggingFaceImport: true, managedInference: Boolean(env.HF_API_TOKEN), inrQuote: INR_PER_ETH > 0, inrCheckout: INR_PAYMENTS_ENABLED, modelVerification: true, creatorAttestation: true, identityReview: true, licenseDocumentReview: true, provenanceCheck: true, malwareScan: Boolean(CLAMAV_HOST), malwareScanRequired: REQUIRE_MALWARE_SCAN, modelModeration: true, takedownProcess: true, adminRoles: true, automatedModeration: AUTOMATED_MODERATION_ENABLED, automatedLowRiskApproval: AUTO_APPROVE_MODEL_VERIFICATION, automatedReportTriage: AUTO_TRIAGE_REPORTS, humanModerationGates: true, basicModelScan: true } }); }));
app.use((e, req, res, next) => res.status(400).json({ error: "Bad request" }));

const startServer = () => app.listen(PORT, () => console.log(JSON.stringify({ level: "info", msg: "gateway up", port: PORT, prod: PROD })));
if (require.main === module) {
  const server = startServer();
  const stop = () => server.close(() => { db.close(); process.exit(0); });
  process.on("SIGTERM", stop); process.on("SIGINT", stop);
}

module.exports = { app, db, market, startServer };
