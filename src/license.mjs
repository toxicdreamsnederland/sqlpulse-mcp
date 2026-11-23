import crypto from "node:crypto";
import os from "node:os";

/**
 * Embedded Ed25519 public key for offline cryptographic verification of SQLPulse Pro/Team licenses.
 * Private signing key lives strictly on the Stripe-via-Grok-Bot fulfillment server (env SQLPULSE_SIGNING_PRIVATE_KEY_PEM).
 */
export const DEFAULT_PUBLIC_KEY_PEM =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAP6XzEIzUwg5wiEvZvYMY2MMCUSEhv2oozypfBO8XR4s=\n-----END PUBLIC KEY-----\n";

/**
 * Strictly bounded tier definitions (Zero false promises; deterministic hard caps per plan).
 */
export const TIER_CAPS = Object.freeze({
  community: Object.freeze({
    tier: "community",
    label: "Community (Free Open-Core)",
    priceLabel: "€0",
    maxProfiles: 1,
    allowRemoteDsn: false,
    maxTablesPerScan: 40,
    maxSampleRows: 20,
    maxSeats: 1,
    ciRunsPerYear: 25,
    features: Object.freeze({
      schemaXray: true,
      basicExplain: true,
      piiMasking: true,
      migrationLint: true,
      indexAdvisorDdl: false,
      schemaDiff: false,
      teamPolicy: false
    })
  }),
  pro_quarterly: Object.freeze({
    tier: "pro_quarterly",
    label: "SQLPulse Pro (Kwartaal)",
    priceEur: 19,
    billingInterval: "quarter",
    durationDays: 93,
    priceLabel: "€19 / kwartaal",
    maxProfiles: 5,
    allowRemoteDsn: true,
    maxTablesPerScan: 500,
    maxSampleRows: 50,
    maxSeats: 3,
    ciRunsPerYear: 500,
    features: Object.freeze({
      schemaXray: true,
      basicExplain: true,
      piiMasking: true,
      migrationLint: true,
      indexAdvisorDdl: true,
      schemaDiff: true,
      teamPolicy: false
    })
  }),
  pro_yearly: Object.freeze({
    tier: "pro_yearly",
    label: "SQLPulse Pro (Jaar)",
    priceEur: 49,
    billingInterval: "year",
    durationDays: 366,
    priceLabel: "€49 / jaar",
    maxProfiles: 5,
    allowRemoteDsn: true,
    maxTablesPerScan: 500,
    maxSampleRows: 50,
    maxSeats: 3,
    ciRunsPerYear: 1000,
    features: Object.freeze({
      schemaXray: true,
      basicExplain: true,
      piiMasking: true,
      migrationLint: true,
      indexAdvisorDdl: true,
      schemaDiff: true,
      teamPolicy: false
    })
  }),
  team_yearly: Object.freeze({
    tier: "team_yearly",
    label: "SQLPulse Team Pack (Jaar)",
    priceEur: 149,
    billingInterval: "year",
    durationDays: 366,
    priceLabel: "€149 / jaar",
    maxProfiles: 20,
    allowRemoteDsn: true,
    maxTablesPerScan: 1500,
    maxSampleRows: 50,
    maxSeats: 15,
    ciRunsPerYear: 5000,
    features: Object.freeze({
      schemaXray: true,
      basicExplain: true,
      piiMasking: true,
      migrationLint: true,
      indexAdvisorDdl: true,
      schemaDiff: true,
      teamPolicy: true
    })
  })
});

export function getMachineSeatHash() {
  const raw = `${os.hostname()}|${os.platform()}|${os.arch()}|${os.userInfo().username}`;
  return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

/**
 * Signs a new SQLPulse license key (Server-side Stripe via Grok Bot webhook only).
 * Format: SQLP1.<payload_base64url>.<ed25519_sig_base64url>
 */
export function signLicenseKey(payload, privateKeyPem = process.env.SQLPULSE_SIGNING_PRIVATE_KEY_PEM) {
  if (!privateKeyPem) {
    throw new Error("Missing SQLPULSE_SIGNING_PRIVATE_KEY_PEM for license signing.");
  }
  const tierKey = payload.tier;
  if (!TIER_CAPS[tierKey] || tierKey === "community") {
    throw new Error(`Invalid paid license tier '${tierKey}'.`);
  }
  const now = new Date();
  const durationDays = payload.durationDays ?? TIER_CAPS[tierKey].durationDays;
  const expiresAt =
    payload.expiresAt || new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000).toISOString();

  const canonicalPayload = {
    v: 1,
    id: payload.id || `lic_${crypto.randomBytes(8).toString("hex")}`,
    tier: tierKey,
    email: String(payload.email || "").trim().toLowerCase(),
    seats: TIER_CAPS[tierKey].maxSeats,
    maxProfiles: TIER_CAPS[tierKey].maxProfiles,
    maxTables: TIER_CAPS[tierKey].maxTablesPerScan,
    issuedAt: payload.issuedAt || now.toISOString(),
    expiresAt,
    stripeSessionId: payload.stripeSessionId || null
  };

  const encodedPayload = Buffer.from(JSON.stringify(canonicalPayload), "utf8").toString("base64url");
  const signature = crypto.sign(null, Buffer.from(encodedPayload, "utf8"), privateKeyPem).toString("base64url");

  return {
    licenseKey: `SQLP1.${encodedPayload}.${signature}`,
    claims: canonicalPayload,
    caps: TIER_CAPS[tierKey]
  };
}

/**
 * Verifies a license key 100% offline in <1ms using Ed25519 public key cryptography.
 */
export function verifyLicenseKey(
  rawKey = process.env.SQLPULSE_LICENSE_KEY,
  { publicKeyPem = process.env.SQLPULSE_PUBLIC_KEY_PEM || DEFAULT_PUBLIC_KEY_PEM, now = new Date() } = {}
) {
  if (!rawKey || !String(rawKey).trim()) {
    return {
      valid: true,
      isPaid: false,
      status: "community_default",
      caps: TIER_CAPS.community,
      claims: null,
      machineSeat: getMachineSeatHash()
    };
  }

  const trimmed = String(rawKey).trim();
  const parts = trimmed.split(".");
  if (parts.length !== 3 || parts[0] !== "SQLP1") {
    return {
      valid: false,
      isPaid: false,
      status: "malformed_key",
      error: "Ongeldig licentieformaat. Verwacht 'SQLP1.<payload>.<signature>'. Teruggevallen op Community-caps.",
      caps: TIER_CAPS.community,
      claims: null
    };
  }

  const [, encodedPayload, encodedSig] = parts;
  try {
    const sigBuffer = Buffer.from(encodedSig, "base64url");
    const isVerified = crypto.verify(null, Buffer.from(encodedPayload, "utf8"), publicKeyPem, sigBuffer);
    if (!isVerified) {
      return {
        valid: false,
        isPaid: false,
        status: "invalid_signature",
        error: "Cryptografische Ed25519 handtekening ongeldig. Teruggevallen op Community-caps.",
        caps: TIER_CAPS.community,
        claims: null
      };
    }

    const claims = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
    const caps = TIER_CAPS[claims.tier];
    if (!caps || claims.tier === "community") {
      return {
        valid: false,
        isPaid: false,
        status: "unknown_tier",
        error: `Onbekende tier '${claims.tier}' in licentie.`,
        caps: TIER_CAPS.community,
        claims
      };
    }

    const expTime = Date.parse(claims.expiresAt);
    if (!Number.isFinite(expTime) || expTime < now.getTime()) {
      return {
        valid: false,
        isPaid: false,
        status: "expired",
        error: `Licentie is verlopen op ${claims.expiresAt}. Verleng via Stripe checkout om Pro-caps te hervatten.`,
        caps: TIER_CAPS.community,
        claims
      };
    }

    return {
      valid: true,
      isPaid: true,
      status: "active",
      caps,
      claims,
      machineSeat: getMachineSeatHash()
    };
  } catch (err) {
    return {
      valid: false,
      isPaid: false,
      status: "parse_error",
      error: `Kon licentiesleutel niet verifiëren: ${err.message}`,
      caps: TIER_CAPS.community,
      claims: null
    };
  }
}

/**
 * Checks if a database DSN points to a local machine (allowed in Community) or remote host (requires Pro/Team).
 */
export function isLocalDsn(dsn) {
  const s = String(dsn || "").trim();
  if (!s) return true;
  if (
    s === ":memory:" ||
    s.startsWith("sqlite:") ||
    s.startsWith("file:") ||
    s.endsWith(".db") ||
    s.endsWith(".sqlite") ||
    s.endsWith(".sqlite3")
  ) {
    return true;
  }
  try {
    const parsed = new URL(s);
    const host = (parsed.hostname || "").toLowerCase();
    return (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "::1" ||
      host === "[::1]" ||
      host === "host.docker.internal" ||
      host.endsWith(".local")
    );
  } catch {
    return false;
  }
}
