/**
 * Zero-Trust Read-Only SQL Firewall & Automatic PII Scrubber
 * Ensures AI coding assistants can NEVER mutate schemas/data or leak customer PII into IDE prompts.
 */

const FORBIDDEN_SQL_KEYWORDS = new Set([
  "INSERT",
  "UPDATE",
  "DELETE",
  "DROP",
  "ALTER",
  "TRUNCATE",
  "CREATE",
  "REPLACE",
  "MERGE",
  "UPSERT",
  "GRANT",
  "REVOKE",
  "COMMIT",
  "ROLLBACK",
  "SAVEPOINT",
  "COPY",
  "CALL",
  "EXEC",
  "EXECUTE",
  "PREPARE",
  "DEALLOCATE",
  "VACUUM",
  "REINDEX",
  "CLUSTER",
  "LOCK",
  "ATTACH",
  "DETACH",
  "LOAD_FILE",
  "PG_SLEEP",
  "SLEEP",
  "BENCHMARK"
]);

const SENSITIVE_COLUMN_PATTERNS = [
  /email/i,
  /e_mail/i,
  /phone/i,
  /mobile/i,
  /telefoon/i,
  /iban/i,
  /bic/i,
  /bank_account/i,
  /password/i,
  /passwd/i,
  /pwd/i,
  /secret/i,
  /api_key/i,
  /apikey/i,
  /access_token/i,
  /refresh_token/i,
  /private_key/i,
  /ssn/i,
  /bsn/i,
  /tax_id/i,
  /credit_card/i,
  /card_number/i,
  /cvv/i,
  /ip_address/i,
  /client_ip/i
];

const EMAIL_RE = /\b([a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
const IBAN_RE = /\b([A-Z]{2}\d{2})[\s-]?[A-Z0-9]{4}[\s-]?\d{4}[\s-]?\d{2,14}(\d{2})\b/g;
const JWT_RE = /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g;
const SECRET_KEY_RE = /\b(sk_live_|sk_test_|rk_live_|ghp_|gho_|xoxb-|xoxp-|AIza)[a-zA-Z0-9_-]{12,}\b/g;
const HASH_RE = /^\$(2[aby]|argon2id|argon2i|scrypt)\$[^\s]+$/;
const PHONE_RE = /(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{2,4}\b/g;

/**
 * Strips SQL comments and string literals so keyword scanning cannot be tricked by literals or comments.
 */
export function stripSqlLiteralsAndComments(sql) {
  return String(sql || "")
    .replace(/--[^\r\n]*/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/'(?:''|\\'|[^'])*'/g, "''")
    .replace(/"(?:""|\\"|[^"])*"/g, '""');
}

/**
 * Validates that a query is strictly a single Read-Only SELECT / WITH query.
 */
export function assertReadOnlySelect(sql) {
  const raw = String(sql || "").trim();
  if (!raw) {
    return { ok: false, reason: "Lege SQL-query ontvangen." };
  }

  const sanitized = stripSqlLiteralsAndComments(raw).trim();
  // Strip optional trailing semicolon, then reject any remaining semicolon (multi-statement injection)
  const withoutTrailingSemi = sanitized.replace(/;\s*$/, "").trim();
  if (!withoutTrailingSemi) {
    return { ok: false, reason: "Query bevat geen uitvoerbare SELECT-instructie." };
  }
  if (withoutTrailingSemi.includes(";")) {
    return {
      ok: false,
      reason: "Multi-statement SQL (meerdere ';' statements) is geblokkeerd door de Read-Only Firewall."
    };
  }

  const upper = withoutTrailingSemi.toUpperCase();
  if (!upper.startsWith("SELECT ") && !upper.startsWith("SELECT\n") && !upper.startsWith("SELECT\t") && !upper.startsWith("WITH ")) {
    return {
      ok: false,
      reason: "Alleen Read-Only SELECT / WITH CTE queries zijn toegestaan."
    };
  }

  if (/\bINTO\s+(OUTFILE|DUMPFILE)\b/i.test(withoutTrailingSemi)) {
    return { ok: false, reason: "SELECT INTO OUTFILE/DUMPFILE is geblokkeerd." };
  }
  if (/\bFOR\s+(UPDATE|SHARE|NO\s+KEY\s+UPDATE|KEY\s+SHARE)\b/i.test(withoutTrailingSemi)) {
    return { ok: false, reason: "Row-locking clausules (FOR UPDATE / FOR SHARE) zijn geblokkeerd in Read-Only modus." };
  }

  const tokens = upper.split(/[^A-Z0-9_]+/).filter(Boolean);
  for (const token of tokens) {
    if (FORBIDDEN_SQL_KEYWORDS.has(token)) {
      return {
        ok: false,
        reason: `Verboden mutatie- of systeemkeyword '${token}' gedetecteerd door Read-Only Firewall.`
      };
    }
  }

  return { ok: true, normalizedSql: raw.replace(/;\s*$/, "").trim() };
}

/**
 * Ensures a SELECT query has a bounded LIMIT <= maxRows.
 */
export function enforceRowLimit(sql, maxRows = 25) {
  const safeMax = Math.max(1, Math.min(50, Number(maxRows) || 25));
  const clean = String(sql || "").replace(/;\s*$/, "").trim();
  const limitMatch = clean.match(/\bLIMIT\s+(\d+)\s*(?:OFFSET\s+\d+)?\s*$/i);
  if (limitMatch) {
    const currentLimit = Number(limitMatch[1]);
    if (currentLimit <= safeMax) return clean;
    return clean.replace(/\bLIMIT\s+\d+(\s*(?:OFFSET\s+\d+)?\s*)$/i, `LIMIT ${safeMax}$1`);
  }
  return `${clean} LIMIT ${safeMax}`;
}

export function isSensitiveColumnName(columnName) {
  const name = String(columnName || "");
  return SENSITIVE_COLUMN_PATTERNS.some((rx) => rx.test(name));
}

export function maskStringValue(val, forceColumnMask = false) {
  if (val === null || val === undefined) return val;
  const s = String(val);
  if (!s) return s;

  if (HASH_RE.test(s)) return "[REDACTED_PASSWORD_HASH]";

  let masked = s
    .replace(JWT_RE, "[REDACTED_JWT]")
    .replace(SECRET_KEY_RE, "$1[REDACTED_SECRET]")
    .replace(EMAIL_RE, "$1***@$2")
    .replace(IBAN_RE, "$1 **** **** **$2");

  if (forceColumnMask) {
    if (masked !== s) return masked;
    if (s.length <= 4) return "****";
    return `${s.slice(0, 2)}***${s.slice(-2)} [PII_MASKED]`;
  }

  // Opportunistic phone redaction on strings that look predominantly like phone numbers
  if (/^\+?[\d\s().-]{9,18}$/.test(masked) && !/^\d{4}-\d{2}-\d{2}/.test(masked)) {
    masked = masked.replace(PHONE_RE, (m) => `${m.slice(0, 3)}******${m.slice(-2)}`);
  }

  return masked;
}

/**
 * Scrubs PII from an array of database result rows before returning them to an AI agent.
 */
export function maskResultRows(rows, customSensitiveColumns = []) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return { rows: [], redactedColumns: [], redactionCount: 0 };
  }
  const extraSet = new Set(customSensitiveColumns.map((c) => String(c).toLowerCase()));
  const redactedColumns = new Set();
  let redactionCount = 0;

  const scrubbed = rows.map((row) => {
    const out = {};
    for (const [col, val] of Object.entries(row)) {
      const colSensitive = isSensitiveColumnName(col) || extraSet.has(col.toLowerCase());
      if (typeof val === "string") {
        const nextVal = maskStringValue(val, colSensitive);
        if (nextVal !== val) {
          redactedColumns.add(col);
          redactionCount++;
        }
        out[col] = nextVal;
      } else if (colSensitive && val !== null && val !== undefined) {
        redactedColumns.add(col);
        redactionCount++;
        out[col] = "[PII_MASKED]";
      } else {
        out[col] = val;
      }
    }
    return out;
  });

  return {
    rows: scrubbed,
    redactedColumns: [...redactedColumns],
    redactionCount
  };
}
