import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

import { signLicenseKey, verifyLicenseKey, isLocalDsn } from "../src/license.mjs";
import { assertReadOnlySelect, maskResultRows } from "../src/security/sql-guard.mjs";
import { analyzeExecutionPlan } from "../src/analyzers/explain-analyzer.mjs";
import { lintMigrationSql } from "../src/analyzers/migration-linter.mjs";
import { SqlPulseMcpEngine } from "../src/mcp/mcp-server.mjs";
import { createSqlPulseWebServer } from "../web/server.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CLI_PATH = path.join(__dirname, "..", "bin", "sqlpulse.mjs");

// Fresh ephemeral Ed25519 test keypair (never ship private keys in source!)
const TEST_KEYS = crypto.generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" }
});

test("1. Read-Only SQL Firewall blocks mutations, multi-statement injections & locks", () => {
  assert.equal(assertReadOnlySelect("SELECT id, email FROM users WHERE id = 1;").ok, true);
  assert.equal(assertReadOnlySelect("WITH recent AS (SELECT * FROM orders) SELECT * FROM recent").ok, true);

  assert.equal(assertReadOnlySelect("DELETE FROM users WHERE id = 1").ok, false);
  assert.equal(assertReadOnlySelect("SELECT 1; DROP TABLE users;").ok, false);
  assert.equal(assertReadOnlySelect("SELECT * FROM users FOR UPDATE").ok, false);
  assert.equal(assertReadOnlySelect("SELECT pg_sleep(10)").ok, false);
  assert.equal(assertReadOnlySelect("UPDATE orders SET status = 'paid'").ok, false);
});

test("2. Auto-PII Scrubber masks emails, IBANs, JWTs, API keys & password hashes", () => {
  const sample = [
    {
      id: 7,
      email: "founder@startup.io",
      iban: "NL91ABNA0417164300",
      password_hash: "$2b$12$KIX9fG9uV7rM8yQ1zP3L4eW2xT5nB6vC8mN0pQ2rS4tU6vW8xY0zA",
      notes: "Bearer token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U and key sk_live_1234567890abcdef"
    }
  ];

  const scrubbed = maskResultRows(sample);
  assert.equal(scrubbed.rows[0].email, "f***@startup.io");
  assert.match(scrubbed.rows[0].iban, /^NL91 \*\*\*\* \*\*\*\* \*\*00$/);
  assert.equal(scrubbed.rows[0].password_hash, "[REDACTED_PASSWORD_HASH]");
  assert.match(scrubbed.rows[0].notes, /\[REDACTED_JWT\]/);
  assert.match(scrubbed.rows[0].notes, /sk_live_\[REDACTED_SECRET\]/);
  assert.ok(scrubbed.redactionCount >= 4);
});

test("3. Ed25519 Offline License Key signing, verification, tamper & expiry protection", () => {
  const community = verifyLicenseKey("");
  assert.equal(community.valid, true);
  assert.equal(community.isPaid, false);
  assert.equal(community.caps.tier, "community");
  assert.equal(community.caps.maxProfiles, 1);

  const signed = signLicenseKey(
    { tier: "pro_yearly", email: "dev@cursor-user.io", stripeSessionId: "cs_test_999" },
    TEST_KEYS.privateKey
  );
  const verified = verifyLicenseKey(signed.licenseKey, { publicKeyPem: TEST_KEYS.publicKey });
  assert.equal(verified.valid, true);
  assert.equal(verified.isPaid, true);
  assert.equal(verified.caps.tier, "pro_yearly");
  assert.equal(verified.caps.maxProfiles, 5);
  assert.equal(verified.caps.features.schemaDiff, true);

  // Tamper test
  const tampered = signed.licenseKey.slice(0, -4) + "AAAA";
  const badVerify = verifyLicenseKey(tampered, { publicKeyPem: TEST_KEYS.publicKey });
  assert.equal(badVerify.valid, false);
  assert.equal(badVerify.caps.tier, "community");

  // Expiry test
  const expiredSigned = signLicenseKey(
    {
      tier: "pro_quarterly",
      email: "expired@dev.io",
      expiresAt: "2025-01-01T00:00:00.000Z"
    },
    TEST_KEYS.privateKey
  );
  const expVerify = verifyLicenseKey(expiredSigned.licenseKey, {
    publicKeyPem: TEST_KEYS.publicKey,
    now: new Date("2026-11-21T00:00:00.000Z")
  });
  assert.equal(expVerify.valid, false);
  assert.equal(expVerify.status, "expired");

  // Remote DSN local check
  assert.equal(isLocalDsn("postgresql://u:p@localhost:5432/db"), true);
  assert.equal(isLocalDsn("postgresql://u:p@ep-cool-cloud.eu-central-1.aws.neon.tech:5432/db"), false);
});

test("4. Deterministic EXPLAIN Analyzer synthesizes ESR CONCURRENTLY DDL for Postgres & MySQL", () => {
  const pgPlan = [
    {
      Plan: {
        "Node Type": "Sort",
        "Sort Key": ["created_at DESC"],
        "Sort Space Type": "Disk",
        "Total Cost": 980.4,
        Plans: [
          {
            "Node Type": "Seq Scan",
            "Relation Name": "orders",
            "Plan Rows": 25000,
            "Actual Rows": 24800,
            "Total Cost": 620.0,
            Filter: "((tenant_id = 9) AND (status = 'paid'))"
          }
        ]
      }
    }
  ];

  const pgAnalysis = analyzeExecutionPlan({
    dialect: "postgres",
    sql: "SELECT id, amount FROM orders WHERE tenant_id = 9 AND status = 'paid' AND total_cents > 1000 ORDER BY created_at DESC LIMIT 20",
    rawPlan: pgPlan,
    includeProDdl: true
  });

  assert.equal(pgAnalysis.status, "NEEDS_INDEX_OPTIMIZATION");
  assert.ok(pgAnalysis.bottlenecks.some((b) => b.code === "PG_SEQ_SCAN"));
  assert.ok(pgAnalysis.bottlenecks.some((b) => b.code === "PG_EXPENSIVE_SORT"));
  assert.equal(pgAnalysis.recommendedIndexes.length, 1);
  assert.match(
    pgAnalysis.recommendedIndexes[0].ddl,
    /^CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_orders_tenant_id_status_created_at_total_cents" ON "orders" \("tenant_id", "status", "created_at" DESC, "total_cents"\);$/
  );

  const mysqlPlan = {
    query_block: {
      ordering_operation: {
        using_filesort: true,
        table: {
          table_name: "subscriptions",
          access_type: "ALL",
          rows_examined_per_scan: 14000
        }
      }
    }
  };
  const myAnalysis = analyzeExecutionPlan({
    dialect: "mysql",
    sql: "SELECT id FROM subscriptions WHERE customer_id = 55 ORDER BY renews_at ASC",
    rawPlan: mysqlPlan,
    includeProDdl: true
  });
  assert.equal(myAnalysis.status, "NEEDS_INDEX_OPTIMIZATION");
  assert.match(myAnalysis.recommendedIndexes[0].ddl, /ALGORITHM=INPLACE, LOCK=NONE/);
});

test("5. Pre-Flight Migration Lock Linter catches Postgres lock hazards & unindexed FKs", () => {
  const riskySql = `
    BEGIN;
    CREATE INDEX idx_users_org ON users (organization_id);
    ALTER TABLE users ADD COLUMN country_code VARCHAR(2) NOT NULL;
    ALTER TABLE invoices ADD CONSTRAINT fk_inv_org FOREIGN KEY (org_id) REFERENCES organizations(id);
    DROP COLUMN legacy_token;
    COMMIT;
  `;
  const report = lintMigrationSql(riskySql, { dialect: "postgres" });
  assert.equal(report.safeToDeploy, false);
  const ruleIds = new Set(report.issues.map((i) => i.ruleId));
  assert.ok(ruleIds.has("LOCK_001"));
  assert.ok(ruleIds.has("LOCK_003"));
  assert.ok(ruleIds.has("LOCK_005"));
  assert.ok(ruleIds.has("DESTRUCT_001"));
  assert.ok(ruleIds.has("PERF_001"));
});

test("6. Live Multi-Profile Schema Audit & Pro Schema Drift Diff", async () => {
  const dbLocal = new DatabaseSync(":memory:");
  dbLocal.exec(`
    CREATE TABLE teams (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
    CREATE TABLE projects (
      id INTEGER PRIMARY KEY,
      team_id INTEGER NOT NULL REFERENCES teams(id),
      slug TEXT NOT NULL,
      region TEXT NOT NULL DEFAULT 'eu'
    );
    CREATE INDEX idx_projects_team ON projects(team_id);
  `);

  const dbStaging = new DatabaseSync(":memory:");
  dbStaging.exec(`
    CREATE TABLE teams (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
    CREATE TABLE projects (
      id INTEGER PRIMARY KEY,
      team_id INTEGER NOT NULL REFERENCES teams(id),
      slug TEXT NOT NULL
    );
  `);

  const sqliteMap = new Map([
    ["sqlite://local", dbLocal],
    ["sqlite://staging", dbStaging]
  ]);

  // Community blocks diff_schemas and caps profiles at 1
  const commEngine = new SqlPulseMcpEngine({
    profiles: { local: "sqlite://local", staging: "sqlite://staging" },
    sqliteInstances: sqliteMap
  });
  await assert.rejects(() => commEngine.callTool("diff_schemas", { sourceProfile: "local", targetProfile: "staging" }), /SQLPulse Pro/);

  // Pro unlocks 5 profiles + diff_schemas + exact FK DDL
  process.env.SQLPULSE_PUBLIC_KEY_PEM = TEST_KEYS.publicKey;
  const proKey = signLicenseKey({ tier: "pro_yearly", email: "pro@team.dev" }, TEST_KEYS.privateKey).licenseKey;

  const proEngine = new SqlPulseMcpEngine({
    profiles: { local: "sqlite://local", staging: "sqlite://staging" },
    licenseKey: proKey,
    sqliteInstances: sqliteMap
  });

  const stagingAudit = await proEngine.callTool("audit_schema_health", { profile: "staging" });
  assert.ok(stagingAudit.findings.some((f) => f.ruleId === "FK_MISSING_INDEX" && f.table === "projects"));

  const drift = await proEngine.callTool("diff_schemas", { sourceProfile: "local", targetProfile: "staging" });
  assert.equal(drift.inSync, false);
  assert.ok(drift.columnDiffs.some((d) => d.column === "region" && d.change === "missing_in_target"));
  assert.ok(drift.indexDiffs.some((d) => d.index === "idx_projects_team"));

  dbLocal.close();
  dbStaging.close();
  delete process.env.SQLPULSE_PUBLIC_KEY_PEM;
});

test("7. Real MCP stdio JSON-RPC 2.0 subprocess handshake & tool execution", async () => {
  const child = spawn(process.execPath, [CLI_PATH, "mcp", "--dsn", ":memory:"], {
    stdio: ["pipe", "pipe", "pipe"]
  });

  const sendRpc = (msg) =>
    new Promise((resolve, reject) => {
      const onData = (buf) => {
        const lines = buf.toString("utf8").trim().split("\n");
        for (const line of lines) {
          if (!line.trim()) continue;
          const parsed = JSON.parse(line);
          if (parsed.id === msg.id) {
            child.stdout.off("data", onData);
            resolve(parsed);
          }
        }
      };
      child.stdout.on("data", onData);
      child.once("error", reject);
      child.stdin.write(JSON.stringify(msg) + "\n");
    });

  try {
    const initRes = await sendRpc({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test-ide", version: "1.0" } }
    });
    assert.equal(initRes.result.serverInfo.name, "sqlpulse-mcp");

    const toolsRes = await sendRpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    assert.equal(toolsRes.result.tools.length, 6);

    const lintRes = await sendRpc({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "lint_migration_sql",
        arguments: { migrationSql: "CREATE INDEX idx_test ON orders (user_id);", dialect: "postgres" }
      }
    });
    const payload = JSON.parse(lintRes.result.content[0].text);
    assert.equal(payload.safeToDeploy, false);
    assert.equal(payload.issues[0].ruleId, "LOCK_001");
  } finally {
    child.kill();
  }
});

test("8. Storefront Server, Live Sandbox & Stripe via Grok Bot Webhook License Fulfillment", async () => {
  const webhookSecret = "whsec_test_superos_v003";
  const server = createSqlPulseWebServer({
    ledgerPath: ":memory:",
    env: {
      STRIPE_WEBHOOK_SECRET: webhookSecret,
      SQLPULSE_SIGNING_PRIVATE_KEY_PEM: TEST_KEYS.privateKey
    }
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Landing page renders
    const homeRes = await fetch(baseUrl);
    assert.equal(homeRes.status, 200);
    const html = await homeRes.text();
    assert.match(html, /SQLPulse MCP/);

    // 2. Live Sandbox EXPLAIN works
    const demoRes = await fetch(`${baseUrl}/api/demo/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: "explain",
        sql: "SELECT id, total_cents FROM orders WHERE organization_id = 2 ORDER BY created_at DESC"
      })
    });
    const demoJson = await demoRes.json();
    assert.equal(demoJson.ok, true);
    assert.equal(demoJson.result.status, "NEEDS_INDEX_OPTIMIZATION");
    assert.ok(demoJson.result.recommendedIndexes.length >= 1);

    // 3. Stripe Webhook HMAC verification + automatic Ed25519 license minting
    const eventPayload = JSON.stringify({
      id: "evt_001",
      type: "checkout.session.completed",
      data: {
        object: {
          id: "cs_live_grokbot_777",
          customer_details: { email: "buyer@indiehacker.nl" },
          metadata: { tier: "pro_yearly" }
        }
      }
    });
    const ts = Math.floor(Date.now() / 1000);
    const hmac = crypto
      .createHmac("sha256", webhookSecret)
      .update(`${ts}.${eventPayload}`, "utf8")
      .digest("hex");

    const whRes = await fetch(`${baseUrl}/api/webhooks/stripe`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Stripe-Signature": `t=${ts},v1=${hmac}`
      },
      body: eventPayload
    });
    const whJson = await whRes.json();
    assert.equal(whJson.ok, true);
    assert.equal(whJson.handled, true);
    assert.match(whJson.record.license_key, /^SQLP1\./);

    // 4. Instant retrieval by session_id & offline cryptographic verification
    const lookupRes = await fetch(`${baseUrl}/api/license/by-session?session_id=cs_live_grokbot_777`);
    const lookupJson = await lookupRes.json();
    assert.equal(lookupJson.ok, true);
    const verified = verifyLicenseKey(lookupJson.licenseKey, { publicKeyPem: TEST_KEYS.publicKey });
    assert.equal(verified.valid, true);
    assert.equal(verified.caps.tier, "pro_yearly");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
