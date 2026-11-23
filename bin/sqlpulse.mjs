#!/usr/bin/env node
import fs from "node:fs";
import { verifyLicenseKey } from "../src/license.mjs";
import { SqlPulseMcpEngine, startStdioMcpServer } from "../src/mcp/mcp-server.mjs";
import { lintMigrationSql } from "../src/analyzers/migration-linter.mjs";

function parseCliArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        out[key] = next;
        i++;
      } else {
        out[key] = true;
      }
    } else {
      out._.push(arg);
    }
  }
  return out;
}

function buildIdeConfigSnippet(dsn, licenseKey) {
  const envObj = {
    SQLPULSE_DSN: dsn || "postgresql://readonly_user:password@localhost:5432/app_db"
  };
  if (licenseKey) {
    envObj.SQLPULSE_LICENSE_KEY = licenseKey;
  }
  return {
    mcpServers: {
      sqlpulse: {
        command: "npx",
        args: ["-y", "github:toxicdreamsnederland/sqlpulse-mcp", "mcp"],
        env: envObj
      }
    }
  };
}

async function main() {
  const args = parseCliArgs(process.argv.slice(2));
  const sub = args._[0] || "mcp";

  if (sub === "mcp") {
    const profiles = args.dsn ? { default: args.dsn } : undefined;
    startStdioMcpServer({ profiles, licenseKey: args["license-key"] || process.env.SQLPULSE_LICENSE_KEY });
    return;
  }

  if (sub === "init-ide") {
    const snippet = buildIdeConfigSnippet(args.dsn, args["license-key"]);
    console.log(JSON.stringify(snippet, null, 2));
    return;
  }

  if (sub === "license-status") {
    const info = verifyLicenseKey(args["license-key"] || process.env.SQLPULSE_LICENSE_KEY);
    console.log(JSON.stringify(info, null, 2));
    process.exit(info.valid ? 0 : 1);
  }

  if (sub === "audit") {
    const dsn = args.dsn || process.env.SQLPULSE_DSN || process.env.DATABASE_URL;
    if (!dsn) {
      console.error("Geef --dsn <postgres://...|mysql://...|sqlite://...> of stel SQLPULSE_DSN in.");
      process.exit(1);
    }
    const engine = new SqlPulseMcpEngine({
      profiles: { default: dsn },
      licenseKey: args["license-key"] || process.env.SQLPULSE_LICENSE_KEY
    });
    const res = await engine.callTool("audit_schema_health", { profile: "default" });
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  if (sub === "explain") {
    const dsn = args.dsn || process.env.SQLPULSE_DSN || process.env.DATABASE_URL;
    if (!dsn || !args.sql) {
      console.error('Gebruik: sqlpulse explain --dsn <dsn> --sql "SELECT ..."');
      process.exit(1);
    }
    const engine = new SqlPulseMcpEngine({
      profiles: { default: dsn },
      licenseKey: args["license-key"] || process.env.SQLPULSE_LICENSE_KEY
    });
    const res = await engine.callTool("explain_query", { profile: "default", sql: args.sql });
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  if (sub === "lint-migration") {
    const filePath = args._[1] || args.file;
    if (!filePath || !fs.existsSync(filePath)) {
      console.error("Gebruik: sqlpulse lint-migration <pad-naar-migratie.sql> [--dialect postgres|mysql|sqlite]");
      process.exit(1);
    }
    const sql = fs.readFileSync(filePath, "utf8");
    const report = lintMigrationSql(sql, { dialect: args.dialect || "postgres" });
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.safeToDeploy ? 0 : 2);
  }

  console.log(`SQLPulse MCP v1.0.0 — Zero-LLM SQL Schema & Query Performance MCP Server

Commando's:
  sqlpulse mcp [--dsn <dsn>]                     Start MCP stdio server voor Cursor, Windsurf & Antigravity
  sqlpulse init-ide [--dsn <dsn>]                Genereer .cursor/mcp.json / mcp_config.json snippet
  sqlpulse audit --dsn <dsn>                     Voer volledige DBA schema & index audit uit
  sqlpulse explain --dsn <dsn> --sql "SELECT.."  Analyseer query uitvoeringsplan & ESR index advies
  sqlpulse lint-migration <migration.sql>        CI/CD pre-flight controle op tabel-locks & dataverlies
  sqlpulse license-status                        Controleer actieve licentie & harde tier-caps
`);
}

main().catch((err) => {
  console.error(JSON.stringify({ ok: false, error: err.message }));
  process.exit(1);
});
