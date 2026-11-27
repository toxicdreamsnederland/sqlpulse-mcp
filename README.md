# SQLPulse MCP — Zero-LLM SQL Schema & Query Performance MCP Server

[![Website](https://img.shields.io/badge/Website-sqlpulse.dynonode.com-10b981)](https://sqlpulse.dynonode.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-059669.svg)](./LICENSE)

**SQLPulse MCP** gives AI coding agents (**Cursor**, **Windsurf**, **Claude Code**, **Antigravity**) deterministic, read-only database visibility without hallucinated indexes, table-locking migrations, or raw PII leaks.

- **Read-Only SQL Guard:** Blocks `DROP`, `DELETE`, `UPDATE`, `ALTER`, `TRUNCATE`, and multi-statement injections before they touch your database.
- **Auto-PII Masking:** Automatically redacts emails, IBANs, phone numbers, JWTs, and API keys before returning rows to the LLM context.
- **Deterministic `EXPLAIN` Index Advisor:** Parses PostgreSQL, MySQL 8+, and SQLite execution plans using the Equality–Sort–Range (ESR) rule.
- **Pre-Flight Migration Lock Linter:** Catches table-locking `ALTER TABLE` statements in CI/CD before production deploy.

## Quickstart (Zero Install via `npx`)

Add to `.cursor/mcp.json`, `claude_desktop_config.json`, or Windsurf `mcp_config.json`:

```json
{
  "mcpServers": {
    "sqlpulse": {
      "command": "npx",
      "args": ["-y", "github:toxicdreamsnederland/sqlpulse-mcp", "mcp"],
      "env": {
        "SQLPULSE_DSN": "postgresql://readonly_user:password@localhost:5432/app_db"
      }
    }
  }
}
```

Or run CLI commands directly:

```bash
npx -y github:toxicdreamsnederland/sqlpulse-mcp init-ide
npx -y github:toxicdreamsnederland/sqlpulse-mcp lint-migration ./migrations/001_add_index.sql
```

## Community (Free) vs. Pro Offline Ed25519 License

- **Community (Free, €0):** Localhost / Docker / SQLite DSNs, up to 40 tables/scan, full read-only guard, PII masking & migration linter.
- **SQLPulse Pro (€19/quarter or €49/year):** Remote staging/read-replica DSNs, up to 5 DB profiles & 500 tables/scan, `CREATE INDEX CONCURRENTLY` DDL advisor, and staging-vs-prod schema drift diffs. Verified 100% offline via Ed25519 public-key cryptography.

👉 **Docs & Instant Pro License:** [https://sqlpulse.dynonode.com](https://sqlpulse.dynonode.com)
