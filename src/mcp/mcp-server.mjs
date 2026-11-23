import readline from "node:readline";
import { verifyLicenseKey } from "../license.mjs";
import { DatabaseProfileManager } from "../adapters/db-manager.mjs";
import { auditSchemaSnapshot, diffSchemas } from "../analyzers/schema-auditor.mjs";
import { analyzeExecutionPlan } from "../analyzers/explain-analyzer.mjs";
import { lintMigrationSql } from "../analyzers/migration-linter.mjs";

export const MCP_TOOLS = [
  {
    name: "inspect_schema",
    description:
      "Inspect PostgreSQL, MySQL or SQLite tables, columns, primary keys, foreign keys and indexes in compact token-efficient JSON.",
    inputSchema: {
      type: "object",
      properties: {
        profile: { type: "string", description: "Database profile name (default: 'default')." },
        tableFilter: { type: "string", description: "Optional substring to filter table names." }
      }
    }
  },
  {
    name: "audit_schema_health",
    description:
      "Detect unindexed foreign keys, missing primary keys, shadowed indexes, wide SELECT * hazards and PII columns with ready-to-run DDL.",
    inputSchema: {
      type: "object",
      properties: {
        profile: { type: "string", description: "Database profile name (default: 'default')." }
      }
    }
  },
  {
    name: "explain_query",
    description:
      "Run read-only EXPLAIN on a SELECT query, pinpoint Seq Scans / sorts / loop bottlenecks, and synthesize ESR composite index DDL.",
    inputSchema: {
      type: "object",
      required: ["sql"],
      properties: {
        sql: { type: "string", description: "Read-only SELECT or WITH query to analyze." },
        profile: { type: "string", description: "Database profile name (default: 'default')." }
      }
    }
  },
  {
    name: "lint_migration_sql",
    description:
      "Pre-flight audit SQL migration DDL (Prisma/Drizzle/Supabase/raw) for table locks, non-concurrent indexes, unindexed FKs & data loss.",
    inputSchema: {
      type: "object",
      required: ["migrationSql"],
      properties: {
        migrationSql: { type: "string", description: "SQL DDL statements from migration file." },
        dialect: {
          type: "string",
          enum: ["postgres", "mysql", "sqlite"],
          description: "Target SQL dialect (default: 'postgres')."
        }
      }
    }
  },
  {
    name: "diff_schemas",
    description:
      "[Pro/Team] Compare two database profiles (e.g. 'local' vs 'staging') for missing tables, column type mismatches and missing indexes.",
    inputSchema: {
      type: "object",
      required: ["sourceProfile", "targetProfile"],
      properties: {
        sourceProfile: { type: "string", description: "Reference profile (e.g. 'local')." },
        targetProfile: { type: "string", description: "Comparison profile (e.g. 'staging')." }
      }
    }
  },
  {
    name: "safe_sample_query",
    description:
      "Execute a strictly read-only SELECT query with row caps and automatic PII masking (emails, IBANs, tokens, phone numbers, hashes).",
    inputSchema: {
      type: "object",
      required: ["sql"],
      properties: {
        sql: { type: "string", description: "Read-only SELECT query." },
        limit: { type: "integer", description: "Max rows to return (capped by active tier)." },
        profile: { type: "string", description: "Database profile name (default: 'default')." }
      }
    }
  }
];

export function loadProfilesFromEnv(env = process.env) {
  const profiles = {};
  if (env.SQLPULSE_PROFILES_JSON) {
    try {
      const parsed = JSON.parse(env.SQLPULSE_PROFILES_JSON);
      Object.assign(profiles, parsed);
    } catch {
      // ignore invalid JSON fallback to single DSN
    }
  }
  if (env.SQLPULSE_DSN && !profiles.default) {
    profiles.default = env.SQLPULSE_DSN;
  }
  if (env.DATABASE_URL && Object.keys(profiles).length === 0) {
    profiles.default = env.DATABASE_URL;
  }
  // Support SQLPULSE_DSN_<NAME> env vars (e.g. SQLPULSE_DSN_STAGING)
  for (const [key, val] of Object.entries(env)) {
    if (key.startsWith("SQLPULSE_DSN_") && val) {
      const name = key.slice("SQLPULSE_DSN_".length).toLowerCase();
      profiles[name] = val;
    }
  }
  return profiles;
}

export class SqlPulseMcpEngine {
  constructor({ profiles, licenseKey = process.env.SQLPULSE_LICENSE_KEY, sqliteInstances } = {}) {
    this.licenseInfo = verifyLicenseKey(licenseKey);
    const effectiveProfiles = profiles || loadProfilesFromEnv();
    this.dbManager = new DatabaseProfileManager({
      profiles: effectiveProfiles,
      licenseInfo: this.licenseInfo,
      sqliteInstances
    });
  }

  async callTool(name, args = {}) {
    const caps = this.licenseInfo.caps;
    const includeProDdl = Boolean(caps.features.indexAdvisorDdl);

    switch (name) {
      case "inspect_schema": {
        const snap = await this.dbManager.inspectSchema(args.profile || "default");
        const filter = args.tableFilter ? String(args.tableFilter).toLowerCase() : null;
        const tables = filter
          ? snap.tables.filter((t) => t.name.toLowerCase().includes(filter))
          : snap.tables;

        return {
          tier: caps.tier,
          dialect: snap.dialect,
          totalTablesFound: snap.totalTablesFound,
          truncatedByCap: snap.truncatedByCap,
          tables: tables.map((t) => ({
            name: t.name,
            estRows: t.estimatedRows,
            columns: t.columns.map((c) => `${c.name}:${c.type}${c.isPrimaryKey ? " [PK]" : ""}${c.nullable ? "" : " NOT NULL"}`),
            foreignKeys: t.foreignKeys.map(
              (fk) => `(${fk.columns.join(",")}) -> ${fk.referencedTable}(${fk.referencedColumns.join(",")})`
            ),
            indexes: t.indexes.map((ix) => `${ix.name}(${ix.columns.join(",")})${ix.isUnique ? " [UNIQUE]" : ""}`)
          }))
        };
      }

      case "audit_schema_health": {
        const snap = await this.dbManager.inspectSchema(args.profile || "default");
        const report = auditSchemaSnapshot(snap, { includeProDdl });
        return {
          tier: caps.tier,
          ...report,
          upgradeHint: !includeProDdl
            ? "Activeer SQLPulse Pro (€19/kwartaal of €49/jaar) voor exacte CONCURRENTLY DDL, 5 DB-profielen en Schema Drift Diff."
            : undefined
        };
      }

      case "explain_query": {
        const { dialect, rawPlan } = await this.dbManager.explainQuery(args.profile || "default", args.sql);
        const analysis = analyzeExecutionPlan({
          dialect,
          sql: args.sql,
          rawPlan,
          includeProDdl
        });
        return {
          tier: caps.tier,
          ...analysis,
          rawPlan
        };
      }

      case "lint_migration_sql": {
        return lintMigrationSql(args.migrationSql || "", {
          dialect: args.dialect || "postgres"
        });
      }

      case "diff_schemas": {
        if (!caps.features.schemaDiff) {
          throw new Error(
            "Multi-environment 'diff_schemas' vereist een actieve SQLPulse Pro (€19/kwartaal of €49/jaar) of Team licentie."
          );
        }
        const srcSnap = await this.dbManager.inspectSchema(args.sourceProfile);
        const tgtSnap = await this.dbManager.inspectSchema(args.targetProfile);
        return diffSchemas(srcSnap, tgtSnap, {
          sourceName: args.sourceProfile,
          targetName: args.targetProfile
        });
      }

      case "safe_sample_query": {
        return await this.dbManager.executeSafeSample(
          args.profile || "default",
          args.sql,
          args.limit || caps.maxSampleRows
        );
      }

      default:
        throw new Error(`Onbekende MCP tool: '${name}'.`);
    }
  }

  async handleJsonRpc(message) {
    if (!message || typeof message !== "object") return null;
    const { id, method, params } = message;

    // Notifications do not expect a response
    if (id === undefined || id === null) {
      return null;
    }

    try {
      if (method === "initialize") {
        const clientProtocol = params?.protocolVersion || "2024-11-05";
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: clientProtocol,
            capabilities: {
              tools: { listChanged: false },
              prompts: { listChanged: false }
            },
            serverInfo: {
              name: "sqlpulse-mcp",
              version: "1.0.0"
            }
          }
        };
      }

      if (method === "ping") {
        return { jsonrpc: "2.0", id, result: {} };
      }

      if (method === "tools/list") {
        return {
          jsonrpc: "2.0",
          id,
          result: { tools: MCP_TOOLS }
        };
      }

      if (method === "prompts/list") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            prompts: [
              {
                name: "full-db-performance-audit",
                description: "Inspect schema health, unindexed foreign keys, and top slow query risks."
              }
            ]
          }
        };
      }

      if (method === "prompts/get") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            description: "SQLPulse Full Database Audit Prompt",
            messages: [
              {
                role: "user",
                content: {
                  type: "text",
                  text: "Run `audit_schema_health` first, summarize all CRITICAL and HIGH unindexed Foreign Keys or redundant indexes, and propose safe zero-downtime migration steps."
                }
              }
            ]
          }
        };
      }

      if (method === "tools/call") {
        const toolName = params?.name;
        const toolArgs = params?.arguments || {};
        try {
          const output = await this.callTool(toolName, toolArgs);
          return {
            jsonrpc: "2.0",
            id,
            result: {
              content: [{ type: "text", text: JSON.stringify(output, null, 2) }],
              isError: false
            }
          };
        } catch (toolErr) {
          return {
            jsonrpc: "2.0",
            id,
            result: {
              content: [{ type: "text", text: JSON.stringify({ error: toolErr.message }, null, 2) }],
              isError: true
            }
          };
        }
      }

      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` }
      };
    } catch (err) {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: err.message }
      };
    }
  }
}

export function startStdioMcpServer(options = {}) {
  const engine = new SqlPulseMcpEngine(options);
  const rl = readline.createInterface({
    input: process.stdin,
    terminal: false
  });

  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      process.stdout.write(
        JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }) + "\n"
      );
      return;
    }

    const response = await engine.handleJsonRpc(parsed);
    if (response) {
      process.stdout.write(JSON.stringify(response) + "\n");
    }
  });

  return engine;
}
