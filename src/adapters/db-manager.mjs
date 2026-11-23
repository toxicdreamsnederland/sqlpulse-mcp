import { DatabaseSync } from "node:sqlite";
import pg from "pg";
import mysql from "mysql2/promise";
import { isLocalDsn } from "../license.mjs";
import { assertReadOnlySelect, enforceRowLimit, maskResultRows } from "../security/sql-guard.mjs";

const { Client: PgClient } = pg;

export function detectDialect(dsn) {
  const s = String(dsn || "").trim();
  if (!s) throw new Error("Database DSN ontbreekt.");
  if (s.startsWith("postgres://") || s.startsWith("postgresql://")) return "postgres";
  if (s.startsWith("mysql://") || s.startsWith("mariadb://")) return "mysql";
  if (
    s === ":memory:" ||
    s.startsWith("sqlite:") ||
    s.startsWith("file:") ||
    s.endsWith(".db") ||
    s.endsWith(".sqlite") ||
    s.endsWith(".sqlite3")
  ) {
    return "sqlite";
  }
  throw new Error(
    `Onbekend database-protocol in DSN '${s.slice(0, 24)}...'. Gebruik postgres://, mysql:// of sqlite://pad.db`
  );
}

function normalizeSqlitePath(dsn) {
  const s = String(dsn || "").trim();
  if (s === ":memory:" || s === "sqlite://:memory:" || s === "sqlite::memory:") return ":memory:";
  if (s.startsWith("sqlite://")) return s.slice("sqlite://".length);
  if (s.startsWith("sqlite:")) return s.slice("sqlite:".length);
  if (s.startsWith("file://")) return s.slice("file://".length);
  return s;
}

/**
 * Manages named database profiles with strict tier-cap enforcement (Community vs Pro vs Team).
 */
export class DatabaseProfileManager {
  constructor({ profiles = {}, licenseInfo, sqliteInstances = new Map() } = {}) {
    this.licenseInfo = licenseInfo;
    this.sqliteInstances = sqliteInstances;
    this.profiles = new Map();

    const entries = Object.entries(profiles);
    const maxProfiles = licenseInfo?.caps?.maxProfiles || 1;

    for (const [name, dsn] of entries.slice(0, maxProfiles)) {
      if (dsn) this.registerProfile(name, dsn);
    }
    this.skippedProfilesCount = Math.max(0, entries.length - maxProfiles);
  }

  registerProfile(name, dsn) {
    const caps = this.licenseInfo?.caps;
    if (this.profiles.size >= (caps?.maxProfiles || 1) && !this.profiles.has(name)) {
      throw new Error(
        `Profiel-cap bereikt (${caps.maxProfiles} max op ${caps.label}). Upgrade naar SQLPulse Pro (5 profielen) of Team (20 profielen).`
      );
    }
    if (!caps?.allowRemoteDsn && !isLocalDsn(dsn)) {
      throw new Error(
        `Remote database DSN voor profiel '${name}' vereist SQLPulse Pro (€19/kwartaal of €49/jaar). Community ondersteunt uitsluitend localhost en lokale SQLite bestanden.`
      );
    }
    const dialect = detectDialect(dsn);
    this.profiles.set(name, { name, dsn, dialect });
    return { name, dialect };
  }

  getProfile(name = "default") {
    if (this.profiles.has(name)) return this.profiles.get(name);
    if (name === "default" && this.profiles.size > 0) {
      return this.profiles.values().next().value;
    }
    throw new Error(
      `Database-profiel '${name}' niet gevonden. Geconfigureerde profielen: ${
        [...this.profiles.keys()].join(", ") || "(geen — stel SQLPULSE_DSN in)"
      }.`
    );
  }

  getSqliteHandle(dsn) {
    if (this.sqliteInstances.has(dsn)) {
      return { db: this.sqliteInstances.get(dsn), closeAfter: false };
    }
    const filePath = normalizeSqlitePath(dsn);
    const db = new DatabaseSync(filePath, { readOnly: filePath !== ":memory:" });
    return { db, closeAfter: true };
  }

  async inspectSchema(profileName = "default") {
    const profile = this.getProfile(profileName);
    const maxTables = this.licenseInfo?.caps?.maxTablesPerScan || 40;

    if (profile.dialect === "sqlite") {
      return this.#inspectSqlite(profile.dsn, maxTables);
    }
    if (profile.dialect === "postgres") {
      return await this.#inspectPostgres(profile.dsn, maxTables);
    }
    if (profile.dialect === "mysql") {
      return await this.#inspectMysql(profile.dsn, maxTables);
    }
    throw new Error(`Niet-ondersteund dialect: ${profile.dialect}`);
  }

  async explainQuery(profileName = "default", sql) {
    const check = assertReadOnlySelect(sql);
    if (!check.ok) {
      throw new Error(`SQL Firewall blokkade: ${check.reason}`);
    }
    const profile = this.getProfile(profileName);

    if (profile.dialect === "sqlite") {
      const { db, closeAfter } = this.getSqliteHandle(profile.dsn);
      try {
        const planRows = db.prepare(`EXPLAIN QUERY PLAN ${check.normalizedSql}`).all();
        return { dialect: "sqlite", rawPlan: planRows };
      } finally {
        if (closeAfter) db.close();
      }
    }

    if (profile.dialect === "postgres") {
      const client = new PgClient({ connectionString: profile.dsn, statement_timeout: 5000 });
      await client.connect();
      try {
        await client.query("BEGIN READ ONLY");
        await client.query("SET LOCAL statement_timeout = '5000ms'");
        const res = await client.query(`EXPLAIN (FORMAT JSON) ${check.normalizedSql}`);
        await client.query("ROLLBACK");
        return { dialect: "postgres", rawPlan: res.rows[0]?.["QUERY PLAN"] || res.rows };
      } finally {
        await client.end().catch(() => {});
      }
    }

    if (profile.dialect === "mysql") {
      const conn = await mysql.createConnection(profile.dsn);
      try {
        await conn.query("SET SESSION TRANSACTION READ ONLY");
        await conn.query("START TRANSACTION READ ONLY");
        const [rows] = await conn.query(`EXPLAIN FORMAT=JSON ${check.normalizedSql}`);
        await conn.query("ROLLBACK");
        const rawJson = rows[0]?.EXPLAIN || rows[0]?.explain || "{}";
        return { dialect: "mysql", rawPlan: typeof rawJson === "string" ? JSON.parse(rawJson) : rawJson };
      } finally {
        await conn.end().catch(() => {});
      }
    }

    throw new Error(`Niet-ondersteund dialect: ${profile.dialect}`);
  }

  async executeSafeSample(profileName = "default", sql, requestedLimit = 20) {
    const check = assertReadOnlySelect(sql);
    if (!check.ok) {
      throw new Error(`SQL Firewall blokkade: ${check.reason}`);
    }
    const maxSampleRows = this.licenseInfo?.caps?.maxSampleRows || 20;
    const boundedSql = enforceRowLimit(check.normalizedSql, Math.min(requestedLimit || 20, maxSampleRows));
    const profile = this.getProfile(profileName);

    let rawRows = [];
    if (profile.dialect === "sqlite") {
      const { db, closeAfter } = this.getSqliteHandle(profile.dsn);
      try {
        rawRows = db.prepare(boundedSql).all();
      } finally {
        if (closeAfter) db.close();
      }
    } else if (profile.dialect === "postgres") {
      const client = new PgClient({ connectionString: profile.dsn, statement_timeout: 5000 });
      await client.connect();
      try {
        await client.query("BEGIN READ ONLY");
        await client.query("SET LOCAL statement_timeout = '5000ms'");
        const res = await client.query(boundedSql);
        rawRows = res.rows;
        await client.query("ROLLBACK");
      } finally {
        await client.end().catch(() => {});
      }
    } else if (profile.dialect === "mysql") {
      const conn = await mysql.createConnection(profile.dsn);
      try {
        await conn.query("SET SESSION TRANSACTION READ ONLY");
        await conn.query("START TRANSACTION READ ONLY");
        const [rows] = await conn.query(boundedSql);
        rawRows = Array.isArray(rows) ? rows : [];
        await conn.query("ROLLBACK");
      } finally {
        await conn.end().catch(() => {});
      }
    }

    const scrubbed = maskResultRows(rawRows);
    return {
      dialect: profile.dialect,
      executedSql: boundedSql,
      rowCount: scrubbed.rows.length,
      piiRedactedColumns: scrubbed.redactedColumns,
      piiRedactionCount: scrubbed.redactionCount,
      rows: scrubbed.rows
    };
  }

  #inspectSqlite(dsn, maxTables) {
    const { db, closeAfter } = this.getSqliteHandle(dsn);
    try {
      const allTables = db
        .prepare(
          `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name ASC`
        )
        .all();

      const truncatedByCap = allTables.length > maxTables;
      const selected = allTables.slice(0, maxTables);

      const tables = selected.map(({ name }) => {
        const safeIdent = name.replace(/"/g, '""');
        const colRows = db.prepare(`PRAGMA table_info("${safeIdent}")`).all();
        const fkRows = db.prepare(`PRAGMA foreign_key_list("${safeIdent}")`).all();
        const idxList = db.prepare(`PRAGMA index_list("${safeIdent}")`).all();

        let estimatedRows = 0;
        try {
          const cnt = db.prepare(`SELECT COUNT(*) AS c FROM "${safeIdent}"`).get();
          estimatedRows = Number(cnt?.c || 0);
        } catch {
          estimatedRows = 0;
        }

        const columns = colRows.map((c) => ({
          name: c.name,
          type: c.type || "ANY",
          nullable: c.notnull === 0 && c.pk === 0,
          defaultValue: c.dflt_value,
          isPrimaryKey: c.pk > 0
        }));

        // Group composite FKs by id
        const fkGroups = new Map();
        for (const f of fkRows) {
          if (!fkGroups.has(f.id)) {
            fkGroups.set(f.id, {
              referencedTable: f.table,
              columns: [],
              referencedColumns: []
            });
          }
          const grp = fkGroups.get(f.id);
          grp.columns.push(f.from);
          grp.referencedColumns.push(f.to);
        }

        const indexes = idxList.map((ix) => {
          const safeIdx = ix.name.replace(/"/g, '""');
          const ixCols = db.prepare(`PRAGMA index_info("${safeIdx}")`).all();
          return {
            name: ix.name,
            isUnique: ix.unique === 1,
            isPrimary: ix.origin === "pk",
            columns: ixCols.sort((a, b) => a.seqno - b.seqno).map((ic) => ic.name)
          };
        });

        return {
          name,
          estimatedRows,
          columns,
          foreignKeys: [...fkGroups.values()],
          indexes
        };
      });

      return {
        dialect: "sqlite",
        totalTablesFound: allTables.length,
        truncatedByCap,
        tables
      };
    } finally {
      if (closeAfter) db.close();
    }
  }

  async #inspectPostgres(dsn, maxTables) {
    const client = new PgClient({ connectionString: dsn, statement_timeout: 6000 });
    await client.connect();
    try {
      await client.query("BEGIN READ ONLY");
      const tblRes = await client.query(`
        SELECT c.relname AS table_name, GREATEST(c.reltuples::bigint, 0) AS est_rows
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'r' AND n.nspname = 'public'
        ORDER BY c.relname ASC
      `);
      const truncatedByCap = tblRes.rows.length > maxTables;
      const selectedRows = tblRes.rows.slice(0, maxTables);
      const tableNames = selectedRows.map((r) => r.table_name);

      if (tableNames.length === 0) {
        await client.query("ROLLBACK");
        return { dialect: "postgres", totalTablesFound: 0, truncatedByCap: false, tables: [] };
      }

      const colsRes = await client.query(
        `
        SELECT table_name, column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = ANY($1)
        ORDER BY table_name, ordinal_position
      `,
        [tableNames]
      );

      const idxRes = await client.query(
        `
        SELECT
          t.relname AS table_name,
          i.relname AS index_name,
          ix.indisunique AS is_unique,
          ix.indisprimary AS is_primary,
          ARRAY_AGG(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns
        FROM pg_class t
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_index ix ON t.oid = ix.indrelid
        JOIN pg_class i ON i.oid = ix.indexrelid
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
        WHERE n.nspname = 'public' AND t.relname = ANY($1)
        GROUP BY t.relname, i.relname, ix.indisunique, ix.indisprimary
      `,
        [tableNames]
      );

      const fkRes = await client.query(
        `
        SELECT
          con.conname AS constraint_name,
          rel.relname AS table_name,
          frel.relname AS ref_table,
          ARRAY_AGG(att.attname ORDER BY u.ord) AS columns,
          ARRAY_AGG(fatt.attname ORDER BY u.ord) AS ref_columns
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
        JOIN pg_class frel ON frel.oid = con.confrelid
        JOIN LATERAL unnest(con.conkey, con.confkey) WITH ORDINALITY AS u(attnum, fattnum, ord) ON true
        JOIN pg_attribute att ON att.attrelid = rel.oid AND att.attnum = u.attnum
        JOIN pg_attribute fatt ON fatt.attrelid = frel.oid AND fatt.attnum = u.fattnum
        WHERE con.contype = 'f' AND nsp.nspname = 'public' AND rel.relname = ANY($1)
        GROUP BY con.conname, rel.relname, frel.relname
      `,
        [tableNames]
      );

      await client.query("ROLLBACK");

      const tableMap = new Map(
        selectedRows.map((r) => [
          r.table_name,
          { name: r.table_name, estimatedRows: Number(r.est_rows || 0), columns: [], indexes: [], foreignKeys: [] }
        ])
      );

      const pkColsByTable = new Map();
      for (const ix of idxRes.rows) {
        const entry = tableMap.get(ix.table_name);
        if (!entry) continue;
        entry.indexes.push({
          name: ix.index_name,
          isUnique: Boolean(ix.is_unique),
          isPrimary: Boolean(ix.is_primary),
          columns: ix.columns || []
        });
        if (ix.is_primary) {
          pkColsByTable.set(ix.table_name, new Set(ix.columns || []));
        }
      }

      for (const c of colsRes.rows) {
        const entry = tableMap.get(c.table_name);
        if (!entry) continue;
        const pkSet = pkColsByTable.get(c.table_name) || new Set();
        entry.columns.push({
          name: c.column_name,
          type: c.data_type,
          nullable: c.is_nullable === "YES",
          defaultValue: c.column_default,
          isPrimaryKey: pkSet.has(c.column_name)
        });
      }

      for (const fk of fkRes.rows) {
        const entry = tableMap.get(fk.table_name);
        if (!entry) continue;
        entry.foreignKeys.push({
          name: fk.constraint_name,
          columns: fk.columns || [],
          referencedTable: fk.ref_table,
          referencedColumns: fk.ref_columns || []
        });
      }

      return {
        dialect: "postgres",
        totalTablesFound: tblRes.rows.length,
        truncatedByCap,
        tables: [...tableMap.values()]
      };
    } finally {
      await client.end().catch(() => {});
    }
  }

  async #inspectMysql(dsn, maxTables) {
    const conn = await mysql.createConnection(dsn);
    try {
      await conn.query("SET SESSION TRANSACTION READ ONLY");
      const [dbRow] = await conn.query("SELECT DATABASE() AS db");
      const dbName = dbRow[0]?.db;
      if (!dbName) throw new Error("Geen database geselecteerd in MySQL DSN.");

      const [tblRows] = await conn.query(
        `SELECT TABLE_NAME AS table_name, TABLE_ROWS AS est_rows
         FROM information_schema.TABLES
         WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'
         ORDER BY TABLE_NAME ASC`,
        [dbName]
      );
      const truncatedByCap = tblRows.length > maxTables;
      const selected = tblRows.slice(0, maxTables);
      const tableNames = selected.map((r) => r.table_name);

      if (tableNames.length === 0) {
        return { dialect: "mysql", totalTablesFound: 0, truncatedByCap: false, tables: [] };
      }

      const [colRows] = await conn.query(
        `SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, COLUMN_TYPE AS data_type,
                IS_NULLABLE AS is_nullable, COLUMN_DEFAULT AS column_default, COLUMN_KEY AS column_key
         FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME IN (?)
         ORDER BY TABLE_NAME, ORDINAL_POSITION`,
        [dbName, tableNames]
      );

      const [statRows] = await conn.query(
        `SELECT TABLE_NAME AS table_name, INDEX_NAME AS index_name, NON_UNIQUE AS non_unique,
                SEQ_IN_INDEX AS seq, COLUMN_NAME AS column_name
         FROM information_schema.STATISTICS
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME IN (?)
         ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX`,
        [dbName, tableNames]
      );

      const [fkRows] = await conn.query(
        `SELECT TABLE_NAME AS table_name, CONSTRAINT_NAME AS constraint_name,
                COLUMN_NAME AS column_name, REFERENCED_TABLE_NAME AS ref_table,
                REFERENCED_COLUMN_NAME AS ref_column
         FROM information_schema.KEY_COLUMN_USAGE
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME IN (?) AND REFERENCED_TABLE_NAME IS NOT NULL
         ORDER BY TABLE_NAME, CONSTRAINT_NAME, ORDINAL_POSITION`,
        [dbName, tableNames]
      );

      const tableMap = new Map(
        selected.map((r) => [
          r.table_name,
          { name: r.table_name, estimatedRows: Number(r.est_rows || 0), columns: [], indexes: [], foreignKeys: [] }
        ])
      );

      for (const c of colRows) {
        const entry = tableMap.get(c.table_name);
        if (!entry) continue;
        entry.columns.push({
          name: c.column_name,
          type: c.data_type,
          nullable: c.is_nullable === "YES",
          defaultValue: c.column_default,
          isPrimaryKey: c.column_key === "PRI"
        });
      }

      const idxGroups = new Map();
      for (const s of statRows) {
        const key = `${s.table_name}::${s.index_name}`;
        if (!idxGroups.has(key)) {
          idxGroups.set(key, {
            tableName: s.table_name,
            name: s.index_name,
            isUnique: Number(s.non_unique) === 0,
            isPrimary: s.index_name === "PRIMARY",
            columns: []
          });
        }
        idxGroups.get(key).columns.push(s.column_name);
      }
      for (const ix of idxGroups.values()) {
        tableMap.get(ix.tableName)?.indexes.push({
          name: ix.name,
          isUnique: ix.isUnique,
          isPrimary: ix.isPrimary,
          columns: ix.columns
        });
      }

      const fkGroups = new Map();
      for (const fk of fkRows) {
        const key = `${fk.table_name}::${fk.constraint_name}`;
        if (!fkGroups.has(key)) {
          fkGroups.set(key, {
            tableName: fk.table_name,
            name: fk.constraint_name,
            referencedTable: fk.ref_table,
            columns: [],
            referencedColumns: []
          });
        }
        const g = fkGroups.get(key);
        g.columns.push(fk.column_name);
        g.referencedColumns.push(fk.ref_column);
      }
      for (const fk of fkGroups.values()) {
        tableMap.get(fk.tableName)?.foreignKeys.push({
          name: fk.name,
          columns: fk.columns,
          referencedTable: fk.referencedTable,
          referencedColumns: fk.referencedColumns
        });
      }

      return {
        dialect: "mysql",
        totalTablesFound: tblRows.length,
        truncatedByCap,
        tables: [...tableMap.values()]
      };
    } finally {
      await conn.end().catch(() => {});
    }
  }
}
