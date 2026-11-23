import { stripSqlLiteralsAndComments } from "../security/sql-guard.mjs";

/**
 * Extracts table aliases and candidate ESR (Equality -> Sort -> Range) columns from a SQL query
 * so deterministic composite index DDL can be synthesized with zero LLM calls.
 */
export function extractQueryPredicates(sql) {
  const clean = stripSqlLiteralsAndComments(sql);
  const aliasToTable = new Map();
  const tables = [];

  const tableMatches = clean.matchAll(
    /\b(?:FROM|JOIN)\s+([`"[]?[a-zA-Z0-9_]+[`"\]]?)(?:\s+(?:AS\s+)?([a-zA-Z0-9_]+))?/gi
  );
  for (const m of tableMatches) {
    const rawTable = m[1].replace(/[`"[\]]/g, "");
    const rawAlias = m[2] && !/^(WHERE|ON|LEFT|INNER|RIGHT|FULL|CROSS|ORDER|GROUP|LIMIT|HAVING)$/i.test(m[2]) ? m[2] : rawTable;
    tables.push(rawTable);
    aliasToTable.set(rawAlias.toLowerCase(), rawTable);
    aliasToTable.set(rawTable.toLowerCase(), rawTable);
  }

  const primaryTable = tables[0] || null;
  const perTable = new Map();
  const ensureBucket = (tbl) => {
    if (!tbl) return null;
    const key = tbl.toLowerCase();
    if (!perTable.has(key)) {
      perTable.set(key, { table: tbl, equality: new Set(), range: new Set(), sort: new Set(), join: new Set() });
    }
    return perTable.get(key);
  };

  const resolveCol = (qualifier, col) => {
    const cleanCol = col.replace(/[`"[\]]/g, "");
    if (qualifier) {
      const cleanQ = qualifier.replace(/[`"[\]]/g, "").toLowerCase();
      const mapped = aliasToTable.get(cleanQ);
      if (mapped) return { table: mapped, column: cleanCol };
    }
    if (primaryTable && tables.length === 1) {
      return { table: primaryTable, column: cleanCol };
    }
    return { table: primaryTable, column: cleanCol };
  };

  // Extract JOIN ON columns: t1.a = t2.b
  const joinMatches = clean.matchAll(
    /\bON\s+([a-zA-Z0-9_`"]+)\.([a-zA-Z0-9_`"]+)\s*=\s*([a-zA-Z0-9_`"]+)\.([a-zA-Z0-9_`"]+)/gi
  );
  for (const jm of joinMatches) {
    const left = resolveCol(jm[1], jm[2]);
    const right = resolveCol(jm[3], jm[4]);
    if (left.table) ensureBucket(left.table)?.join.add(left.column);
    if (right.table) ensureBucket(right.table)?.join.add(right.column);
  }

  // Extract WHERE section
  const whereMatch = clean.match(/\bWHERE\b([\s\S]*?)(?:\bGROUP\s+BY\b|\bORDER\s+BY\b|\bLIMIT\b|$)/i);
  if (whereMatch) {
    const whereClause = whereMatch[1];
    // Equality: [alias.]col = ... or [alias.]col IN (...) or [alias.]col IS NULL
    const eqMatches = whereClause.matchAll(
      /(?:([a-zA-Z0-9_`"]+)\.)?([a-zA-Z0-9_`"]+)\s*(?:=|\bIN\s*\(|\bIS\s+(?:NOT\s+)?NULL)/gi
    );
    for (const em of eqMatches) {
      const colName = em[2].replace(/[`"[\]]/g, "");
      if (/^(AND|OR|NOT|SELECT|WHERE|NULL|TRUE|FALSE)$/i.test(colName)) continue;
      const resolved = resolveCol(em[1], colName);
      if (resolved.table) ensureBucket(resolved.table)?.equality.add(resolved.column);
    }

    // Range: [alias.]col > / < / >= / <= / BETWEEN / LIKE
    const rangeMatches = whereClause.matchAll(
      /(?:([a-zA-Z0-9_`"]+)\.)?([a-zA-Z0-9_`"]+)\s*(?:>=|<=|>|<|\bBETWEEN\b|\bILIKE\b|\bLIKE\b)/gi
    );
    for (const rm of rangeMatches) {
      const colName = rm[2].replace(/[`"[\]]/g, "");
      if (/^(AND|OR|NOT|SELECT|WHERE)$/i.test(colName)) continue;
      const resolved = resolveCol(rm[1], colName);
      if (resolved.table) ensureBucket(resolved.table)?.range.add(resolved.column);
    }
  }

  // Extract ORDER BY section
  const orderMatch = clean.match(/\bORDER\s+BY\b([\s\S]*?)(?:\bLIMIT\b|\bOFFSET\b|$)/i);
  if (orderMatch) {
    const parts = orderMatch[1].split(",");
    for (const part of parts) {
      const om = part.trim().match(/^(?:([a-zA-Z0-9_`"]+)\.)?([a-zA-Z0-9_`"]+)(?:\s+(ASC|DESC))?/i);
      if (om) {
        const resolved = resolveCol(om[1], om[2]);
        const dir = om[3] ? om[3].toUpperCase() : "ASC";
        if (resolved.table) {
          ensureBucket(resolved.table)?.sort.add(dir === "DESC" ? `${resolved.column} DESC` : resolved.column);
        }
      }
    }
  }

  return { tables, perTable };
}

function synthesizeEsrIndexDdl(dialect, tableBucket) {
  if (!tableBucket) return null;
  const seen = new Set();
  const orderedCols = [];

  const pushCol = (rawCol) => {
    const baseName = rawCol.replace(/\s+(ASC|DESC)$/i, "").trim();
    const lower = baseName.toLowerCase();
    if (!baseName || seen.has(lower)) return;
    seen.add(lower);
    orderedCols.push(rawCol);
  };

  // ESR rule: Equality & Join predicates first -> Range / Sort order carefully
  // Standard ESR: Equality -> Sort (if no range on earlier col) -> Range
  for (const c of tableBucket.equality) pushCol(c);
  for (const c of tableBucket.join) pushCol(c);
  for (const c of tableBucket.sort) pushCol(c);
  for (const c of tableBucket.range) pushCol(c);

  if (orderedCols.length === 0) return null;
  const cappedCols = orderedCols.slice(0, 4);
  const slugCols = cappedCols
    .map((c) => c.replace(/\s+(ASC|DESC)$/i, "").replace(/[^a-zA-Z0-9_]/g, ""))
    .join("_");
  const idxName = `idx_${tableBucket.table}_${slugCols}`.slice(0, 60);

  const formattedCols = cappedCols
    .map((c) => {
      const m = c.match(/^([a-zA-Z0-9_]+)(?:\s+(ASC|DESC))?$/i);
      if (!m) return c;
      const colIdent = dialect === "mysql" ? `\`${m[1]}\`` : `"${m[1]}"`;
      return m[2] ? `${colIdent} ${m[2].toUpperCase()}` : colIdent;
    })
    .join(", ");

  if (dialect === "postgres") {
    return `CREATE INDEX CONCURRENTLY IF NOT EXISTS "${idxName}" ON "${tableBucket.table}" (${formattedCols});`;
  }
  if (dialect === "mysql") {
    return `CREATE INDEX \`${idxName}\` ON \`${tableBucket.table}\` (${formattedCols}) ALGORITHM=INPLACE, LOCK=NONE;`;
  }
  return `CREATE INDEX IF NOT EXISTS "${idxName}" ON "${tableBucket.table}" (${formattedCols});`;
}

/**
 * Walks a PostgreSQL EXPLAIN (FORMAT JSON) tree.
 */
function walkPostgresPlan(node, bottlenecks, scannedTables) {
  if (!node || typeof node !== "object") return;
  const nodeType = node["Node Type"] || "";
  const rel = node["Relation Name"] || null;
  const planRows = Number(node["Plan Rows"] || 0);
  const actualRows = Number(node["Actual Rows"] ?? planRows);
  const totalCost = Number(node["Total Cost"] || 0);

  if (nodeType === "Seq Scan" && rel) {
    scannedTables.add(rel);
    bottlenecks.push({
      code: "PG_SEQ_SCAN",
      severity: actualRows >= 500 || totalCost >= 100 || node["Filter"] ? "HIGH" : "MEDIUM",
      table: rel,
      summary: `Sequential Scan op tabel '${rel}' (geschatte rijen: ${planRows}, cost: ${totalCost.toFixed(1)})${
        node["Filter"] ? ` met filter ${node["Filter"]}` : ""
      }.`
    });
  }

  if (nodeType === "Sort" && (node["Sort Space Type"] === "Disk" || totalCost >= 250)) {
    bottlenecks.push({
      code: "PG_EXPENSIVE_SORT",
      severity: node["Sort Space Type"] === "Disk" ? "CRITICAL" : "MEDIUM",
      table: rel,
      summary: `Dure Sort-stap op ${JSON.stringify(node["Sort Key"] || [])}${
        node["Sort Space Type"] === "Disk" ? " (spilt naar Disk!)" : ""
      }.`
    });
  }

  if (nodeType === "Nested Loop" && actualRows >= 2000) {
    bottlenecks.push({
      code: "PG_NESTED_LOOP_AMPLIFICATION",
      severity: "HIGH",
      table: rel,
      summary: `Nested Loop met hoog rijvolume (${actualRows} rijen). Controleer ontbrekende index op de inner join-kolom.`
    });
  }

  if (Array.isArray(node.Plans)) {
    for (const child of node.Plans) {
      walkPostgresPlan(child, bottlenecks, scannedTables);
    }
  }
}

/**
 * Walks a MySQL EXPLAIN FORMAT=JSON object.
 */
function walkMysqlPlan(obj, bottlenecks, scannedTables) {
  if (!obj || typeof obj !== "object") return;
  if (obj.table && typeof obj.table === "object") {
    const t = obj.table;
    const tblName = t.table_name || null;
    if (t.access_type === "ALL" && tblName) {
      scannedTables.add(tblName);
      bottlenecks.push({
        code: "MYSQL_FULL_TABLE_SCAN",
        severity: Number(t.rows_examined_per_scan || 0) >= 500 ? "HIGH" : "MEDIUM",
        table: tblName,
        summary: `Full Table Scan (access_type=ALL) op '${tblName}' (${t.rows_examined_per_scan || "?"} onderzochte rijen).`
      });
    }
    if (t.using_filesort) {
      bottlenecks.push({
        code: "MYSQL_FILESORT",
        severity: "MEDIUM",
        table: tblName,
        summary: `MySQL voert een extra filesort uit${tblName ? ` op '${tblName}'` : ""}.`
      });
    }
    if (t.using_temporary_table) {
      bottlenecks.push({
        code: "MYSQL_TEMP_TABLE",
        severity: "MEDIUM",
        table: tblName,
        summary: `MySQL maakt een tijdelijke tabel aan voor groepering/sortering.`
      });
    }
  }
  for (const val of Object.values(obj)) {
    if (Array.isArray(val)) {
      val.forEach((item) => walkMysqlPlan(item, bottlenecks, scannedTables));
    } else if (val && typeof val === "object" && val !== obj.table) {
      walkMysqlPlan(val, bottlenecks, scannedTables);
    }
  }
}

/**
 * Parses SQLite EXPLAIN QUERY PLAN detail rows.
 */
function walkSqlitePlan(rows, bottlenecks, scannedTables) {
  for (const r of rows || []) {
    const detail = String(r.detail || r.notused || "");
    const scanMatch = detail.match(/\bSCAN\s+(?:TABLE\s+)?([a-zA-Z0-9_]+)/i);
    if (scanMatch && !/\bUSING\s+COVERING\s+INDEX\b/i.test(detail)) {
      const tbl = scanMatch[1];
      scannedTables.add(tbl);
      bottlenecks.push({
        code: "SQLITE_FULL_SCAN",
        severity: "HIGH",
        table: tbl,
        summary: `Full Table Scan gedetecteerd in SQLite queryplan: '${detail}'.`
      });
    }
    if (/\bUSE\s+TEMP\s+B-TREE\s+FOR\s+ORDER\s+BY\b/i.test(detail)) {
      bottlenecks.push({
        code: "SQLITE_TEMP_BTREE_SORT",
        severity: "MEDIUM",
        table: null,
        summary: `Extra geheugen/schijf sortering ('${detail}') doordat de index de ORDER BY volgorde niet dekt.`
      });
    }
  }
}

/**
 * Deterministic EXPLAIN Analyzer + Composite ESR Index Synthesizer.
 */
export function analyzeExecutionPlan({ dialect = "postgres", sql, rawPlan, includeProDdl = true }) {
  const bottlenecks = [];
  const scannedTables = new Set();

  if (dialect === "postgres") {
    const rootArr = Array.isArray(rawPlan) ? rawPlan : [rawPlan];
    const topPlan = rootArr[0]?.Plan || rootArr[0];
    walkPostgresPlan(topPlan, bottlenecks, scannedTables);
  } else if (dialect === "mysql") {
    const parsed = typeof rawPlan === "string" ? JSON.parse(rawPlan) : rawPlan;
    walkMysqlPlan(parsed, bottlenecks, scannedTables);
  } else if (dialect === "sqlite") {
    walkSqlitePlan(Array.isArray(rawPlan) ? rawPlan : [], bottlenecks, scannedTables);
  }

  const predicates = extractQueryPredicates(sql || "");
  const recommendedIndexes = [];

  const candidateTables = new Set([
    ...[...scannedTables].map((t) => t.toLowerCase()),
    ...(bottlenecks.length > 0 ? [...predicates.perTable.keys()] : [])
  ]);

  for (const tblKey of candidateTables) {
    const bucket = predicates.perTable.get(tblKey);
    if (!bucket) continue;
    const ddl = synthesizeEsrIndexDdl(dialect, bucket);
    if (ddl) {
      recommendedIndexes.push({
        table: bucket.table,
        strategy: "ESR (Equality -> Sort -> Range)",
        ddl: includeProDdl
          ? ddl
          : `-- [SQLPulse Pro vereist voor exacte ${dialect.toUpperCase()} zero-downtime composite DDL op ${bucket.table}]`,
        columnsConsidered: {
          equality: [...bucket.equality],
          join: [...bucket.join],
          sort: [...bucket.sort],
          range: [...bucket.range]
        }
      });
    }
  }

  // Detect SELECT * anti-pattern in SQL text
  if (/\bSELECT\s+\*\s+FROM\b/i.test(stripSqlLiteralsAndComments(sql || ""))) {
    bottlenecks.push({
      code: "SQL_SELECT_STAR",
      severity: "LOW",
      table: predicates.tables[0] || null,
      summary:
        "Query gebruikt 'SELECT *', wat Covering Index-Only Scans verhindert en onnodige kolomdata ophaalt."
    });
  }

  const status =
    bottlenecks.some((b) => b.severity === "CRITICAL" || b.severity === "HIGH")
      ? "NEEDS_INDEX_OPTIMIZATION"
      : bottlenecks.length > 0
        ? "SUBOPTIMAL"
        : "OPTIMAL";

  return {
    dialect,
    status,
    bottleneckCount: bottlenecks.length,
    bottlenecks,
    recommendedIndexes,
    proDdlUnlocked: includeProDdl
  };
}
