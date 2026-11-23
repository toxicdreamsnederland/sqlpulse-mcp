import { isSensitiveColumnName } from "../security/sql-guard.mjs";

/**
 * Normalizes identifier casing for safe cross-engine comparison.
 */
function norm(id) {
  return String(id || "").trim().toLowerCase();
}

function buildCreateIndexDdl(dialect, tableName, columns, indexSuffix = "idx") {
  const cleanTable = tableName.replace(/[^a-zA-Z0-9_]/g, "");
  const cleanCols = columns.map((c) => c.replace(/[^a-zA-Z0-9_]/g, ""));
  const idxName = `idx_${cleanTable}_${cleanCols.join("_")}_${indexSuffix}`.slice(0, 62);
  const colList = cleanCols.map((c) => (dialect === "mysql" ? `\`${c}\`` : `"${c}"`)).join(", ");
  const tblRef = dialect === "mysql" ? `\`${tableName}\`` : `"${tableName}"`;

  if (dialect === "postgres") {
    return `CREATE INDEX CONCURRENTLY IF NOT EXISTS "${idxName}" ON ${tblRef} (${colList});`;
  }
  if (dialect === "mysql") {
    return `CREATE INDEX \`${idxName}\` ON ${tblRef} (${colList}) ALGORITHM=INPLACE, LOCK=NONE;`;
  }
  return `CREATE INDEX IF NOT EXISTS "${idxName}" ON ${tblRef} (${colList});`;
}

/**
 * Checks whether `fkColumns` is covered as a left-prefix of any existing index on the table.
 */
function isPrefixIndexed(fkColumns, tableIndexes) {
  const target = fkColumns.map(norm);
  if (target.length === 0) return true;

  for (const idx of tableIndexes || []) {
    const idxCols = (idx.columns || []).map((c) => norm(typeof c === "string" ? c : c.name));
    if (idxCols.length < target.length) continue;
    let matchesPrefix = true;
    for (let i = 0; i < target.length; i++) {
      if (idxCols[i] !== target[i]) {
        matchesPrefix = false;
        break;
      }
    }
    if (matchesPrefix) return true;
  }
  return false;
}

/**
 * Deterministic 0-LLM DBA & AI-Hallucination Schema Health Auditor.
 */
export function auditSchemaSnapshot(snapshot, { includeProDdl = true } = {}) {
  const dialect = snapshot.dialect || "postgres";
  const findings = [];
  const piiProtectedColumns = [];

  for (const table of snapshot.tables || []) {
    const tableName = table.name;
    const cols = table.columns || [];
    const indexes = table.indexes || [];
    const fks = table.foreignKeys || [];
    const pkCols = cols.filter((c) => c.isPrimaryKey).map((c) => c.name);
    const hasPkIndex = pkCols.length > 0 || indexes.some((ix) => ix.isPrimary);

    // 1. Missing Primary Key
    if (!hasPkIndex) {
      findings.push({
        ruleId: "SCHEMA_NO_PK",
        severity: "HIGH",
        table: tableName,
        title: `Tabel '${tableName}' mist een Primary Key`,
        impact:
          "Veroorzaakt full-table locks bij replicatie, breekt ORM identity maps en dwingt sequentiële scans af bij row-updates.",
        recommendation: includeProDdl
          ? `ALTER TABLE "${tableName}" ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY;`
          : "Voeg een expliciete PRIMARY KEY kolom toe (upgrade naar SQLPulse Pro voor automatische migratie-DDL)."
      });
    }

    // 2. Unindexed Foreign Keys (#1 silent join & DELETE lock killer)
    const effectiveIndexes = [...indexes];
    if (pkCols.length > 0 && !effectiveIndexes.some((ix) => ix.isPrimary)) {
      effectiveIndexes.push({ name: `${tableName}_pkey`, isPrimary: true, isUnique: true, columns: pkCols });
    }

    for (const fk of fks) {
      const fkCols = fk.columns || [];
      if (!isPrefixIndexed(fkCols, effectiveIndexes)) {
        findings.push({
          ruleId: "FK_MISSING_INDEX",
          severity: (table.estimatedRows || 0) >= 1000 ? "CRITICAL" : "HIGH",
          table: tableName,
          columns: fkCols,
          references: `${fk.referencedTable}(${(fk.referencedColumns || []).join(", ")})`,
          title: `Foreign Key op '${tableName}(${fkCols.join(", ")})' heeft géén dekkende index`,
          impact:
            `Elke JOIN met '${fk.referencedTable}' of een DELETE/UPDATE op de parent-tabel forceert een dure full table scan op '${tableName}'.`,
          recommendation: includeProDdl
            ? buildCreateIndexDdl(dialect, tableName, fkCols, "fk")
            : `Maak een B-Tree index op ${tableName}(${fkCols.join(", ")}) (Pro genereert direct zero-downtime DDL).`
        });
      }
    }

    // 3. Redundant / Shadowed Left-Prefix Indexes
    for (let i = 0; i < indexes.length; i++) {
      const idxA = indexes[i];
      if (idxA.isPrimary || idxA.isUnique) continue;
      const colsA = (idxA.columns || []).map((c) => norm(typeof c === "string" ? c : c.name));
      if (colsA.length === 0) continue;

      for (let j = 0; j < indexes.length; j++) {
        if (i === j) continue;
        const idxB = indexes[j];
        const colsB = (idxB.columns || []).map((c) => norm(typeof c === "string" ? c : c.name));
        if (colsB.length < colsA.length) continue;
        if (colsB.length === colsA.length && i > j) continue;

        let shadowed = true;
        for (let k = 0; k < colsA.length; k++) {
          if (colsA[k] !== colsB[k]) {
            shadowed = false;
            break;
          }
        }
        if (shadowed) {
          findings.push({
            ruleId: "INDEX_REDUNDANT_PREFIX",
            severity: "MEDIUM",
            table: tableName,
            index: idxA.name,
            shadowedBy: idxB.name,
            title: `Redundante index '${idxA.name}' op '${tableName}' wordt volledig overschaduwd door '${idxB.name}'`,
            impact: "Vertraagt elke INSERT/UPDATE/DELETE en verspilt buffer-RAM zonder extra leeswinst.",
            recommendation: includeProDdl
              ? dialect === "postgres"
                ? `DROP INDEX CONCURRENTLY IF EXISTS "${idxA.name}";`
                : `DROP INDEX "${idxA.name}";`
              : `Overweeg index '${idxA.name}' te verwijderen na verificatie.`
          });
          break;
        }
      }
    }

    // 4. Wide Table / Large Payload Columns Warning for AI Context
    const largeCols = cols.filter((c) => /json|text|blob|bytea|tsvector/i.test(c.type || "")).map((c) => c.name);
    if (cols.length >= 18 || largeCols.length >= 3) {
      findings.push({
        ruleId: "WIDE_TABLE_SELECT_STAR",
        severity: "LOW",
        table: tableName,
        columns: largeCols,
        title: `Tabel '${tableName}' bevat ${cols.length} kolommen (${largeCols.length} tekst/JSON kolommen)`,
        impact: "AI-gegenereerde 'SELECT *' queries veroorzaken TOAST/heap I/O spikes en overspoelen de IDE context.",
        recommendation: `instrueer de ORM/query om expliciete kolomprojectie te gebruiken en vermijd SELECT * op '${tableName}'.`
      });
    }

    // 5. PII Surface Tracking
    for (const col of cols) {
      if (isSensitiveColumnName(col.name)) {
        piiProtectedColumns.push(`${tableName}.${col.name}`);
      }
    }
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  const rawScore = 100 - counts.CRITICAL * 22 - counts.HIGH * 12 - counts.MEDIUM * 5 - counts.LOW * 2;
  const healthScore = Math.max(0, Math.min(100, rawScore));

  return {
    dialect,
    tableCount: (snapshot.tables || []).length,
    truncatedByCap: Boolean(snapshot.truncatedByCap),
    healthScore,
    severityCounts: counts,
    piiProtectedColumns,
    findings
  };
}

/**
 * Multi-Environment Schema Drift Auditor (Pro / Team Feature).
 * Compares two normalized schema snapshots (e.g. `local` vs `staging`).
 */
export function diffSchemas(sourceSnapshot, targetSnapshot, { sourceName = "source", targetName = "target" } = {}) {
  const srcMap = new Map((sourceSnapshot.tables || []).map((t) => [norm(t.name), t]));
  const tgtMap = new Map((targetSnapshot.tables || []).map((t) => [norm(t.name), t]));
  const targetDialect = targetSnapshot.dialect || sourceSnapshot.dialect || "postgres";

  const drift = {
    sourceName,
    targetName,
    inSync: true,
    missingTablesInTarget: [],
    extraTablesInTarget: [],
    columnDiffs: [],
    indexDiffs: [],
    foreignKeyDiffs: [],
    syncHintsDdl: []
  };

  for (const [tKey, srcTable] of srcMap.entries()) {
    const tgtTable = tgtMap.get(tKey);
    if (!tgtTable) {
      drift.inSync = false;
      drift.missingTablesInTarget.push(srcTable.name);
      drift.syncHintsDdl.push(`-- Tabel '${srcTable.name}' bestaat in ${sourceName} maar ontbreekt in ${targetName}`);
      continue;
    }

    const srcCols = new Map((srcTable.columns || []).map((c) => [norm(c.name), c]));
    const tgtCols = new Map((tgtTable.columns || []).map((c) => [norm(c.name), c]));

    for (const [cKey, sCol] of srcCols.entries()) {
      const tCol = tgtCols.get(cKey);
      if (!tCol) {
        drift.inSync = false;
        drift.columnDiffs.push({
          table: srcTable.name,
          column: sCol.name,
          change: "missing_in_target",
          sourceType: sCol.type,
          nullable: sCol.nullable
        });
        const nullSql = sCol.nullable === false && sCol.defaultValue === null ? "/* voeg eerst nullable toe, backfill, zet daarna NOT NULL */" : "";
        drift.syncHintsDdl.push(
          `ALTER TABLE "${tgtTable.name}" ADD COLUMN "${sCol.name}" ${sCol.type || "TEXT"} ${nullSql};`.trim()
        );
      } else if (norm(sCol.type) !== norm(tCol.type) || Boolean(sCol.nullable) !== Boolean(tCol.nullable)) {
        drift.inSync = false;
        drift.columnDiffs.push({
          table: srcTable.name,
          column: sCol.name,
          change: "type_or_nullability_mismatch",
          source: { type: sCol.type, nullable: sCol.nullable },
          target: { type: tCol.type, nullable: tCol.nullable }
        });
      }
    }

    for (const [cKey, tCol] of tgtCols.entries()) {
      if (!srcCols.has(cKey)) {
        drift.inSync = false;
        drift.columnDiffs.push({
          table: srcTable.name,
          column: tCol.name,
          change: "extra_in_target",
          targetType: tCol.type
        });
      }
    }

    // Compare indexed column signatures
    const sig = (ix) =>
      `${ix.isUnique ? "U:" : "I:"}${(ix.columns || []).map((c) => norm(typeof c === "string" ? c : c.name)).join(",")}`;
    const tgtIdxSigs = new Set((tgtTable.indexes || []).map(sig));
    for (const sIdx of srcTable.indexes || []) {
      if (!tgtIdxSigs.has(sig(sIdx))) {
        drift.inSync = false;
        const colNames = (sIdx.columns || []).map((c) => (typeof c === "string" ? c : c.name));
        drift.indexDiffs.push({
          table: srcTable.name,
          index: sIdx.name,
          columns: colNames,
          change: "missing_in_target"
        });
        if (colNames.length > 0) {
          drift.syncHintsDdl.push(buildCreateIndexDdl(targetDialect, tgtTable.name, colNames, "sync"));
        }
      }
    }
  }

  for (const [tKey, tgtTable] of tgtMap.entries()) {
    if (!srcMap.has(tKey)) {
      drift.inSync = false;
      drift.extraTablesInTarget.push(tgtTable.name);
    }
  }

  return drift;
}
