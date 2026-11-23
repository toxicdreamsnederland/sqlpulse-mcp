import { stripSqlLiteralsAndComments } from "../security/sql-guard.mjs";

/**
 * Pre-flight SQL Migration Lock-Risk & Data-Loss Gate.
 * Catches production table locks and unindexed foreign keys in Prisma, Drizzle, Supabase & raw SQL migrations.
 */
export function lintMigrationSql(migrationSql, { dialect = "postgres" } = {}) {
  const raw = String(migrationSql || "");
  const clean = stripSqlLiteralsAndComments(raw);
  const issues = [];

  const hasExplicitTx = /\bBEGIN\b[\s\S]*?\bCOMMIT\b/i.test(clean);

  // Split statements conservatively
  const statements = clean
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);

  // Track indexed columns in this migration so we can verify newly added Foreign Keys
  const indexedInMigration = new Set();
  for (const stmt of statements) {
    const idxMatch = stmt.match(
      /\bCREATE\s+(?:UNIQUE\s+)?INDEX\b[\s\S]*?\bON\s+(?:[a-zA-Z0-9_`"]+\.)?([a-zA-Z0-9_`"]+)\s*\(([^)]+)\)/i
    );
    if (idxMatch) {
      const tbl = idxMatch[1].replace(/[`"]/g, "").toLowerCase();
      const firstCol = idxMatch[2]
        .split(",")[0]
        .trim()
        .split(/\s+/)[0]
        .replace(/[`"]/g, "")
        .toLowerCase();
      indexedInMigration.add(`${tbl}.${firstCol}`);
    }
  }

  statements.forEach((stmt, index) => {
    const stmtNo = index + 1;

    // 1. CREATE INDEX without CONCURRENTLY (PostgreSQL)
    if (
      dialect === "postgres" &&
      /\bCREATE\s+(?:UNIQUE\s+)?INDEX\b/i.test(stmt) &&
      !/\bCONCURRENTLY\b/i.test(stmt)
    ) {
      issues.push({
        ruleId: "LOCK_001",
        severity: "HIGH",
        statementIndex: stmtNo,
        title: "CREATE INDEX zonder CONCURRENTLY blokkeert alle schrijfacties (INSERT/UPDATE/DELETE)",
        fix: "Gebruik 'CREATE INDEX CONCURRENTLY IF NOT EXISTS ...' buiten een transactieblok."
      });
    }

    // 2. CREATE INDEX CONCURRENTLY inside explicit BEGIN...COMMIT
    if (dialect === "postgres" && hasExplicitTx && /\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\b/i.test(stmt)) {
      issues.push({
        ruleId: "LOCK_002",
        severity: "CRITICAL",
        statementIndex: stmtNo,
        title: "CREATE INDEX CONCURRENTLY binnen een BEGIN...COMMIT transactie faalt altijd in PostgreSQL",
        fix: "Draai deze migratie buiten een transactie (bijv. '-- prisma-migrate-disable-next-transaction' of aparte stap)."
      });
    }

    // 3. ALTER TABLE ADD COLUMN NOT NULL without DEFAULT
    if (
      /\bALTER\s+TABLE\b[\s\S]*?\bADD\s+(?:COLUMN\s+)?[a-zA-Z0-9_`"]+[\s\S]*?\bNOT\s+NULL\b/i.test(stmt) &&
      !/\bDEFAULT\b/i.test(stmt)
    ) {
      issues.push({
        ruleId: "LOCK_003",
        severity: "CRITICAL",
        statementIndex: stmtNo,
        title: "ADD COLUMN ... NOT NULL zonder DEFAULT faalt direct op tabellen met bestaande rijen",
        fix: "Voeg eerst de kolom nullable toe, backfill in batches, en gebruik een CHECK (...) NOT VALID constraint."
      });
    }

    // 4. ALTER COLUMN TYPE (Full Table Rewrite + ACCESS EXCLUSIVE lock)
    if (/\bALTER\s+TABLE\b[\s\S]*?\bALTER\s+COLUMN\b[\s\S]*?\bTYPE\b/i.test(stmt)) {
      issues.push({
        ruleId: "LOCK_004",
        severity: "HIGH",
        statementIndex: stmtNo,
        title: "ALTER COLUMN ... TYPE forceert vaak een volledige table-rewrite onder een ACCESS EXCLUSIVE lock",
        fix: "Gebruik het Expand-Contract patroon (nieuwe kolom toevoegen -> dual-write/backfill -> kolom wisselen)."
      });
    }

    // 5. ADD CONSTRAINT ... FOREIGN KEY without NOT VALID (Postgres)
    if (
      dialect === "postgres" &&
      /\bALTER\s+TABLE\b[\s\S]*?\bADD\s+CONSTRAINT\b[\s\S]*?\bFOREIGN\s+KEY\b/i.test(stmt) &&
      !/\bNOT\s+VALID\b/i.test(stmt)
    ) {
      issues.push({
        ruleId: "LOCK_005",
        severity: "HIGH",
        statementIndex: stmtNo,
        title: "FOREIGN KEY toevoegen zonder 'NOT VALID' neemt een zware SHARE ROW EXCLUSIVE lock tijdens validatie",
        fix: "Gebruik 'ALTER TABLE ... ADD CONSTRAINT ... FOREIGN KEY (...) REFERENCES ... NOT VALID;' gevolgd door 'VALIDATE CONSTRAINT'."
      });
    }

    // 6. Destructive DDL Gate (DROP TABLE / DROP COLUMN / TRUNCATE)
    if (/\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE\s+TABLE|TRUNCATE\b)/i.test(stmt)) {
      issues.push({
        ruleId: "DESTRUCT_001",
        severity: "CRITICAL",
        statementIndex: stmtNo,
        title: "Destructieve DDL gedetecteerd (DROP TABLE / DROP COLUMN / TRUNCATE) — risico op onomkeerbaar dataverlies",
        fix: "Verifieer dat applicatiecode deze kolom/tabel in de vorige release al niet meer leest of schrijft."
      });
    }

    // 7. Foreign Key added without matching index in migration
    const alterFkMatch = stmt.match(
      /\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:[a-zA-Z0-9_`"]+\.)?([a-zA-Z0-9_`"]+)[\s\S]*?\bFOREIGN\s+KEY\s*\(\s*([a-zA-Z0-9_`"]+)/i
    );
    if (alterFkMatch) {
      const tbl = alterFkMatch[1].replace(/[`"]/g, "").toLowerCase();
      const fkCol = alterFkMatch[2].replace(/[`"]/g, "").toLowerCase();
      if (!indexedInMigration.has(`${tbl}.${fkCol}`)) {
        issues.push({
          ruleId: "PERF_001",
          severity: "MEDIUM",
          statementIndex: stmtNo,
          title: `Nieuwe Foreign Key op '${tbl}(${fkCol})' heeft geen bijbehorende CREATE INDEX in deze migratie`,
          fix:
            dialect === "postgres"
              ? `CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_${tbl}_${fkCol}_fk" ON "${tbl}" ("${fkCol}");`
              : `CREATE INDEX "idx_${tbl}_${fkCol}_fk" ON "${tbl}" ("${fkCol}");`
        });
      }
    }
  });

  const safeToDeploy = !issues.some((i) => i.severity === "CRITICAL" || i.severity === "HIGH");

  return {
    dialect,
    statementCount: statements.length,
    safeToDeploy,
    issueCount: issues.length,
    issues
  };
}
