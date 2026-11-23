import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';
import { blocksAfter, extractArgs, lineIndex } from '../core/lexer.js';
import { buildSchema, isIndexed, resolveTable } from '../core/schema.js';

// ---------- shared ----------

const SQL_DRIVERS = ['pg', 'postgres', 'mysql2', 'mysql', 'mariadb', 'better-sqlite3', 'sqlite3', 'tedious', 'mssql', 'oracledb', '@neondatabase/serverless', '@planetscale/database', '@vercel/postgres'];
const ORMS = ['prisma', '@prisma/client', 'typeorm', 'sequelize', 'drizzle-orm', 'knex', 'objection', '@mikro-orm/core', 'kysely', 'mongoose', 'mongodb'];

const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

const usesDb = (ctx) => ctx.hasDep(...SQL_DRIVERS, ...ORMS);
const usesSql = (ctx) => ctx.hasDep(...SQL_DRIVERS, 'prisma', '@prisma/client', 'typeorm', 'sequelize', 'drizzle-orm', 'knex', 'objection', '@mikro-orm/core', 'kysely');
const usesMongo = (ctx) => ctx.hasDep('mongoose', 'mongodb');

const MIGRATION_FILE = /(^|\/)(migrations?|migrate|db\/migrate|prisma\/migrations|drizzle|supabase\/migrations|flyway|liquibase|sql\/migrations)\/|(^|\/)V\d+(_\d+)*__\w+\.sql$|\.(up|down)\.sql$|changelog[^/]*\.(xml|ya?ml|json)$/i;

/** A DB call that hits the database (used for N+1 and transaction checks). */
const DB_CALL = /\b(await\s+)?(prisma|db|knex|trx|tx|pool|client|connection|conn|sequelize|repo\w*|this\.\w*(repo|repository|model|db)\w*|[A-Z]\w*)\s*\.\s*(\w+\s*\.\s*)?(query|execute|raw|findMany|findFirst|findUnique|findOne|findAll|findByPk|findById|findBy|findOneBy|find|count|countDocuments|aggregate|select|insert|create|createMany|update|updateMany|updateOne|upsert|delete|deleteMany|deleteOne|destroy|save|get|first)\s*\(/;
// Receiver must look like a DB handle/model, so Map.delete(), hash.update() etc. do not count.
const WRITE_CALL = /\b(prisma|db|tx|trx|pool|client|conn|connection|knex|sequelize|manager|repo\w*|[A-Z]\w*|this\.\w*(repo|repository|model|db)\w*)\s*\.\s*(\w+\s*\.\s*)?(create|createMany|insert|insertOne|insertMany|update|updateMany|updateOne|upsert|delete|deleteMany|deleteOne|destroy|save|bulkCreate|increment|decrement)\s*\(|\.(query|execute)\s*\(\s*['"`]\s*(INSERT|UPDATE|DELETE)\b/g;
const TX = /\$transaction|\.transaction\s*\(|withTransaction|startSession|startTransaction|['"`]\s*BEGIN\b|\btrx\b|\bqueryRunner\.startTransaction|getManager\(\)\.transaction|dataSource\.transaction|db\.transaction/i;

// ---------- quick checks ----------

const migrations = defineCheck({
  id: 'DB-001',
  title: 'Schema changes are managed by versioned migrations',
  severity: 'high',
  tags: ['migrations'],
  why: 'Without migrations, every environment drifts, deploys need hand-run SQL, and rollbacks are guesswork.',
  fix: 'Use your ORM\'s migration tool (prisma migrate, TypeORM/Sequelize/Knex migrations, drizzle-kit) or node-pg-migrate / Flyway; commit migrations and run them in the deploy pipeline.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    if (usesMongo(ctx) && !usesSql(ctx)) {
      return ctx.hasDep('migrate-mongo', 'mongodb-migrations', 'ts-migrate-mongoose', '@mongoosejs/migrate') || ctx.findFiles(MIGRATION_FILE).length
        ? pass('MongoDB migration tooling in use.')
        : warn('MongoDB without a migration tool — index and data changes are applied by hand. Consider migrate-mongo.');
    }
    const files = ctx.findFiles(MIGRATION_FILE).filter((f) => /\.(sql|[cm]?[jt]s|xml|ya?ml|json)$/.test(f));
    const tools = ['node-pg-migrate', 'db-migrate', 'umzug', 'knex', 'sequelize-cli', 'drizzle-kit', 'prisma', 'typeorm', 'kysely-migration-cli', 'postgrator', '@mikro-orm/migrations'].filter((t) => ctx.hasDep(t));
    if (files.length) return pass(`${files.length} migration file(s)${tools.length ? ` via ${tools.join(', ')}` : ''}.`);
    if (ctx.findFiles(/\.prisma$/).length && !ctx.findFiles(/prisma\/migrations\//).length) {
      return fail('Prisma schema without a migrations folder — `prisma db push` is not safe for production.');
    }
    return fail('Database in use but no migration files found.');
  },
});

const autoSync = defineCheck({
  id: 'DB-002',
  title: 'No automatic schema sync against production',
  severity: 'critical',
  tags: ['migrations', 'safety'],
  why: '`synchronize: true`, `sync({ alter/force })` and `db push` rewrite tables on boot — one model rename can drop a column of production data.',
  fix: 'Disable auto-sync outside local dev (`synchronize: process.env.NODE_ENV === \'development\'`) and apply changes with reviewed migrations.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const hits = [
      ...ctx.grep(/synchronize\s*:\s*true/),
      ...ctx.grep(/\.sync\s*\(\s*\{[^}]*(force|alter)\s*:\s*true/),
      ...ctx.grep(/dropSchema\s*:\s*true/),
      ...ctx.grep(/prisma\s+db\s+push(?![^"\n]*--help)|migrate\s+reset|--accept-data-loss/, { files: ctx.files.filter((f) => /package\.json$|Dockerfile|\.ya?ml$|\.sh$/.test(f)) }),
    ];
    const unguarded = hits.filter((h) => !/NODE_ENV|isDev|isTest|development|test/.test(h.text));
    return unguarded.length ? fail('Schema auto-sync or destructive reset can run outside development.', unguarded) : pass('No unguarded auto-sync or db push.');
  },
});

const fkIndexes = defineCheck({
  id: 'DB-003',
  title: 'Foreign key columns are indexed',
  severity: 'high',
  tags: ['indexing'],
  why: 'PostgreSQL does not index foreign keys automatically. Joins and "list children of X" queries then scan the whole table, and deleting a parent row locks/scans the child table.',
  fix: 'Add an index whose first column is the FK: Prisma `@@index([userId])`, SQL `CREATE INDEX CONCURRENTLY idx_orders_user_id ON orders (user_id);`, TypeORM `@Index()` on the relation column, Mongoose `{ ref: ..., index: true }`.',
  docs: ['https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-FK'],
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const schema = buildSchema(ctx);
    if (!schema.tables.size) return skip('No schema found (Prisma, SQL migrations, Mongoose, TypeORM, Sequelize, Knex).');
    const mysqlOnly = schema.dialects.has('mysql') && !schema.dialects.has('postgresql');
    // The same FK is often declared twice (SQL migration + ORM model): count it once.
    const seen = new Set();
    const fks = [...schema.tables.values()].flatMap((t) => t.fks.map((fk) => ({ ...fk, table: t })))
      .filter((fk) => {
        const key = `${fk.table.name}.${snake(fk.column)}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    if (!fks.length) return pass(`${schema.tables.size} table(s), no foreign keys declared.`);
    if (mysqlOnly) return pass('MySQL/InnoDB indexes foreign keys automatically.');
    const missing = fks.filter((fk) => !isIndexed(fk.table, fk.column));
    if (!missing.length) return pass(`All ${fks.length} foreign key(s) are indexed.`);
    return fail(`${missing.length} of ${fks.length} foreign key(s) have no index.`,
      missing.map((fk) => ctx.at(fk.file, fk.line, `${fk.table.name}.${fk.column} → ${fk.references} (no index)`)));
  },
});

const pooling = defineCheck({
  id: 'DB-004',
  title: 'Connection pooling with explicit limits',
  severity: 'high',
  tags: ['connections', 'scaling'],
  why: 'Each app replica opens its own pool; replicas × pool size must stay below the database\'s max_connections or new requests fail under load.',
  fix: 'Set the pool size explicitly (pg `max`, mysql2 `connectionLimit`, Mongoose `maxPoolSize`, Prisma `connection_limit`), and size it as max_connections ÷ replicas. Serverless: use PgBouncer / RDS Proxy / Neon or Prisma Accelerate pooling.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const single = ctx.grep(/new\s+(pg\.)?Client\s*\(|mysql\.createConnection\s*\(|createConnection\s*\(\s*\{/);
    const configured = ctx.contains(/\b(max|connectionLimit|maxPoolSize|poolSize|connection_limit|pool_size)\s*[:=]\s*[\w.]+|pool\s*:\s*\{[^}]*\bmax\b|connection_limit=|pgbouncer=true|\?.*pool_max/i)
      || ctx.files.some((f) => /\.env\.(example|sample)$|\.ya?ml$/.test(f) && /connection_limit=|pgbouncer=true|pool_max|DB_POOL/i.test(ctx.read(f) ?? ''));
    const pooled = ctx.contains(/new\s+(pg\.)?Pool\s*\(|createPool\s*\(|PrismaClient|mongoose\.connect|new\s+Sequelize|knex\s*\(|DataSource\s*\(|drizzle\s*\(/);
    if (single.length && !pooled) return fail('Single connections (Client/createConnection) used instead of a pool.', single);
    if (configured) return pass('Pool size configured explicitly.');
    if (pooled) return warn('Pool in use with library defaults — set the size explicitly per replica count.');
    return skip('No connection setup found.');
  },
});

const timeouts = defineCheck({
  id: 'DB-005',
  title: 'Query and connection timeouts are set',
  severity: 'medium',
  tags: ['reliability'],
  why: 'One runaway query or a stuck connection can hold a pool slot forever; without timeouts a slow DB turns into a full outage.',
  fix: 'pg: `statement_timeout`, `query_timeout`, `connectionTimeoutMillis`, `idleTimeoutMillis`. mysql2: `connectTimeout`. Mongoose: `serverSelectionTimeoutMS`, `socketTimeoutMS`, `maxTimeMS`. Prisma: `pool_timeout`, `connect_timeout`, transaction `timeout`.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const re = /statement_timeout|statementTimeout|query_timeout|queryTimeout|connectionTimeoutMillis|idleTimeoutMillis|connectTimeout|acquireTimeout|acquireConnectionTimeout|serverSelectionTimeoutMS|socketTimeoutMS|maxTimeMS|pool_timeout|connect_timeout|lock_timeout|idle_in_transaction_session_timeout|requestTimeout/;
    const inCode = ctx.contains(re);
    const inConfig = ctx.files.some((f) => /\.env\.(example|sample)$|\.ya?ml$|\.sql$|\.json$/.test(f) && re.test(ctx.read(f) ?? ''));
    return inCode || inConfig ? pass('Database timeouts configured.') : fail('No query/connection timeouts found.');
  },
});

const tls = defineCheck({
  id: 'DB-006',
  title: 'Database connections use TLS',
  severity: 'medium',
  tags: ['security', 'network'],
  why: 'Unencrypted DB traffic exposes credentials and data to anyone on the network path — especially across VPCs or to managed databases.',
  fix: 'Enable TLS: pg `ssl: { rejectUnauthorized: true, ca }`, `?sslmode=verify-full` in the URL, Mongo `tls=true`. Do not disable certificate verification.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    if (ctx.hasDep('better-sqlite3', 'sqlite3') && !ctx.hasDep('pg', 'mysql2', 'mongoose', 'mongodb', 'prisma', '@prisma/client')) return skip('SQLite (local file).');
    const re = /\bssl\s*:\s*(true|\{|process\.env|config\.)|sslmode=(require|verify-ca|verify-full)|\btls\s*[:=]\s*true|tls=true|ssl=true|useSSL|PGSSLMODE|DB_SSL/i;
    const has = ctx.contains(re) || ctx.files.some((f) => /\.env\.(example|sample)$|\.ya?ml$|\.json$/.test(f) && re.test(ctx.read(f) ?? ''));
    const disabled = ctx.grep(/\bssl\s*:\s*false|sslmode=disable/i);
    if (disabled.length) return fail('TLS explicitly disabled for the database.', disabled);
    return has ? pass('TLS configured for database connections.') : warn('No TLS settings found in code or env templates — confirm the production URL enforces sslmode.');
  },
});

const unbounded = defineCheck({
  id: 'DB-007',
  title: 'List queries are paginated / bounded',
  severity: 'medium',
  tags: ['performance'],
  why: 'A query that returns "all rows" works in dev and times out (or OOMs the server) when the table hits a million rows.',
  fix: 'Always paginate list endpoints (cursor/keyset pagination preferred): Prisma `take`/`cursor`, Sequelize/TypeORM `limit`/`take`, SQL `LIMIT`, Mongo `.limit()`. Cap page size server-side.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const hits = unique([
      ...ctx.grep(/\.(findMany|findAll|find)\s*\(\s*\)/),
      ...ctx.grep(/\.(find|findAll)\s*\(\s*\{\s*\}\s*\)(?!\s*\.\s*limit)/),
      ...ctx.grep(/['"`]\s*SELECT\s+[^'"`]*\s+FROM\s+["\w.]+\s*(ORDER\s+BY\s+[\w\s,."]+)?['"`]/i),
    ]).filter((h) => !/\b(limit|take|LIMIT)\b/.test(h.text));
    return hits.length ? fail(`${hits.length} unbounded query(ies).`, hits) : pass('No unbounded list queries found.');
  },
});

const destructiveMigrations = defineCheck({
  id: 'DB-008',
  title: 'Migrations avoid locking / destructive changes (or flag them)',
  severity: 'medium',
  tags: ['migrations', 'zero-downtime'],
  why: 'DROP/RENAME breaks the old app version still running during a deploy; plain CREATE INDEX and type changes lock big tables for minutes.',
  fix: 'Use expand/contract: add new column → backfill → switch code → drop later. `CREATE INDEX CONCURRENTLY`, add NOT NULL via CHECK … NOT VALID then VALIDATE, set `lock_timeout` in migrations.',
  docs: ['https://github.com/ankane/strong_migrations#checks'],
  run(ctx) {
    const files = ctx.findFiles(MIGRATION_FILE).filter((f) => f.endsWith('.sql') || ctx.codeFiles.includes(f));
    if (!files.length) return skip('No migration files.');
    // Only the latest few migrations matter: old ones already ran.
    const recent = files.sort().slice(-10);
    const risky = [
      ...ctx.grep(/\bdrop\s+(table|column)\b|\brename\s+(column|to)\b|\balter\s+column\s+\S+\s+(set\s+data\s+)?type\b|^\s*truncate\s/im, { files: recent }),
      ...ctx.grep(/\bcreate\s+(unique\s+)?index\s+(?!concurrently)(?!if\s+not\s+exists\s+concurrently)/i, { files: recent.filter((f) => f.endsWith('.sql')) })
        .map((h) => ({ ...h, text: `${h.text.trim()}  ← not CONCURRENTLY (Postgres)` })),
      ...ctx.grep(/\.(dropColumn|dropTable|renameColumn|changeColumn|removeColumn)\s*\(/, { files: recent }),
    ];
    const isPg = buildSchema(ctx).dialects.has('postgresql') || ctx.hasDep('pg', 'postgres');
    const shown = isPg ? risky : risky.filter((h) => !/CONCURRENTLY/.test(h.text));
    return shown.length ? warn(`${shown.length} risky statement(s) in the latest migrations — confirm they are deploy-safe.`, unique(shown)) : pass(`Latest ${recent.length} migration(s) look deploy-safe.`);
  },
});

const backups = defineCheck({
  id: 'DB-009',
  title: 'Automated backups / point-in-time recovery are configured',
  severity: 'high',
  tags: ['backup', 'recovery'],
  why: 'Ransomware, a bad migration or a mistaken DELETE will happen; without tested backups the data is simply gone.',
  fix: 'Managed DB: enable automated backups + PITR (RDS `backup_retention_period`, Cloud SQL `point_in_time_recovery_enabled`, Atlas continuous backup). Self-hosted: scheduled pg_dump/WAL-G to off-site storage. Keep it in IaC.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const iac = ctx.files.filter((f) => /\.(tf|tf\.json|ya?ml|json|ts|js|sh|bicep)$/.test(f));
    const hit = iac.find((f) => /backup_retention_period|point_in_time_recovery|pointInTimeRecovery|backup_configuration|backupRetention|deletion_protection|BackupPlan|AWS::Backup|wal-g|pgbackrest|pg_dump|mongodump|mysqldump|continuous_backup|PointInTimeRecoveryEnabled|backup\s*:\s*\{/i.test(ctx.read(f) ?? ''));
    return hit ? pass(`Backup configuration in ${hit}.`) : warn('No backup configuration in the repo. If the provider handles it, verify retention and restores, then tick DB-M01.');
  },
});

const shutdown = defineCheck({
  id: 'DB-010',
  title: 'Connections are closed on shutdown',
  severity: 'low',
  tags: ['connections'],
  why: 'Killing a process mid-query leaves aborted transactions and leaked server-side connections during every deploy.',
  fix: 'On SIGTERM: stop accepting requests, then `await pool.end()` / `prisma.$disconnect()` / `mongoose.connection.close()` / `sequelize.close()` / `knex.destroy()`.',
  run(ctx) {
    if (!usesDb(ctx) || !ctx.stack.server.length) return skip('No long-running server with a database.');
    const closes = ctx.contains(/\b(pool|db|client|knex|sequelize|connection)\.(end|close|destroy)\s*\(|\$disconnect\s*\(|mongoose\.(disconnect|connection\.close)\s*\(|dataSource\.destroy\s*\(/);
    const signal = ctx.contains(/process\.on\s*\(\s*['"`](SIGTERM|SIGINT)|enableShutdownHooks|onApplicationShutdown|beforeShutdown|lightship|@godaddy\/terminus|createTerminus/);
    if (closes && signal) return pass('Connections closed on shutdown signal.');
    if (signal) return warn('Shutdown handler exists but no DB close call found.');
    return fail('No graceful shutdown closing DB connections.');
  },
});

// ---------- in-depth (--review) ----------

/** Pull `where` keys (and SQL WHERE columns) from DB calls in a file. */
function filterColumns(code) {
  const out = [];
  const lineOf = lineIndex(code);
  // ORM calls: prisma.user.findMany({ where: { email } }), User.findOne({ where: { email } }), repo.findOneBy({ email }), Model.find({ email })
  const callRe = /\b(?:prisma|db|tx|this\.prisma)\.(\w+)\.(findMany|findFirst|findFirstOrThrow|findUnique|findUniqueOrThrow|count|updateMany|deleteMany|aggregate|groupBy)\s*\(|\b([A-Z]\w*|\w*[Rr]epo\w*)\.(findOne|findAll|findAndCountAll|count|findOneBy|findBy|find|findOneAndUpdate|updateMany|deleteMany|countDocuments|exists)\s*\(/g;
  let m;
  while ((m = callRe.exec(code))) {
    const model = m[1] ?? m[3];
    const method = m[2] ?? m[4];
    const open = m.index + m[0].lastIndexOf('(');
    const first = extractArgs(code, open).args[0];
    if (!first || !first.startsWith('{')) continue;
    let whereObj = null;
    if (/^(findOneBy|findBy|find|findOneAndUpdate|updateMany|deleteMany|countDocuments|exists)$/.test(method) && !/\bwhere\s*:/.test(first)) {
      whereObj = first; // Mongoose/TypeORM: object is the filter
    } else {
      const w = first.match(/\bwhere\s*:\s*\{/);
      if (w) {
        const at = first.indexOf('{', w.index);
        whereObj = first.slice(at, extractArgs(first, at).end);
      }
    }
    if (!whereObj) continue;
    for (const entry of extractArgs(whereObj, 0).args) {
      const key = (entry.match(/^['"]?([A-Za-z_]\w*)['"]?\s*(:|$|,)/) ?? [])[1];
      if (!key || /^(AND|OR|NOT|\$and|\$or|id|_id)$/.test(key)) continue;
      out.push({ model, column: key, line: lineOf(m.index) });
    }
  }
  // SQL strings: FROM t ... WHERE col = / AND col = / ORDER BY col
  const sqlRe = /\bFROM\s+["`]?(\w+)["`]?([^'"`;]*?)\bWHERE\b([^'"`;]*)/gi;
  while ((m = sqlRe.exec(code))) {
    const tableName = m[1];
    for (const c of m[3].matchAll(/(?:^|\bAND\b|\bOR\b|\(|\s)\s*(?:\w+\.)?["`]?(\w+)["`]?\s*(=|<>|!=|>=|<=|>|<|\bIN\b|\bLIKE\b|\bILIKE\b|\bIS\b|\bBETWEEN\b)/gi)) {
      const col = c[1];
      if (/^(and|or|not|null|true|false|id|\d+)$/i.test(col)) continue;
      out.push({ model: tableName, column: col, line: lineOf(m.index) });
    }
  }
  return out;
}

const filterIndexes = defineCheck({
  id: 'DB-R01',
  review: true,
  title: 'Columns used in query filters are indexed',
  severity: 'high',
  tags: ['indexing', 'performance'],
  why: 'Every WHERE on an unindexed column is a full table scan. It is invisible at 1,000 rows and an outage at 10 million.',
  fix: 'Index the columns your queries filter or sort on (composite index with the most selective / equality column first). Verify with `EXPLAIN ANALYZE`; drop indexes nobody uses.',
  docs: ['https://use-the-index-luke.com/'],
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const schema = buildSchema(ctx);
    if (!schema.tables.size) return skip('No schema found to compare queries against.');
    const usage = new Map(); // table.column -> { count, first }
    let resolved = 0;
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code || !/where|WHERE|find/.test(code)) continue;
      for (const u of filterColumns(code)) {
        const t = resolveTable(schema, u.model);
        if (!t) continue;
        resolved++;
        if (isIndexed(t, u.column)) continue;
        if (t.columns.size && ![...t.columns].some((c) => snake(c) === snake(u.column))) continue; // not a column of this table
        const key = `${t.name}.${snake(u.column)}`;
        const cur = usage.get(key) ?? { count: 0, first: ctx.at(f, u.line, `${key} filtered without an index`) };
        cur.count++;
        usage.set(key, cur);
      }
    }
    if (!resolved) return skip('Could not map any queries to schema tables.');
    if (!usage.size) return pass(`${resolved} filtered query column(s) checked — all indexed.`);
    const findings = [...usage.entries()].sort((a, b) => b[1].count - a[1].count)
      .map(([key, v]) => ({ ...v.first, text: `${key} — used in ${v.count} quer${v.count === 1 ? 'y' : 'ies'}, no index` }));
    return (usage.size > 2 ? fail : warn)(`${usage.size} filtered column(s) have no index (skip if the table stays small).`, findings);
  },
});

const nPlusOne = defineCheck({
  id: 'DB-R02',
  review: true,
  title: 'No N+1 queries (database calls inside loops)',
  severity: 'high',
  tags: ['performance'],
  why: 'One query per item turns a 20 ms page into 2,000 queries and a pool exhaustion as data grows.',
  fix: 'Batch: `findMany({ where: { id: { in: ids } } })`, SQL `WHERE id = ANY($1)`, ORM `include`/eager loading, or a DataLoader for GraphQL resolvers.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const findings = [];
    const loopRe = /\bfor\s*\([^)]*\b(of|in)\b[^)]*\)\s*\{|\bwhile\s*\([^)]*\)\s*\{|\.(forEach|map|flatMap)\s*\(\s*async\s*(\([^)]*\)|\w+)\s*=>\s*\{/;
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code || !DB_CALL.test(code)) continue;
      const lineOf = lineIndex(code);
      for (const b of blocksAfter(code, loopRe)) {
        const call = b.body.match(DB_CALL);
        if (call && /await|\.then\s*\(|Promise\.all/.test(b.body)) {
          findings.push(ctx.at(f, lineOf(b.open + 1 + call.index), `DB call inside loop: ${call[0].replace(/\s+/g, ' ').trim()}`));
        }
      }
    }
    return findings.length ? fail(`${findings.length} database call(s) inside loops.`, unique(findings)) : pass('No database calls inside loops found.');
  },
});

const transactions = defineCheck({
  id: 'DB-R03',
  review: true,
  title: 'Multi-step writes run in a transaction',
  severity: 'medium',
  tags: ['integrity'],
  why: 'If the second write fails, the first one stays: orders without items, money moved but not recorded.',
  fix: 'Wrap related writes: Prisma `$transaction`, Sequelize/TypeORM/Knex transactions, `BEGIN … COMMIT` on one pg client, Mongo `session.withTransaction()`.',
  run(ctx) {
    if (!usesDb(ctx)) return skip('No database dependency detected.');
    const findings = [];
    const fnRe = /\basync\s+function\s*\w*\s*\([^)]*\)\s*\{|\basync\s*\([^)]*\)\s*=>\s*\{|\basync\s+\w+\s*\([^)]*\)\s*\{/;
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code) continue;
      const lineOf = lineIndex(code);
      for (const b of blocksAfter(code, fnRe)) {
        // only the function's own statements: skip bodies that contain nested async functions
        if (fnRe.test(b.body)) continue;
        const writes = b.body.match(WRITE_CALL) ?? [];
        if (writes.length >= 2 && !TX.test(b.body)) findings.push(ctx.at(f, lineOf(b.start), `${writes.length} writes, no transaction`));
      }
    }
    return findings.length ? warn(`${findings.length} function(s) perform several writes without a transaction.`, unique(findings)) : pass('Multi-write functions use transactions.');
  },
});

// ---------- manual ----------

const manual = [
  {
    id: 'DB-M01', title: 'Backups are encrypted, stored off-site, and a restore was tested this quarter', severity: 'critical',
    why: 'An untested backup is a hope, not a backup. Most teams learn their backups are broken during the incident.',
    fix: 'Define RPO/RTO per database, automate a periodic restore into a scratch instance, and record the time it took.',
  },
  {
    id: 'DB-M02', title: 'Slow-query monitoring is on and reviewed', severity: 'high',
    why: 'Missing indexes and bad plans only show under real data and traffic.',
    fix: 'Enable pg_stat_statements / slow query log / Performance Insights / Atlas profiler; review top queries by total time each sprint.',
  },
  {
    id: 'DB-M03', title: 'Connection budget fits: replicas × pool size < max_connections', severity: 'high',
    why: 'Autoscaling the app is the classic way to take the database down.',
    fix: 'Document max_connections, pool size per app and max replicas for every app sharing the DB; add a pooler (PgBouncer, RDS Proxy) when it does not fit.',
  },
  {
    id: 'DB-M04', title: 'Read scaling strategy exists (replicas, caching) for read-heavy apps', severity: 'medium',
    why: 'Several apps and websites reading the same primary eventually saturate it.',
    fix: 'Route reporting/analytics and heavy reads to replicas; cache hot reads (Redis) with explicit invalidation; watch replica lag.',
  },
  {
    id: 'DB-M05', title: 'Zero-downtime migration practice is documented and followed', severity: 'medium',
    why: 'Deploys with multiple running versions break on destructive or locking migrations.',
    fix: 'Expand/contract rule, `lock_timeout` in migrations, CONCURRENTLY for indexes, backfills in batches, migration review checklist in PRs.',
  },
  {
    id: 'DB-M06', title: 'Separate DB users for migrations, app runtime and read-only access', severity: 'high',
    why: 'An app that connects as owner can drop tables; a reporting tool with write access is an accident waiting to happen.',
    fix: 'Owner role for migrations only; runtime role with DML on its tables; read-only role for BI; no shared superuser across apps.',
  },
  {
    id: 'DB-M07', title: 'Data retention and deletion (incl. GDPR erasure) are implemented per table', severity: 'medium',
    why: 'Tables grow forever and personal data is kept long after it is needed.',
    fix: 'Define retention per table, run scheduled purges or partition drops, and support erasure requests across every app\'s database.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'database',
  title: 'Database',
  description: 'Migrations, indexing, connection pooling, timeouts, query safety and recovery — keeping data correct and fast as it grows.',
  checks: [
    migrations, autoSync, fkIndexes, pooling, timeouts, tls, unbounded, destructiveMigrations, backups, shutdown,
    filterIndexes, nPlusOne, transactions,
    ...manual,
  ],
});
