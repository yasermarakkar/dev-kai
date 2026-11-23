# devkai-readiness

Scan your apps and get **production-readiness checklists** — what is missing, where, and how to fix it.
One file per area (security, logging, monitoring, auditing, database, scaling …), written into your repo so the team can track progress over time.

Zero runtime dependencies. **Node 21+** (`.nvmrc` pins 22 LTS).

```bash
npx devkai-readiness scan .            # once published
node bin/devkai.js scan ./my-app       # from this repo
```

Output:

```
readiness/
  README.md      ← overall score + "fix first" list
  security.md    ← checklist with [x]/[ ] items, file:line evidence, why + fix
  logging.md
  monitoring.md
  auditing.md
  database.md
  scalability.md
  report.json    ← with --format json, for CI / dashboards
```

## Commands

| Command | What it does |
|---|---|
| `devkai scan [dir]` | Scan a project, print a summary, write checklist files |
| `devkai list` | List all checklists and checks |
| `devkai init [dir]` | Create `devkai.config.json` |

Scan options: `--only security,logging` · `--format console,md,json` · `--out <dir>` · `--fail-on high` (exit 1 for CI) · `--review` · `--offline` · `--verbose` · `--config <file>`.

## Two modes: quick (default) and `--review`

| | `devkai scan` (quick) | `devkai scan --review` (in-depth) |
|---|---|---|
| Matching | Regex, line by line | Comment-aware, follows statements across lines |
| Comments | Can match commented-out code | Ignored |
| Extra checks | — | Taint tracing (req input → SQL/shell/fs/redirect/fetch/HTML), route auth inventory (Express-style, NestJS, Next.js), mass assignment, `npm audit` CVEs, raw-object logging, catch-block log levels, health handlers that skip the DB, public `/metrics`, silent 5xx catch blocks, routes with no audit event, spoofable audit actor, unrecorded 403s, filtered columns without an index, N+1 queries, multi-write functions without a transaction, module-level state written by handlers, blocking sync calls in handlers, outbound calls without a timeout |
| Findings | file:line | file:line + surrounding code |
| Speed | Milliseconds — run on every commit | Seconds — run in CI / before release |

`--review` calls `npm audit` / `pnpm audit` (sends your dependency list to the npm registry). Add `--offline` to skip it.
Analysis is static and file-scoped: no type info, no cross-file data flow — it points reviewers at the right lines, it does not prove absence of bugs.

## How checks work

- **Automated** checks read code, deps and config (no code is executed, nothing leaves your machine).
  Status: `PASS`, `MISSING`, `REVIEW` (partial), `N/A` (not applicable to your stack).
- **Manual** checks cover what code can't prove (MFA, pentests, incident plan). Tick `[x]` in the generated file —
  ticks are preserved on the next scan.
- **Score** = severity-weighted share of applicable checks passing (critical 10, high 6, medium 3, low 1).
- Secrets found are **masked** in all output, so reports are safe to commit.

## Config — `devkai.config.json`

```json
{
  "outDir": "readiness",
  "ignore": ["legacy/", "scripts/seed"],
  "disable": ["SEC-005"],
  "severity": { "SEC-007": "low" }
}
```

## CI

```yaml
- run: npx devkai-readiness scan . --format md,json --fail-on critical
```

## Programmatic API

```js
import { runAudit, writeMarkdown } from 'devkai-readiness';
const report = await runAudit({ root: '.', only: ['security'] });
writeMarkdown(report, './readiness');
```

## Writing a check

```js
import { defineCheck, pass, fail, skip } from 'devkai-readiness';

export const myCheck = defineCheck({
  id: 'LOG-001', title: 'Structured logger in use', severity: 'medium',
  why: '…', fix: '…',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend');
    return ctx.hasDep('pino', 'winston') ? pass('Found logger') : fail('console.log only', ctx.grep(/console\.log\(/));
  },
});
```

`ctx` gives you: `files`, `codeFiles`, `appCodeFiles`, `apps` (every package.json — monorepo aware), `deps`, `prodDeps`, `stack`,
`review`, `offline`, `read(file)`, `code(file)` (comments stripped), `at(file, line, text)` (finding with context),
`exists(file)`, `hasDep(...names)`, `grep(regex, { files, filter, limit })` (mode-aware), `contains(regex)`, `findFiles(pattern)`.

Add `review: true` to a check to run it only with `--review`.

### Schema model

`buildSchema(ctx)` (in `src/core/schema.js`) reads Prisma schemas, SQL migrations, Mongoose schemas, TypeORM entities,
Sequelize models and Knex migrations into one model: tables → columns, foreign keys and indexed (leading) columns.
The database checks use it to find unindexed foreign keys and query filters.

## Roadmap

| Step | Checklist | Status |
|---|---|---|
| 1 | Core engine, CLI, markdown/JSON reports, **Security** (18 quick + 4 in-depth + 9 manual) | done |
| 1b | `--review` in-depth mode, Node 21+ | done |
| 2 | **Logging** (11 quick + 2 in-depth + 5 manual) — logger, levels, request ids, redaction, swallowed errors | done |
| 3 | **Monitoring** (11 quick + 3 in-depth + 7 manual) — health/readiness, error tracking (server + frontend), metrics, tracing, probes, alerts as code, RUM, source maps | done |
| 4 | **Auditing** (8 quick + 3 in-depth + 7 manual) — audit store and fields, auth/admin events, append-only protection, created_by/soft delete, no secrets, retention | done |
| 5 | **Database** (10 quick + 3 in-depth + 7 manual) — migrations, no auto-sync, FK indexes, pooling, timeouts, TLS, pagination, deploy-safe migrations, backups, shutdown | done |
| 6 | **Scalability & load balancing** (14 quick + 3 in-depth + 7 manual) — shared sessions/uploads/rate limits, graceful shutdown, outbound + keep-alive timeouts, caching, jobs, WebSockets, autoscaling, resources, trust proxy, compression, load tests | done |
| 7 | **Reliability** — retries/backoff, circuit breakers, idempotency, error handling | next |
| 8 | **CI/CD & quality**, **Frontend performance & accessibility**, **API design** | |
| 9 | Per-app reports for monorepos, HTML dashboard, publish to npm | |
