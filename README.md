# devkai-readiness

Scan your apps and get **production-readiness checklists** — what is missing, where, and how to fix it.
One file per area (security, logging, monitoring, auditing, database, scaling …), written into your repo so the team can track progress over time.

Zero runtime dependencies. **Node 21+** (`.nvmrc` pins 22 LTS).

```bash
npx devkai-readiness scan .                  # one-off, no install
npm install --save-dev devkai-readiness      # or add it to a project…
npx devkai scan . --review --format md,html  # …and run the `devkai` command
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
  reliability.md
  cicd.md
  frontend.md
  api.md
  report.json    ← with --format json, for CI / dashboards
  index.html     ← with --format html, an interactive dashboard
```

### HTML dashboard

```bash
devkai scan . --per-app --format console,md,html
open readiness/index.html
```

One self-contained file (no CDN, works offline from `file://`, safe to commit or attach to a CI run):
overall score, an apps × checklists matrix (click a cell to filter), checklist cards, and every check
with severity/status/search filters; expand a check for why, fix, file:line and — in `--review` mode —
the surrounding code. Light and dark themes, phone-friendly.

Report text comes from your source code, so the page treats it as untrusted: data is embedded as escaped
JSON and rendered with `textContent` only.

## Commands

| Command | What it does |
|---|---|
| `devkai scan [dir]` | Scan a project, print a summary, write checklist files |
| `devkai list` | List all checklists and checks |
| `devkai apps [dir]` | List the apps found in a monorepo |
| `devkai init [dir]` | Create `devkai.config.json` |

Scan options: `--only security,logging` · `--format console,md,json,html` · `--out <dir>` · `--fail-on high` (exit 1 for CI) · `--review` · `--offline` · `--per-app` · `--app <names>` · `--verbose` · `--config <file>`.

## Monorepos: one report per app

```bash
devkai apps .                 # list the apps found (every package.json outside fixtures)
devkai scan . --per-app       # one report per app + a score matrix
devkai scan . --app api,web   # only these apps (name or dir)
```

Each app is scanned with **its own files and dependencies** plus the **shared repo files** (`.github/`, root
config, infra) — never another app's code. So `helmet` in `apps/api` does not make `apps/admin` pass, and
frontend checks only score the apps that have a frontend (`–` = not applicable). Repo-level checks
(monorepo tooling, shared clients) still see every package.

```
readiness/
  README.md            ← apps × checklists score matrix + "fix first" across all apps
  apps-api/            ← that app's README + security.md, logging.md, …
  apps-web/
```

Manual ticks are kept per app (`readiness/<app>/*.md`). Set `"perApp": true` in `devkai.config.json` to make it the default.
`--fail-on` fails if **any** app has an issue at that severity.

## Two modes: quick (default) and `--review`

| | `devkai scan` (quick) | `devkai scan --review` (in-depth) |
|---|---|---|
| Matching | Regex, line by line | Comment-aware, follows statements across lines |
| Comments | Can match commented-out code | Ignored |
| Extra checks | — | Taint tracing (req input → SQL/shell/fs/redirect/fetch/HTML), route auth inventory (Express-style, NestJS, Next.js), mass assignment, `npm audit` CVEs, raw-object logging, catch-block log levels, health handlers that skip the DB, public `/metrics`, silent 5xx catch blocks, routes with no audit event, spoofable audit actor, unrecorded 403s, filtered columns without an index, N+1 queries, multi-write functions without a transaction, module-level state written by handlers, blocking sync calls in handlers, outbound calls without a timeout, async handlers that can hang (Express 4), `.then()` without `.catch()`, catch blocks that answer with success, critical modules no test imports, `.only`/skipped tests, CI jobs without timeouts or concurrency, icon-only buttons without a name, skipped heading levels, WCAG text contrast (CSS + Tailwind), React missing keys / effects without deps, unpaginated collection endpoints, raw DB rows with sensitive columns in responses, validation errors answered with 500 |
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

## Silencing a false positive

Put a comment next to the code (check ids are required, `*` = every check):

```js
const html = sanitize(input); el.innerHTML = html; // devkai-ignore SEC-018
// devkai-ignore-next-line LOG-002
console.log(banner);
/* devkai-ignore-file SEC-008 — sandboxed formula evaluator, reviewed 2026-11 */
```

Suppressed findings are counted in the report (`(2 suppressed)`), so they stay visible in review.
Checks that look for code constructs (calls, options, sinks) already ignore text inside strings, regexes and comments.

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

## Developing this package

```bash
npm ci
npm run lint            # ESLint
npm test                # unit + fixture tests
npm run test:coverage   # fails below 95% lines / 80% branches / 90% functions
npm run scan:self       # devkai on itself; CI fails on any high/critical finding
```

CI (`.github/workflows/ci.yml`) runs lint, coverage and `npm audit` on Node 22 and 24, then scans this repo with
`--review --fail-on high` and uploads the dashboard as a build artifact. Dependabot keeps dev dependencies and
actions current. The package itself has **no runtime dependencies**.

## Releasing (maintainers)

Releases are published **only from CI**, never from a laptop:

1. Move the `## [Unreleased]` notes in `CHANGELOG.md` under a new `## [x.y.z]` heading.
2. `npm run release:patch` (or `release:minor` / `release:major`) — runs lint + tests, bumps the
   version, commits and tags `vx.y.z`.
3. `git push --follow-tags` — `.github/workflows/release.yml` checks the tag matches `package.json`
   and the CHANGELOG, re-runs lint, coverage and the self-scan, then `npm publish --provenance`.

One-time setup:
- Add `repository` (`{ "type": "git", "url": "git+https://github.com/<owner>/<repo>.git" }`) to
  `package.json` — provenance requires it to match the GitHub repo that publishes.
- On npmjs.com, add this repo + `release.yml` as a **Trusted Publisher** for the package (OIDC; no
  npm token stored in GitHub). For the very first version npm may require the package to exist:
  publish 0.1.0 once with a granular token in the `NODE_AUTH_TOKEN` secret, then switch to trusted publishing.
- In GitHub → Settings → Environments, create `npm` with required reviewers so every release needs an approval.

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
| 7 | **Reliability** (11 quick + 3 in-depth + 7 manual) — retries, circuit breakers, idempotency keys, verified/deduped webhooks, central error handler, Express 4 async errors, error boundaries, pinned images, feature flags, queue DLQs, env validation | done |
| 8 | **CI/CD & quality** (14 quick + 3 in-depth + 7 manual) — pipeline, tests + test script, CI runs tests/lint/typecheck, coverage threshold, CODEOWNERS, automated deploys, staging + gated prod, frozen installs, SHA-pinned actions, workflow injection/permissions, hooks, monorepo affected builds, releases | done |
| 9 | **Frontend & a11y** (16 quick + 4 in-depth + 7 manual) — image weight/dimensions, heavy libs, code splitting, perf budgets, fonts, third-party scripts, source maps, alt text, labels, semantic controls, lang/title, a11y tooling, zoom, focus, reduced motion | done |
| 10 | **API design** (12 quick + 3 in-depth + 7 manual) — contracts, spec sync, versioning, one error format, status codes, payload/GraphQL limits, docs, shared clients, contract tests, naming, rate-limit headers | done |
| 11 | Per-app reports for monorepos (`--per-app`, `--app`, `devkai apps`) | done |
| 12 | HTML dashboard (`--format html`) | done |
| 13 | CI for this package (lint, coverage gate, audit, self-scan) and inline `devkai-ignore` | done |
| 14 | npm release pipeline (tag-triggered, trusted publishing + provenance, CHANGELOG, LICENSE) | done |
| 15 | First public release (needs repository URL + npm Trusted Publisher setup) | next |
