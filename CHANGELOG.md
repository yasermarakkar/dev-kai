# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Check ids (e.g. `SEC-001`) are part of the public
contract: they are never reused, and removing or renaming one is a breaking change.

## [Unreleased]

## [0.1.1]

### Changed
- Releases publish through npm Trusted Publishing (OIDC); no npm token is stored in the repository.
- CI actions bumped: `checkout`, `setup-node` and `upload-artifact` to v7.

## [0.1.0] — first release

### Added
- `devkai scan` with 10 checklists and 226 checks: security, logging, monitoring, auditing,
  database, scalability & load balancing, reliability, CI/CD & quality, frontend performance &
  accessibility, API design. Each has quick (pattern) checks, in-depth `--review` checks and
  manual checks that humans tick in the generated Markdown.
- `--review` mode: comment- and string-aware matching across lines, request-input taint tracing,
  route auth inventory, schema model (Prisma, SQL, Mongoose, TypeORM, Sequelize, Knex) for
  unindexed foreign keys and query filters, N+1 detection, WCAG contrast, `npm audit`.
- Monorepos: `--per-app`, `--app`, `devkai apps` — each app scanned with its own code and
  dependencies plus shared repo files, with a score matrix.
- Output formats: console, Markdown checklists (manual ticks preserved), JSON, and a
  self-contained HTML dashboard.
- `--fail-on <severity>` for CI, `devkai.config.json` (ignore, disable, severity overrides,
  perApp), and `devkai-ignore` comments for false positives.
- Programmatic API: `runAudit`, `runAuditPerApp`, `defineCheck`, `defineChecklist`, reporters.
