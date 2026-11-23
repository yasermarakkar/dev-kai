import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';
import { extractArgs, lineIndex } from '../core/lexer.js';
import { buildSchema, resolveTable } from '../core/schema.js';

// ---------- route inventory ----------

const CLIENT_RECEIVERS = /^(axios|http|https|got|ky|request|superagent|client|api|this|map|cache|headers|params|searchParams|res|req|config|process|store|redis|db|prisma|fetcher|instance|session|formData|url|router\.query)$/i;

/**
 * Every HTTP route the app declares: Express/Koa/Hono/Fastify shorthand, fastify.route(),
 * NestJS controllers, Next.js route handlers and pages/api.
 * @returns {{ method: string, path: string, file: string, line: number, body: string }[]}
 */
export function allRoutes(ctx) {
  if (ctx._routes) return ctx._routes;
  const routes = [];
  for (const f of ctx.appCodeFiles) {
    const code = ctx.code(f);
    if (!code) continue;
    const lineOf = lineIndex(code);
    const shorthand = /\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|del|head|options)\s*\(\s*(['"`])([^'"`]*)\3/g;
    let m;
    while ((m = shorthand.exec(code))) {
      if (CLIENT_RECEIVERS.test(m[1]) || !m[4].startsWith('/')) continue;
      const { args } = extractArgs(code, m.index + m[0].indexOf('('));
      routes.push({ method: m[2] === 'del' ? 'DELETE' : m[2].toUpperCase(), path: m[4], file: f, line: lineOf(m.index), body: args.at(-1) ?? '' });
    }
    const fastifyRoute = /\.route\s*\(\s*\{/g;
    while ((m = fastifyRoute.exec(code))) {
      const obj = extractArgs(code, m.index + m[0].length - 1).args.join(',');
      const url = (obj.match(/url\s*:\s*['"`]([^'"`]+)/) ?? [])[1];
      const method = (obj.match(/method\s*:\s*['"`](\w+)/) ?? [])[1];
      if (url && method) routes.push({ method: method.toUpperCase(), path: url, file: f, line: lineOf(m.index), body: obj });
    }
    if (/@Controller\s*\(/.test(code)) {
      const prefix = ((code.match(/@Controller\s*\(\s*['"`]([^'"`]*)['"`]/) ?? [])[1] ?? '').replace(/^\/?/, '/').replace(/\/$/, '');
      const dec = /@(Get|Post|Put|Patch|Delete)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/g;
      while ((m = dec.exec(code))) {
        const sub = (m[2] ?? '').replace(/^\/?/, '/');
        routes.push({ method: m[1].toUpperCase(), path: `${prefix}${sub === '/' ? '' : sub}` || '/', file: f, line: lineOf(m.index), body: code.slice(m.index, m.index + 1500) });
      }
    }
    const appRoute = f.match(/(?:^|\/)app\/((?:.*\/)?)route\.[cm]?[jt]sx?$/);
    if (appRoute) {
      const p = `/${appRoute[1].replace(/\/$/, '').replace(/\[([^\]]+)\]/g, ':$1').replace(/\([^)]+\)\//g, '')}`;
      for (const x of code.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b/g)) {
        routes.push({ method: x[1], path: p, file: f, line: lineOf(x.index), body: code.slice(x.index, x.index + 1500) });
      }
    }
  }
  ctx._routes = routes;
  return routes;
}

const publicRoutes = (ctx) => allRoutes(ctx).filter((r) => !/^\/(health|healthz|livez|readyz|ready|ping|metrics|_next|favicon|docs|api-docs|swagger|openapi|reference|webhooks?)\b/i.test(r.path) && r.path !== '/');

const SPEC_FILE = /(^|\/)(openapi|swagger|api-spec|api)[\w.-]*\.(ya?ml|json)$|(^|\/)openapi\/[^/]+\.(ya?ml|json)$/i;
const specFiles = (ctx) => ctx.findFiles(SPEC_FILE).filter((f) => !ctx.isTestFile(f) && /openapi|swagger/i.test((ctx.read(f) ?? '').slice(0, 400)));
const isGraphql = (ctx) => ctx.hasDep('@apollo/server', 'apollo-server', 'apollo-server-express', 'graphql-yoga', 'mercurius', '@nestjs/graphql', 'express-graphql', 'graphql-http', 'type-graphql', 'pothos', '@pothos/core', 'nexus');
const isTrpc = (ctx) => ctx.hasDep('@trpc/server');

const CODEGEN_SPEC = ['@nestjs/swagger', '@fastify/swagger', 'tsoa', '@asteasolutions/zod-to-openapi', 'zod-openapi', '@hono/zod-openapi', 'express-zod-api', 'swagger-jsdoc', 'fastify-openapi-glue', '@ts-rest/open-api', 'trpc-to-openapi', 'trpc-openapi', 'elysia', 'next-swagger-doc', '@scalar/hono-api-reference'];
const SHARED_CLIENT = ['openapi-typescript', 'openapi-fetch', 'orval', '@hey-api/openapi-ts', '@openapitools/openapi-generator-cli', 'openapi-typescript-codegen', 'swagger-typescript-api', '@graphql-codegen/cli', '@trpc/client', '@ts-rest/core', '@zodios/core', 'kubb', '@kubb/core'];

// ---------- quick checks ----------

const contract = defineCheck({
  id: 'API-001',
  title: 'Each API has a machine-readable contract (OpenAPI / GraphQL schema / tRPC)',
  severity: 'high',
  tags: ['contract', 'multi-app'],
  why: 'When several apps call each other, the contract is the only reliable source of truth for what an endpoint accepts and returns — without it, every integration is reverse-engineered from code.',
  fix: 'Publish an OpenAPI 3.1 document (generated from code: @nestjs/swagger, @fastify/swagger, zod-to-openapi, tsoa), or a GraphQL schema, or share tRPC/ts-rest types.',
  run(ctx) {
    if (!publicRoutes(ctx).length && !isGraphql(ctx) && !isTrpc(ctx)) return skip('No HTTP API routes found.');
    if (isTrpc(ctx)) return pass('tRPC router types are the contract.');
    if (isGraphql(ctx)) return pass('GraphQL schema is the contract.');
    const specs = specFiles(ctx);
    const gen = CODEGEN_SPEC.filter((l) => ctx.hasDep(l));
    if (specs.length || gen.length) return pass(`Contract: ${[...specs, ...gen].join(', ')}.`);
    return fail(`${publicRoutes(ctx).length} route(s) with no OpenAPI/GraphQL/tRPC contract.`);
  },
});

const contractSync = defineCheck({
  id: 'API-002',
  title: 'The contract is generated from code or linted and diffed in CI',
  severity: 'medium',
  tags: ['contract', 'ci'],
  why: 'A hand-maintained spec drifts from the implementation within weeks; consumers then build against fiction.',
  fix: 'Generate the spec from route schemas, or lint it (Spectral/Redocly) and diff it against main (oasdiff) in CI; validate requests/responses against it in tests or at runtime (express-openapi-validator).',
  run(ctx) {
    const specs = specFiles(ctx);
    const gen = CODEGEN_SPEC.filter((l) => ctx.hasDep(l));
    if (!specs.length && !gen.length) return skip(isGraphql(ctx) || isTrpc(ctx) ? 'Schema-first framework keeps the contract in code.' : 'No OpenAPI contract (see API-001).');
    if (gen.length) return pass(`Spec generated from code via ${gen.join(', ')}.`);
    const ci = ctx.findFiles(/^\.github\/workflows\/|\.gitlab-ci\.yml$|package\.json$/).map((f) => ctx.read(f) ?? '').join('\n');
    const validated = /spectral|redocly|oasdiff|openapi-diff|swagger-cli\s+validate|openapi-generator[^\n]*validate|vacuum\s+lint|schemathesis|optic/.test(ci) || ctx.hasDep('express-openapi-validator', 'openapi-backend', 'fastify-openapi-glue', 'jest-openapi', 'chai-openapi-response-validator', '@redocly/cli', '@stoplight/spectral-cli');
    return validated ? pass('Hand-written spec is linted/validated automatically.') : warn('Hand-written spec with no lint, diff or runtime validation — it will drift.', specs.map((f) => ({ file: f })));
  },
});

const versioning = defineCheck({
  id: 'API-003',
  title: 'APIs are versioned',
  severity: 'medium',
  tags: ['evolution', 'multi-app'],
  why: 'Without a version, every breaking change breaks every consumer (other apps, mobile clients on old builds, partners) at the same moment.',
  fix: 'Version in the path (`/v1/...`) or a header (`Accept-Version`, media type), NestJS `app.enableVersioning()`; additive changes stay within a version, breaking ones get a new one.',
  run(ctx) {
    if (isGraphql(ctx) || isTrpc(ctx)) return skip('GraphQL/tRPC evolve without URL versions (see API-010 for deprecation).');
    const routes = publicRoutes(ctx);
    if (!routes.length) return skip('No HTTP API routes found.');
    const versioned = routes.filter((r) => /\/v\d+(\/|$)/.test(r.path));
    const global = ctx.contains(/enableVersioning\s*\(|['"`]\/(api\/)?v\d+['"`]\s*,|\bprefix\s*:\s*['"`]\/(api\/)?v\d+|setGlobalPrefix\s*\(\s*['"`](api\/)?v\d+|basePath\s*\(\s*['"`]\/(api\/)?v\d+|Accept-Version|api-version|x-api-version/i);
    if (global || versioned.length === routes.length) return pass('API versioned.');
    if (versioned.length) return warn(`${routes.length - versioned.length} of ${routes.length} route(s) are unversioned.`, routes.filter((r) => !versioned.includes(r)).map((r) => ({ file: r.file, line: r.line, text: `${r.method} ${r.path}` })));
    return fail('No API versioning.', routes.slice(0, 10).map((r) => ({ file: r.file, line: r.line, text: `${r.method} ${r.path}` })));
  },
});

const errorShape = defineCheck({
  id: 'API-004',
  title: 'Errors share one documented format',
  severity: 'medium',
  tags: ['errors', 'consistency'],
  why: 'If one endpoint returns `{ error }`, another `{ message }` and a third `{ msg, code }`, every consumer has to special-case every endpoint.',
  fix: 'Adopt RFC 9457 Problem Details (`application/problem+json` with type/title/status/detail) or one `{ error: { code, message } }` shape, produced by a single helper/error handler.',
  docs: ['https://www.rfc-editor.org/rfc/rfc9457.html'],
  run(ctx) {
    if (!publicRoutes(ctx).length) return skip('No HTTP API routes found.');
    if (ctx.contains(/application\/problem\+json|ProblemDetails|problemDetails|http-problem-details|@fastify\/sensible/)) return pass('RFC 9457 problem details in use.');
    const shapes = new Map();
    for (const h of ctx.grep(/\.status\s*\(\s*[45]\d\d\s*\)\s*\.\s*(json|send)\s*\(\s*\{([^}]*)\}/)) {
      const body = h.text.match(/\.status\s*\(\s*[45]\d\d\s*\)\s*\.\s*(?:json|send)\s*\(\s*\{([^}]*)\}/)?.[1] ?? '';
      const keys = [...body.matchAll(/(?:^|,)\s*['"]?(\w+)['"]?\s*(?=[:,]|$)/g)].map((k) => k[1]).sort().join(',');
      if (!keys) continue;
      if (!shapes.has(keys)) shapes.set(keys, h);
    }
    if (shapes.size <= 2) return pass(shapes.size ? `Error bodies use ${shapes.size} shape(s).` : 'Errors go through a central handler.');
    return warn(`${shapes.size} different error body shapes.`, [...shapes.entries()].map(([k, h]) => ({ ...h, text: `{ ${k} }` })));
  },
});

const statusCodes = defineCheck({
  id: 'API-005',
  title: 'Failures are not returned with a success status',
  severity: 'medium',
  tags: ['errors', 'http'],
  why: 'A 200 with `{ error: ... }` defeats retries, caching, monitoring and every HTTP client\'s error handling.',
  fix: 'Use 4xx for client errors (400/401/403/404/409/422/429) and 5xx for server errors; keep 2xx bodies for success only.',
  run(ctx) {
    if (!publicRoutes(ctx).length) return skip('No HTTP API routes found.');
    const hits = [
      ...ctx.grep(/\.status\s*\(\s*2\d\d\s*\)\s*\.\s*(json|send)\s*\(\s*\{\s*(error|err|errors|errorMessage|success\s*:\s*false)\b/),
      ...ctx.grep(/\b(res|reply)\s*\.\s*(json|send)\s*\(\s*\{\s*(error|err|errors|errorMessage|success\s*:\s*false)\b/),
    ];
    return hits.length ? fail(`${hits.length} error response(s) sent with a 2xx status.`, unique(hits)) : pass('Error bodies carry error statuses.');
  },
});

const payloadLimits = defineCheck({
  id: 'API-006',
  title: 'Request size and upload limits are set',
  severity: 'medium',
  tags: ['abuse', 'performance'],
  why: 'Unbounded uploads or a 50 MB JSON limit let one client exhaust memory or disk on every replica.',
  fix: 'Keep JSON bodies small (Express default 100kb; raise per route only), set multer `limits: { fileSize, files }`, Fastify `bodyLimit`, and enforce the same at the proxy (`client_max_body_size`).',
  run(ctx) {
    if (!publicRoutes(ctx).length) return skip('No HTTP API routes found.');
    const findings = [];
    for (const h of ctx.grep(/\b(json|urlencoded|raw|text)\s*\(\s*\{[^}]*limit\s*:\s*['"`]?(\d+)\s*(mb|gb)/i)) {
      const [, , n, unit] = h.text.match(/\b(json|urlencoded|raw|text)\s*\(\s*\{[^}]*limit\s*:\s*['"`]?(\d+)\s*(mb|gb)/i) ?? [];
      if (unit?.toLowerCase() === 'gb' || Number(n) > 10) findings.push({ ...h, text: `body limit ${n}${unit}` });
    }
    for (const h of ctx.grep(/multer\s*\(\s*(\{[^}]*\})?\s*\)/)) if (!/limits\s*:/.test(h.text)) findings.push({ ...h, text: 'multer without limits' });
    for (const h of ctx.grep(/bodyLimit\s*:\s*(\d+)/)) if (Number(h.text.match(/bodyLimit\s*:\s*(\d+)/)[1]) > 10 * 1024 * 1024) findings.push({ ...h, text: 'Fastify bodyLimit > 10 MB' });
    return findings.length ? fail('Oversized or missing request limits.', findings) : pass('Request size limits are bounded.');
  },
});

const graphqlLimits = defineCheck({
  id: 'API-007',
  title: 'GraphQL queries are limited (depth, complexity, introspection)',
  severity: 'high',
  tags: ['graphql', 'abuse'],
  why: 'One nested GraphQL query can fan out into millions of resolver calls; open introspection maps your whole schema for attackers.',
  fix: 'Add depth and cost limits (graphql-armor, graphql-depth-limit, graphql-query-complexity), disable introspection and playground in production, and consider persisted queries.',
  docs: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
  run(ctx) {
    if (!isGraphql(ctx)) return skip('No GraphQL server.');
    const limits = ctx.hasDep('@escape.tech/graphql-armor', 'graphql-depth-limit', 'graphql-query-complexity', 'graphql-validation-complexity', '@envelop/depth-limit', 'graphql-cost-analysis', '@graphql-armor/max-depth');
    const introspection = ctx.grep(/introspection\s*:\s*true/);
    const findings = [...introspection];
    if (!limits) findings.unshift({ file: 'package.json', text: 'no depth/complexity limiting library' });
    return findings.length ? fail('GraphQL is unbounded or exposes introspection.', findings) : pass('Depth/complexity limits on; introspection not forced on.');
  },
});

const docs = defineCheck({
  id: 'API-008',
  title: 'API reference docs are published for consumers',
  severity: 'low',
  tags: ['docs'],
  why: 'Teams building the other apps should not need to read your source to call your API.',
  fix: 'Serve the OpenAPI doc with Scalar / Redoc / Swagger UI (internally if the API is private), or publish it to a developer portal (Backstage, Bump, ReadMe).',
  run(ctx) {
    if (!publicRoutes(ctx).length && !isGraphql(ctx)) return skip('No HTTP API routes found.');
    const ui = ctx.hasDep('swagger-ui-express', '@fastify/swagger-ui', '@scalar/express-api-reference', '@scalar/fastify-api-reference', '@scalar/nextjs-api-reference', '@scalar/hono-api-reference', 'redoc', 'redoc-express', '@redocly/cli', 'next-swagger-doc', '@nestjs/swagger', 'swagger-ui-react', '@apollo/server', 'graphql-yoga');
    const portal = ctx.findFiles(/(^|\/)(catalog-info\.ya?ml|docs\/api\/|bump\.ya?ml|readme\.config)/i).length > 0;
    return ui || portal ? pass('API docs UI or portal configured.') : warn('No published API reference.');
  },
});

const sharedClients = defineCheck({
  id: 'API-009',
  title: 'Consumers use generated clients or shared types',
  severity: 'medium',
  tags: ['contract', 'multi-app'],
  why: 'Hand-written fetch calls in every app duplicate the contract — a renamed field breaks consumers at runtime, not at build time.',
  fix: 'Generate typed clients from the spec (openapi-typescript + openapi-fetch, orval, @hey-api/openapi-ts) or GraphQL codegen, or share tRPC/ts-rest/zod contracts as a workspace package.',
  run(ctx) {
    const multiApp = ctx.apps.filter((a) => a.dir !== '.').length >= 2 || (ctx.stack.frontend.length && ctx.stack.hasBackend);
    if (!multiApp) return skip('Single app — no internal API consumers detected.');
    const libs = SHARED_CLIENT.filter((l) => ctx.hasDep(l));
    const sharedPkg = ctx.apps.some((a) => /(^|\/)(packages|libs)\/[^/]*(api|client|sdk|contract|types|schema)s?$/i.test(a.dir));
    if (libs.length || sharedPkg) return pass(libs.length ? `Typed clients via ${libs.join(', ')}.` : 'Shared contract/types package in the workspace.');
    return fail('Apps call each other without generated clients or shared types.');
  },
});

const contractTests = defineCheck({
  id: 'API-010',
  title: 'Contract tests catch breaking changes between apps',
  severity: 'medium',
  tags: ['contract', 'tests', 'multi-app'],
  why: 'Each app\'s own tests pass while the integration between them breaks; contract tests make the provider prove it still satisfies consumers.',
  fix: 'Consumer-driven contracts (Pact), or property-based API tests against the spec (Schemathesis), or response validation against OpenAPI in integration tests (jest-openapi), plus `oasdiff breaking` in CI.',
  run(ctx) {
    if (!publicRoutes(ctx).length && !isGraphql(ctx)) return skip('No HTTP API routes found.');
    const libs = ctx.hasDep('@pact-foundation/pact', '@pact-foundation/pact-node', 'jest-openapi', 'chai-openapi-response-validator', 'openapi-response-validator', 'dredd', 'prism', '@stoplight/prism-cli', 'express-openapi-validator');
    const ci = ctx.findFiles(/^\.github\/workflows\/|\.gitlab-ci\.yml$/).some((f) => /schemathesis|oasdiff|openapi-diff|pact|dredd|optic|graphql-inspector/.test(ctx.read(f) ?? ''));
    return libs || ci ? pass('Contract/compatibility testing in place.') : warn('No contract or breaking-change tests.');
  },
});

const naming = defineCheck({
  id: 'API-011',
  title: 'Resource paths follow one naming convention',
  severity: 'low',
  tags: ['consistency'],
  why: 'Mixed styles (`/getUsers`, `/user_profile`, `/orderItems`) make an API hard to guess and signal RPC-style endpoints that resist caching and evolution.',
  fix: 'Use plural nouns in kebab-case (`/v1/order-items/{id}`), let the HTTP method be the verb, and keep actions as sub-resources (`POST /orders/{id}/cancel`) only when needed.',
  run(ctx) {
    const routes = publicRoutes(ctx).filter((r) => !/^\/(api\/)?(auth|login|logout|signup|register|oauth|callback)/i.test(r.path));
    if (routes.length < 3) return skip('Too few routes to judge.');
    const segs = routes.flatMap((r) => r.path.split('/').filter((s) => s && !s.startsWith(':') && !s.startsWith('{') && !/^v\d+$/.test(s) && s !== 'api').map((s) => ({ s, r })));
    const style = (s) => (/_/.test(s) ? 'snake_case' : /[a-z][A-Z]/.test(s) ? 'camelCase' : /-/.test(s) ? 'kebab-case' : 'plain');
    const used = new Set(segs.map((x) => style(x.s)).filter((s) => s !== 'plain'));
    const verbs = segs.filter((x) => /^(get|create|update|delete|remove|add|fetch|list|set|do|make|save)[A-Z_-]/.test(x.s));
    const findings = [
      ...verbs.map((x) => ({ file: x.r.file, line: x.r.line, text: `verb in path: ${x.r.method} ${x.r.path}` })),
      ...(used.size > 1 ? segs.filter((x) => style(x.s) !== 'plain' && style(x.s) !== 'kebab-case').map((x) => ({ file: x.r.file, line: x.r.line, text: `${style(x.s)} segment: ${x.r.path}` })) : []),
    ];
    return findings.length ? warn(`${findings.length} path naming inconsistency(ies).`, unique(findings)) : pass('Paths use one convention and no verbs.');
  },
});

const rateLimitHeaders = defineCheck({
  id: 'API-012',
  title: 'Clients are told about limits (RateLimit / Retry-After headers)',
  severity: 'low',
  tags: ['http', 'abuse'],
  why: 'Without limit headers, well-behaved clients cannot back off; they hammer you until they get 429s and then retry immediately.',
  fix: 'express-rate-limit `standardHeaders: \'draft-7\'` (or `true`), @fastify/rate-limit adds them by default; always send `Retry-After` with 429/503.',
  run(ctx) {
    const limiter = ['express-rate-limit', 'rate-limiter-flexible', '@fastify/rate-limit', '@nestjs/throttler', 'koa-ratelimit', '@upstash/ratelimit'].filter((l) => ctx.hasDep(l));
    if (!limiter.length) return skip('No rate limiter (see SEC-005).');
    if (ctx.hasDep('@fastify/rate-limit', '@nestjs/throttler')) return pass(`${limiter.join(', ')} sends limit headers.`);
    return ctx.contains(/standardHeaders\s*:\s*(true|['"`]draft-\d['"`])|RateLimit-Limit|X-RateLimit-Limit|Retry-After/i) ? pass('Rate limit headers sent.') : warn('Rate limiting without RateLimit/Retry-After headers.');
  },
});

// ---------- in-depth (--review) ----------

const PAGINATION = /\b(limit|take|first|last|cursor|after|before|page|pageSize|per_page|perPage|offset|skip|pageToken|next_?token)\b/i;

const pagination = defineCheck({
  id: 'API-R01',
  review: true,
  title: 'Collection endpoints accept pagination parameters',
  severity: 'medium',
  tags: ['performance', 'contract'],
  why: 'An endpoint that returns "all orders" is a contract you cannot keep once the table grows; adding pagination later is a breaking change.',
  fix: 'Accept `limit` (with a server-side max) plus a cursor (`after`/`cursor`) or page, and return `next` links/cursors. Decide this before the first consumer ships.',
  run(ctx) {
    const lists = publicRoutes(ctx).filter((r) => r.method === 'GET' && !/[:{][\w]+[}]?\/?$/.test(r.path) && /s\/?$/.test(r.path.split('?')[0]) && !/(status|stats|settings|metrics|news|terms|access)\/?$/i.test(r.path));
    if (!lists.length) return skip('No collection GET endpoints found.');
    const unpaged = lists.filter((r) => !PAGINATION.test(r.body));
    if (!unpaged.length) return pass(`${lists.length} collection endpoint(s) accept pagination.`);
    return (unpaged.length === lists.length ? fail : warn)(`${unpaged.length} of ${lists.length} collection endpoint(s) have no pagination.`,
      unpaged.map((r) => ctx.at(r.file, r.line, `GET ${r.path}`)));
  },
});

const SENSITIVE_COL = /^(password|password_?hash|passwordHash|hash|salt|secret|api_?key|apiKey|token|refresh_?token|refreshToken|reset_?token|resetToken|mfa_?secret|mfaSecret|otp|ssn|tax_?id)$/i;
const PROJECTION = /\bselect\s*:|\battributes\s*:|\bprojection\b|\bomit\s*:|\bexclude\b|\.select\s*\(|\.omit\s*\(|\.lean\s*\(\s*\)\s*\.select|toJSON|toDTO|toDto|serialize|plainToInstance|instanceToPlain|ClassSerializer|@Exclude|\bpick\s*\(|DTO|Dto\b/;

const leakedFields = defineCheck({
  id: 'API-R02',
  review: true,
  title: 'Responses do not return raw database records with sensitive fields',
  severity: 'high',
  tags: ['security', 'contract'],
  why: 'Returning an ORM entity straight from the database leaks password hashes, tokens and internal columns — and freezes your schema into the public contract.',
  fix: 'Map records to response DTOs (explicit field lists), use `select`/`attributes`/`omit`, or class-transformer `@Exclude()`; never `res.json(user)` on a full row.',
  run(ctx) {
    const schema = buildSchema(ctx);
    const sensitiveTables = [...schema.tables.values()].filter((t) => [...t.columns].some((c) => SENSITIVE_COL.test(c)));
    if (!sensitiveTables.length) return skip('No tables with sensitive columns found in the schema.');
    const findings = [];
    for (const r of publicRoutes(ctx)) {
      const body = r.body;
      for (const m of body.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*await\s+(?:\w+\.)*?(?:(prisma|db|tx)\.)?([A-Za-z]\w*)\s*\.\s*(findOne|findByPk|findById|findUnique|findFirst|findMany|findAll|find|findOneBy|findBy|get|first)\s*\(([^;]*)/g)) {
        const [, variable, , model, , args] = m;
        const t = resolveTable(schema, model);
        if (!t || !sensitiveTables.includes(t)) continue;
        if (PROJECTION.test(args)) continue;
        const returned = new RegExp(`\\b(res|reply|ctx)\\s*\\.\\s*(json|send)\\s*\\(\\s*\\{?\\s*(\\.\\.\\.)?${variable}\\b|return\\s+(Response|NextResponse)\\.json\\s*\\(\\s*${variable}\\b|ctx\\.body\\s*=\\s*${variable}\\b|return\\s+${variable}\\s*;`).test(body);
        if (returned) {
          const cols = [...t.columns].filter((c) => SENSITIVE_COL.test(c));
          findings.push(ctx.at(r.file, r.line, `${r.method} ${r.path} returns ${model} row including ${cols.join(', ')}`));
        }
      }
    }
    return findings.length ? fail(`${findings.length} endpoint(s) return full records with sensitive columns.`, findings) : pass('Responses use projections/DTOs for sensitive tables.');
  },
});

const validationStatus = defineCheck({
  id: 'API-R03',
  review: true,
  title: 'Invalid input returns 400/422, not 500',
  severity: 'medium',
  tags: ['errors', 'input'],
  why: 'If a schema `.parse()` throws into a generic error handler, clients get a 500 for their own mistake — and your error-rate alerts fire on bad input.',
  fix: 'Use `safeParse` and return 400/422 with the issues, or map `ZodError`/`ValidationError` to 400 in the central error handler (NestJS ValidationPipe, Fastify schemas and celebrate do this for you).',
  run(ctx) {
    const parses = ctx.grep(/\.parse\s*\(\s*(req|request|ctx\.request)\.(body|query|params)|\.(validate|validateSync)\s*\(\s*(req|request)\.(body|query|params)/);
    if (!parses.length) return skip('No inline schema validation of requests.');
    const mapped = ctx.contains(/ZodError|instanceof\s+\w*ValidationError|err\.name\s*===?\s*['"`](ZodError|ValidationError)|isJoi|err\.issues|error\.issues|\.flatten\s*\(\s*\)|status\s*\(\s*(400|422)\s*\)[^;]*issues/);
    if (mapped) return pass('Validation errors are mapped to 4xx.');
    const inTry = parses.filter((p) => {
      const code = ctx.code(p.file) ?? '';
      const lines = code.split('\n');
      const before = lines.slice(Math.max(0, p.line - 8), p.line).join('\n');
      return /\btry\s*\{/.test(before);
    });
    const unhandled = parses.filter((p) => !inTry.includes(p));
    return unhandled.length ? fail(`${unhandled.length} request parse(s) throw into the generic error handler (500).`, unhandled) : pass('Request parsing is wrapped and answered locally.');
  },
});

// ---------- manual ----------

const manual = [
  {
    id: 'API-M01', title: 'One API style guide is shared by every app (naming, errors, pagination, versioning, dates, ids)', severity: 'high',
    why: 'Consistency across your connected apps matters more than any single choice — it is what makes the next integration cheap.',
    fix: 'Write a short guide (or adopt Zalando/Microsoft/Google API guidelines), encode the rules in a Spectral ruleset, and lint every spec in CI.',
  },
  {
    id: 'API-M02', title: 'Breaking-change and deprecation policy is published (notice period, Sunset headers)', severity: 'high',
    why: 'Mobile apps and partners cannot upgrade overnight; surprise removals break them in production.',
    fix: 'Define: what counts as breaking, minimum deprecation window (e.g. 6 months), `Deprecation`/`Sunset` headers, changelog and consumer notification.',
  },
  {
    id: 'API-M03', title: 'Every API has a named owner and a known list of consumers', severity: 'medium',
    why: 'You cannot deprecate safely, or route incidents, when nobody knows who calls what.',
    fix: 'Keep a service catalog (Backstage catalog-info.yaml or a simple table) with owner, consumers, SLA and docs link.',
  },
  {
    id: 'API-M04', title: 'Service-to-service calls are authenticated (not "trusted because internal")', severity: 'high',
    why: 'Flat internal networks let one compromised app call every other app\'s admin endpoints.',
    fix: 'mTLS via service mesh, or short-lived service tokens (OAuth client credentials / workload identity); authorize per calling service.',
  },
  {
    id: 'API-M05', title: 'Per-consumer credentials, quotas and usage visibility', severity: 'medium',
    why: 'One shared API key means you cannot rate-limit, revoke or bill a single misbehaving client.',
    fix: 'Issue a key or client id per consumer app/partner, apply quotas per key, and track usage per key.',
  },
  {
    id: 'API-M06', title: 'Latency and availability targets are documented per endpoint group', severity: 'medium',
    why: 'Consumers set their own timeouts and retries from your numbers; without them they guess.',
    fix: 'Publish p95/p99 latency and availability per API (from SLOs), and the timeout/retry behaviour you expect from clients.',
  },
  {
    id: 'API-M07', title: 'Long-running and bulk operations are asynchronous', severity: 'low',
    why: 'Holding an HTTP request open for a 2-minute export ties up connections across the LB and fails on any network blip.',
    fix: 'Return 202 Accepted with a job id/status URL (or a webhook) for slow work; offer bulk endpoints instead of N single calls.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'api',
  title: 'API design',
  description: 'Contracts, versioning, consistent errors, limits and shared clients — so your connected apps can integrate, evolve and fail predictably.',
  checks: [
    contract, contractSync, versioning, errorShape, statusCodes, payloadLimits, graphqlLimits, docs,
    sharedClients, contractTests, naming, rateLimitHeaders,
    pagination, leakedFields, validationStatus,
    ...manual,
  ],
});
