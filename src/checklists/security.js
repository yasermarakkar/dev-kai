import path from 'node:path';
import { defineCheck, defineChecklist, pass, fail, warn, skip } from '../core/check.js';
import { maskSecret } from '../core/utils.js';
import { reviewChecks } from './security-review.js';

const OWASP = 'https://cheatsheetseries.owasp.org/cheatsheets';

// ---------- shared helpers ----------

const ENV_FILE_RE = /(^|\/)\.env(\.[\w-]+)?$/;
const ENV_TEMPLATE_RE = /\.(example|sample|template|dist|defaults?)$/i;
const CONFIG_FILE_RE = /\.(json|ya?ml|toml|ini|conf|properties|xml)$/i;
const LOCKFILE_RE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|npm-shrinkwrap\.json)$/;

const PLACEHOLDER_RE = /(process\.env|import\.meta\.env|\$\{|<[^>]+>|changeme|change_me|your[-_]|example|placeholder|dummy|sample|xxx+|\*{3,}|todo|redacted|test(ing)?[-_]?(secret|key|password))/i;

const SECRET_PATTERNS = [
  { name: 'AWS access key id', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'Private key block', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/ },
  { name: 'Stripe live secret key', re: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b/ },
  { name: 'GitHub token', re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/ },
  { name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { name: 'OpenAI / Anthropic key', re: /\b(sk-(proj-|ant-)?[A-Za-z0-9_-]{32,})\b/ },
  { name: 'SendGrid key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { name: 'Credentials in connection string', re: /\b(mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|rediss|amqps?|mssql):\/\/[^:\s'"`/]+:[^@\s'"`]+@[^\s'"`]+/ },
  {
    name: 'Hardcoded secret assignment',
    re: /\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|jwt[_-]?secret)\b["']?\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/i,
    valueGroup: 2,
  },
];

function mask(text, match) {
  return text.replace(match, maskSecret(match));
}

function hit(file, line, text) {
  return { file, line, text };
}

const authDelegatedDeps = [
  'next-auth', '@auth/core', '@auth0/nextjs-auth0', 'auth0', '@clerk/nextjs', '@clerk/clerk-sdk-node',
  '@clerk/express', '@supabase/supabase-js', 'firebase', 'firebase-admin', 'amazon-cognito-identity-js',
  '@aws-amplify/auth', 'aws-amplify', 'keycloak-connect', '@okta/okta-auth-js', 'better-auth', '@kinde-oss/kinde-auth-nextjs',
];

const authDeps = ['passport', 'jsonwebtoken', 'jose', 'express-session', 'cookie-session', '@nestjs/passport', '@fastify/jwt', 'lucia'];

// ---------- checks ----------

const hardcodedSecrets = defineCheck({
  id: 'SEC-001',
  title: 'No hardcoded secrets in source or config',
  severity: 'critical',
  tags: ['secrets'],
  why: 'Secrets committed to git live forever in history and leak through forks, CI logs and laptops.',
  fix: 'Move secrets to environment variables or a secrets manager (Vault, AWS Secrets Manager, Doppler, 1Password). Rotate every value found here — assume it is compromised.',
  docs: [`${OWASP}/Secrets_Management_Cheat_Sheet.html`],
  run(ctx) {
    const pool = ctx.files.filter((f) => {
      if (LOCKFILE_RE.test(f) || ENV_FILE_RE.test(f) || ENV_TEMPLATE_RE.test(f)) return false;
      if (/\.(md|mdx|txt|snap)$/i.test(f)) return false;
      return ctx.codeFiles.includes(f) || CONFIG_FILE_RE.test(f) || /(^|\/)Dockerfile|docker-compose/i.test(f);
    });
    const findings = [];
    for (const f of pool) {
      const text = ctx.read(f);
      if (!text) continue;
      text.split(/\r?\n/).forEach((line, i) => {
        if (line.length > 2000) return; // minified / data blobs
        for (const p of SECRET_PATTERNS) {
          const m = line.match(p.re);
          if (!m) continue;
          const value = p.valueGroup ? m[p.valueGroup] : m[0];
          if (PLACEHOLDER_RE.test(value) || (p.valueGroup && PLACEHOLDER_RE.test(line))) continue;
          if (p.name.startsWith('Credentials') && /:\/\/[^:]+:(password|pass|\$)/i.test(m[0])) continue;
          findings.push(hit(f, i + 1, `${p.name}: ${mask(line, value)}`));
          break;
        }
      });
    }
    if (!findings.length) return pass(`Scanned ${pool.length} files, no secret patterns found.`);
    return fail(`${findings.length} possible secret(s) found. Values are masked in this report.`, findings);
  },
});

const envFilesIgnored = defineCheck({
  id: 'SEC-002',
  title: '.env files are git-ignored',
  severity: 'critical',
  tags: ['secrets'],
  why: 'A committed .env file is the most common way production credentials leak.',
  fix: 'Add `.env` and `.env.*` (with `!.env.example`) to .gitignore. If already committed: `git rm --cached .env`, rotate the secrets, and purge history (git filter-repo).',
  docs: [`${OWASP}/Secrets_Management_Cheat_Sheet.html`],
  run(ctx) {
    const envFiles = ctx.findFiles((f) => ENV_FILE_RE.test(f) && !ENV_TEMPLATE_RE.test(f));
    const gitignores = ctx.findFiles((f) => path.posix.basename(f) === '.gitignore');
    const rules = gitignores.flatMap((g) => (ctx.read(g) ?? '').split(/\r?\n/).map((l) => l.trim()));
    const ignoresEnv = rules.some((r) => /^\/?(\*\*\/)?\.env(\*|\.\*|\.local)?$/.test(r) || r === '*.env' || r === '.env*');

    if (!gitignores.length) return fail('No .gitignore found.', envFiles.map((f) => hit(f)));
    if (envFiles.length && !ignoresEnv) {
      return fail('.env files exist but .gitignore does not exclude them.', envFiles.map((f) => hit(f)));
    }
    if (!ignoresEnv) return warn('No .env files now, but .gitignore does not exclude them — add the rule before someone commits one.');
    return pass(envFiles.length ? `${envFiles.length} .env file(s) present and ignored.` : '.gitignore excludes .env files.');
  },
});

const envExample = defineCheck({
  id: 'SEC-003',
  title: 'Environment variables are documented (.env.example)',
  severity: 'low',
  tags: ['secrets', 'dx'],
  why: 'Without a template, people share real .env files over chat to onboard — and secrets spread.',
  fix: 'Commit a `.env.example` listing every variable with placeholder values.',
  run(ctx) {
    const usesEnv = ctx.contains(/process\.env\.|import\.meta\.env\.|Deno\.env/);
    if (!usesEnv) return skip('No environment variable usage detected.');
    const templates = ctx.findFiles((f) => ENV_FILE_RE.test(f.replace(ENV_TEMPLATE_RE, '')) && ENV_TEMPLATE_RE.test(f));
    return templates.length ? pass(`Found ${templates.join(', ')}.`) : fail('Code reads env vars but no .env.example/.env.sample exists.');
  },
});

const securityHeaders = defineCheck({
  id: 'SEC-004',
  title: 'HTTP security headers are set (CSP, HSTS, X-Frame-Options…)',
  severity: 'high',
  tags: ['http'],
  why: 'Headers like Content-Security-Policy and Strict-Transport-Security block XSS, clickjacking and protocol downgrade attacks.',
  fix: 'Express/Nest: `app.use(helmet())`. Fastify: `@fastify/helmet`. Koa: `koa-helmet`. Next.js: add `headers()` in next.config with a CSP, or set them at the CDN/reverse proxy.',
  docs: [`${OWASP}/HTTP_Headers_Cheat_Sheet.html`, 'https://helmetjs.github.io/'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No server or full-stack framework detected.');
    if (ctx.hasDep('helmet', '@fastify/helmet', 'koa-helmet', 'hono') && ctx.contains(/helmet|secureHeaders/)) {
      return pass('Helmet / secure-headers middleware in use.');
    }
    const headerFiles = ctx.findFiles(/(^|\/)(next\.config\.[cm]?[jt]s|nuxt\.config\.[jt]s|middleware\.[jt]s|vercel\.json|netlify\.toml|_headers|nginx[^/]*\.conf|Caddyfile|.*\.conf)$/);
    const hasCsp = headerFiles.some((f) => /Content-Security-Policy/i.test(ctx.read(f) ?? ''));
    const hasHsts = headerFiles.some((f) => /Strict-Transport-Security/i.test(ctx.read(f) ?? ''));
    if (hasCsp && hasHsts) return pass('CSP and HSTS configured in framework/proxy config.');
    if (hasCsp || hasHsts) return warn(`Only ${hasCsp ? 'CSP' : 'HSTS'} found — add the full set (CSP, HSTS, X-Content-Type-Options, frame-ancestors).`);
    return fail('No security header middleware or header config found.');
  },
});

const rateLimiting = defineCheck({
  id: 'SEC-005',
  title: 'Rate limiting / brute-force protection',
  severity: 'high',
  tags: ['http', 'abuse'],
  why: 'Without limits, login endpoints get brute-forced and APIs get scraped or knocked over.',
  fix: 'Add `express-rate-limit`, `rate-limiter-flexible`, `@fastify/rate-limit` or `@nestjs/throttler` (Redis-backed when you run more than one instance). Stricter limits on /login, /signup, /reset-password.',
  docs: [`${OWASP}/Denial_of_Service_Cheat_Sheet.html`],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No server or full-stack framework detected.');
    const libs = ['express-rate-limit', 'rate-limiter-flexible', '@fastify/rate-limit', '@nestjs/throttler', 'koa-ratelimit', 'express-slow-down', '@upstash/ratelimit', 'hono-rate-limiter', 'express-brute'];
    const found = libs.filter((l) => ctx.hasDep(l));
    if (found.length) return pass(`Using ${found.join(', ')}.`);
    const proxy = ctx.findFiles(/(nginx[^/]*\.conf|\.conf|Caddyfile|kong\.ya?ml|traefik[^/]*\.ya?ml)$/).find((f) => /limit_req|rate_limit|ratelimit|rateLimit/i.test(ctx.read(f) ?? ''));
    if (proxy) return pass(`Rate limiting configured at proxy (${proxy}).`);
    return fail('No rate-limiting library or proxy config found. If your API gateway/WAF does this, disable this check in devkai.config.json.');
  },
});

const corsPolicy = defineCheck({
  id: 'SEC-006',
  title: 'CORS is restricted to known origins',
  severity: 'high',
  tags: ['http'],
  why: 'A wildcard or reflected origin lets any website call your API with the user\'s browser.',
  fix: 'Pass an explicit allow-list: `cors({ origin: [\'https://app.example.com\'], credentials: true })`. Never combine `*` with credentials.',
  docs: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No server or full-stack framework detected.');
    const findings = [
      ...ctx.grep(/\bcors\s*\(\s*\)/),
      ...ctx.grep(/origin\s*:\s*(['"`]\*['"`]|true)\b/),
      ...ctx.grep(/Access-Control-Allow-Origin['"`]?\s*[,:]\s*['"`]\*['"`]/i),
      ...ctx.grep(/enableCors\s*\(\s*\)/),
    ];
    if (findings.length) return fail('Wide-open CORS configuration found.', findings);
    return pass('No wildcard CORS configuration found.');
  },
});

const inputValidation = defineCheck({
  id: 'SEC-007',
  title: 'Request input is validated with a schema',
  severity: 'medium',
  tags: ['input'],
  why: 'Unvalidated input is the root of injection, mass-assignment and crash bugs.',
  fix: 'Validate every body/query/params with zod, valibot, joi, class-validator (Nest ValidationPipe), or Fastify JSON schemas. Reject unknown fields.',
  docs: [`${OWASP}/Input_Validation_Cheat_Sheet.html`],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No server or full-stack framework detected.');
    const libs = ['zod', 'joi', 'yup', 'class-validator', 'ajv', 'express-validator', 'valibot', '@sinclair/typebox', 'superstruct', 'celebrate', '@vinejs/vine', 'arktype', 'io-ts'];
    const found = libs.filter((l) => ctx.hasDep(l));
    if (found.length) return pass(`Using ${found.join(', ')}.`);
    if (ctx.hasDep('fastify') && ctx.contains(/schema\s*:\s*\{/)) return pass('Fastify route schemas in use.');
    return fail('No schema validation library found.');
  },
});

const dangerousExec = defineCheck({
  id: 'SEC-008',
  title: 'No eval / dynamic code or shell execution with interpolated input',
  severity: 'high',
  tags: ['injection'],
  why: 'eval, new Function and shell commands built from strings turn any injection into remote code execution.',
  fix: 'Remove eval/new Function. For processes use `execFile`/`spawn` with an argument array, never `exec` with template strings.',
  docs: [`${OWASP}/OS_Command_Injection_Defense_Cheat_Sheet.html`],
  run(ctx) {
    const findings = [
      ...ctx.grep(/(^|[^.\w])eval\s*\(/),
      ...ctx.grep(/new\s+Function\s*\(/),
      ...ctx.grep(/\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|['"][^'"]*['"]\s*\+)/),
      ...ctx.grep(/\bspawn\s*\([^)]*shell\s*:\s*true/),
      ...ctx.grep(/\bvm\.(runInNewContext|runInThisContext|runInContext)\s*\(/),
    ];
    return findings.length ? fail('Dynamic code/shell execution found.', findings) : pass('No eval or string-built shell commands found.');
  },
});

const sqlInjection = defineCheck({
  id: 'SEC-009',
  title: 'SQL queries are parameterized',
  severity: 'critical',
  tags: ['injection', 'database'],
  why: 'String-built SQL is the classic path to full database compromise.',
  fix: 'Use placeholders (`query(\'… WHERE id = $1\', [id])`), the ORM query builder, or tagged templates (Prisma `$queryRaw` or a `sql` tag). Never `$queryRawUnsafe` with user input.',
  docs: [`${OWASP}/SQL_Injection_Prevention_Cheat_Sheet.html`],
  run(ctx) {
    const SQL = '(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY)';
    const findings = [
      ...ctx.grep(new RegExp(`\\.(query|execute|raw|exec|run|all|get|unsafe|whereRaw|orderByRaw|havingRaw)\\s*\\(\\s*\`[^\`]*\\b${SQL}\\b[^\`]*\\$\\{`, 'i')),
      ...ctx.grep(new RegExp(`\\.(query|execute|raw|exec|unsafe)\\s*\\(\\s*['"][^'"]*\\b${SQL}\\b[^'"]*['"]\\s*\\+`, 'i')),
      ...ctx.grep(/\$(queryRawUnsafe|executeRawUnsafe)\s*\(/),
      ...ctx.grep(/sequelize\.literal\s*\(\s*`[^`]*\$\{/),
    ];
    return findings.length ? fail('Possible SQL injection: query text built from variables.', findings) : pass('No string-built SQL found.');
  },
});

const passwordHashing = defineCheck({
  id: 'SEC-010',
  title: 'Passwords use a slow hash (argon2 / bcrypt / scrypt)',
  severity: 'high',
  tags: ['auth', 'crypto'],
  why: 'MD5/SHA hashes of passwords are cracked in minutes with GPUs once the DB leaks.',
  fix: 'Hash with argon2id (`argon2`, `@node-rs/argon2`) or bcrypt cost ≥ 12. Never md5/sha1/sha256 for passwords. Or delegate auth to an identity provider.',
  docs: [`${OWASP}/Password_Storage_Cheat_Sheet.html`],
  run(ctx) {
    const weak = ctx.grep(/createHash\s*\(\s*['"`](md5|sha1)['"`]\s*\)/i);
    const handlesPasswords = ctx.hasDep(...authDeps) || ctx.contains(/\bpassword\b/i, { files: ctx.appCodeFiles.filter((f) => !/\.(vue|svelte|jsx|tsx)$/.test(f)) });
    if (!ctx.stack.hasBackend && !weak.length) return skip('No backend detected.');
    if (weak.length) return fail('Weak hash (md5/sha1) in use — fine for checksums, never for passwords. Review each.', weak);
    if (ctx.hasDep(...authDelegatedDeps)) return pass('Authentication delegated to an identity provider.');
    if (ctx.hasDep('bcrypt', 'bcryptjs', 'argon2', '@node-rs/argon2', '@node-rs/bcrypt', '@phc/argon2') || ctx.contains(/crypto\.scrypt|scryptSync\s*\(/)) {
      return pass('Slow password hash library in use.');
    }
    return handlesPasswords ? fail('Code handles passwords but no argon2/bcrypt/scrypt found.') : skip('No password handling detected.');
  },
});

const jwtUsage = defineCheck({
  id: 'SEC-011',
  title: 'JWTs are verified safely',
  severity: 'high',
  tags: ['auth'],
  why: 'decode() skips signature checks; ignoring expiry or allowing "none" lets attackers forge tokens.',
  fix: 'Always `jwt.verify(token, key, { algorithms: [\'RS256\'] })`, keep expiry short, load the secret from env/KMS, rotate keys.',
  docs: [`${OWASP}/JSON_Web_Token_for_Java_Cheat_Sheet.html`],
  run(ctx) {
    if (!ctx.hasDep('jsonwebtoken', 'jose', '@fastify/jwt', '@nestjs/jwt', 'jwt-decode', 'express-jwt')) return skip('No JWT library in dependencies.');
    const findings = [
      ...ctx.grep(/\bjwt\.decode\s*\(/).map((h) => ({ ...h, text: `decode() without verify: ${h.text}` })),
      ...ctx.grep(/ignoreExpiration\s*:\s*true/),
      ...ctx.grep(/algorithms\s*:\s*\[[^\]]*['"`]none['"`]/i),
      ...ctx.grep(/jwt\.(sign|verify)\s*\([^,]+,\s*['"`][^'"`]+['"`]/).map((h) => ({ ...h, text: `hardcoded JWT secret: ${h.text.replace(/(['"`])[^'"`]+\1/, "'****'")}` })),
    ];
    return findings.length ? fail('Unsafe JWT handling found.', findings) : pass('No unsafe JWT patterns found.');
  },
});

const dependencyScanning = defineCheck({
  id: 'SEC-012',
  title: 'Dependencies are scanned for vulnerabilities automatically',
  severity: 'high',
  tags: ['supply-chain'],
  why: 'Most breaches come through known-vulnerable packages that were never updated.',
  fix: 'Enable Dependabot or Renovate, and run `npm audit --audit-level=high` (or Snyk / OSV-Scanner / Socket) in CI.',
  docs: ['https://docs.github.com/en/code-security/dependabot'],
  run(ctx) {
    const bots = ctx.findFiles(/^(\.github\/dependabot\.ya?ml|renovate\.json5?|\.renovaterc(\.json)?|\.github\/renovate\.json5?|\.snyk)$/);
    const ciFiles = ctx.findFiles(/^(\.github\/workflows\/.*\.ya?ml|\.gitlab-ci\.yml|\.circleci\/config\.yml|azure-pipelines\.yml|bitbucket-pipelines\.yml|Jenkinsfile)$/);
    const ciScan = ciFiles.filter((f) => /(npm|pnpm|yarn|bun) audit|snyk|osv-scanner|trivy|socket|audit-ci|dependency-review-action|codeql/i.test(ctx.read(f) ?? ''));
    if (bots.length && ciScan.length) return pass(`Update bot (${bots.join(', ')}) + CI scan (${ciScan.join(', ')}).`);
    if (bots.length || ciScan.length) return warn(`Only ${bots.length ? 'an update bot' : 'a CI scan'} found — use both: bot to update, CI to block.`);
    return fail('No Dependabot/Renovate config and no audit step in CI.');
  },
});

const lockfile = defineCheck({
  id: 'SEC-013',
  title: 'Lockfile committed (reproducible installs)',
  severity: 'medium',
  tags: ['supply-chain'],
  why: 'Without a lockfile every install can pull a different — possibly compromised — version.',
  fix: 'Commit package-lock.json / pnpm-lock.yaml / yarn.lock and use `npm ci` in CI and Docker builds.',
  run(ctx) {
    if (!ctx.apps.length) return skip('No package.json found.');
    const locks = ctx.findFiles(LOCKFILE_RE);
    return locks.length ? pass(`Found ${locks.join(', ')}.`) : fail('No lockfile found.');
  },
});

const cookieFlags = defineCheck({
  id: 'SEC-014',
  title: 'Cookies are httpOnly, secure and sameSite',
  severity: 'medium',
  tags: ['http', 'auth'],
  why: 'Session cookies readable by JavaScript or sent over HTTP are easy to steal.',
  fix: 'Set `{ httpOnly: true, secure: true, sameSite: \'lax\' }` (or strict) on session/auth cookies.',
  docs: [`${OWASP}/Session_Management_Cheat_Sheet.html`],
  run(ctx) {
    const findings = [
      ...ctx.grep(/httpOnly\s*:\s*false/i),
      ...ctx.grep(/\bsecure\s*:\s*false/),
      ...ctx.grep(/sameSite\s*:\s*['"`]?none['"`]?/i),
      ...ctx.grep(/document\.cookie\s*=\s*[^;]*(token|session|auth)/i),
    ];
    if (findings.length) return fail('Insecure cookie options found.', findings);
    if (!ctx.contains(/cookie|session/i)) return skip('No cookie/session usage found.');
    return pass('No insecure cookie flags found.');
  },
});

const tlsVerification = defineCheck({
  id: 'SEC-015',
  title: 'TLS certificate verification is not disabled',
  severity: 'high',
  tags: ['crypto', 'network'],
  why: 'Turning off verification allows man-in-the-middle attacks on every outbound call.',
  fix: 'Remove `rejectUnauthorized: false` / `NODE_TLS_REJECT_UNAUTHORIZED=0`. Provide the CA bundle with `ca:` or `NODE_EXTRA_CA_CERTS` instead.',
  run(ctx) {
    const pool = ctx.files.filter((f) => !ctx.isTestFile(f) && (ctx.codeFiles.includes(f) || CONFIG_FILE_RE.test(f) || /Dockerfile|docker-compose|\.env/.test(f)));
    const findings = [
      ...ctx.grep(/rejectUnauthorized\s*:\s*false/, { files: pool }),
      ...ctx.grep(/NODE_TLS_REJECT_UNAUTHORIZED['"]?\s*[=:]\s*['"]?0/, { files: pool }),
      ...ctx.grep(/strictSSL\s*:\s*false|insecure\s*:\s*true/, { files: pool }),
    ];
    return findings.length ? fail('TLS verification disabled.', findings) : pass('TLS verification left on.');
  },
});

const errorLeak = defineCheck({
  id: 'SEC-016',
  title: 'Stack traces / internal errors are not sent to clients',
  severity: 'medium',
  tags: ['http', 'errors'],
  why: 'Stack traces reveal file paths, library versions and query shapes — a map for attackers.',
  fix: 'Return a generic message plus a correlation id; log the full error server-side. Make sure NODE_ENV=production.',
  docs: [`${OWASP}/Error_Handling_Cheat_Sheet.html`],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const findings = ctx.grep(/(res|reply|ctx|response)\b.*\.(send|json|end|body)\b.*\b(err|error|e|ex)\.(stack|sqlMessage)\b|\bbody\s*=\s*(err|error)\.stack/);
    return findings.length ? fail('Error details sent in responses.', findings) : pass('No stack traces sent in responses.');
  },
});

const dockerNonRoot = defineCheck({
  id: 'SEC-017',
  title: 'Containers do not run as root',
  severity: 'medium',
  tags: ['container'],
  why: 'A container escape or RCE as root gives an attacker far more power on the host.',
  fix: 'Add `USER node` (or a dedicated uid) near the end of every Dockerfile; use a slim/distroless base.',
  docs: ['https://docs.docker.com/develop/develop-images/instructions/#user'],
  run(ctx) {
    const dockerfiles = ctx.findFiles(/(^|\/)Dockerfile[^/]*$/);
    if (!dockerfiles.length) return skip('No Dockerfile found.');
    const bad = dockerfiles.filter((f) => {
      const users = (ctx.read(f) ?? '').split(/\r?\n/).filter((l) => /^\s*USER\s+/i.test(l));
      const last = users.at(-1);
      return !last || /^\s*USER\s+(root|0)(\s|:|$)/i.test(last);
    });
    return bad.length ? fail('Dockerfile(s) run as root.', bad.map((f) => hit(f))) : pass(`${dockerfiles.length} Dockerfile(s) set a non-root USER.`);
  },
});

const xssSinks = defineCheck({
  id: 'SEC-018',
  title: 'No unsafe HTML injection (XSS sinks)',
  severity: 'high',
  tags: ['frontend', 'injection'],
  why: 'Rendering raw HTML from data lets attackers run script in your users\' browsers.',
  fix: 'Avoid `dangerouslySetInnerHTML` / `v-html` / `innerHTML`. If unavoidable, sanitize with DOMPurify first and add a strict CSP.',
  docs: [`${OWASP}/Cross_Site_Scripting_Prevention_Cheat_Sheet.html`],
  run(ctx) {
    const sinks = [
      ...ctx.grep(/dangerouslySetInnerHTML/),
      ...ctx.grep(/\bv-html\s*=/),
      ...ctx.grep(/\{@html\s/),
      ...ctx.grep(/\.(innerHTML|outerHTML)\s*=(?!=)/),
      ...ctx.grep(/document\.write\s*\(/),
      ...ctx.grep(/\[innerHTML\]\s*=/),
    ];
    if (!sinks.length) return pass('No raw HTML sinks found.');
    const sanitized = ctx.hasDep('dompurify', 'isomorphic-dompurify', 'sanitize-html', 'xss');
    const unsanitized = sinks.filter((s) => !/sanitize|purify|DOMPurify/i.test(s.text));
    if (sanitized && !unsanitized.length) return pass('HTML sinks pass through a sanitizer.');
    return (sanitized ? warn : fail)(`${unsanitized.length} raw HTML sink(s)${sanitized ? ' — sanitizer installed, confirm each one uses it' : ' and no sanitizer installed'}.`, unsanitized);
  },
});

// ---------- manual checks ----------

const manual = [
  {
    id: 'SEC-M01', title: 'Threat model exists for each app and is reviewed yearly', severity: 'medium',
    why: 'You cannot defend what you have not mapped: trust boundaries, data flows, attackers.',
    fix: 'Run a STRIDE session per app; keep the diagram + risks next to the code (docs/threat-model.md).',
  },
  {
    id: 'SEC-M02', title: 'Production secrets live in a secrets manager and are rotated', severity: 'high',
    why: 'Long-lived, hand-copied secrets are guaranteed to leak eventually.',
    fix: 'Use Vault / AWS Secrets Manager / GCP Secret Manager / Doppler; rotate DB and API keys on a schedule and on staff exit.',
  },
  {
    id: 'SEC-M03', title: 'HTTPS enforced everywhere, HTTP redirects, HSTS preload considered', severity: 'high',
    why: 'Any plain-HTTP hop exposes tokens and cookies.',
    fix: 'Terminate TLS at the edge, redirect 80→443, set HSTS with long max-age, use TLS 1.2+.',
  },
  {
    id: 'SEC-M04', title: 'MFA enforced for admin panels, cloud consoles, CI and git hosting', severity: 'high',
    why: 'Stolen passwords for privileged accounts bypass every code-level control.',
    fix: 'Enforce MFA/SSO org-wide (GitHub, cloud provider, CI, admin UI); prefer passkeys/hardware keys.',
  },
  {
    id: 'SEC-M05', title: 'Least privilege for DB users, IAM roles and service tokens', severity: 'high',
    why: 'An app connecting as DB owner turns a small bug into a full data wipe.',
    fix: 'Separate migration user from runtime user; scope IAM roles per service; no wildcard (*) policies.',
  },
  {
    id: 'SEC-M06', title: 'Authorization checked on every endpoint (no IDOR)', severity: 'critical',
    why: 'Broken access control is OWASP #1 — users fetching other users\' records by changing an id.',
    fix: 'Centralize authz (policy middleware/guards), check ownership on every resource read/write, add tests per role.',
  },
  {
    id: 'SEC-M07', title: 'Penetration test or DAST scan done in the last 12 months', severity: 'medium',
    why: 'Static checks miss logic flaws that a tester finds in an afternoon.',
    fix: 'Run OWASP ZAP in CI against staging; commission an external pentest before major launches.',
  },
  {
    id: 'SEC-M08', title: 'Security incident response plan exists and was rehearsed', severity: 'medium',
    why: 'In a breach, hours lost deciding who does what cost data and trust (and GDPR fines: 72h notice).',
    fix: 'Write a one-page runbook: contacts, severity levels, key rotation steps, customer comms. Do a tabletop drill.',
  },
  {
    id: 'SEC-M09', title: 'Personal data is classified, minimized and encrypted at rest', severity: 'high',
    why: 'Data you do not store cannot leak; what you store must be protected and deletable on request.',
    fix: 'Inventory PII per app, enable DB/disk encryption, encrypt sensitive columns, define retention and deletion.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'security',
  title: 'Security',
  description: 'Secrets, HTTP hardening, injection, auth, supply chain and container safety — based on OWASP ASVS / Top 10.',
  checks: [
    hardcodedSecrets, envFilesIgnored, envExample, securityHeaders, rateLimiting, corsPolicy,
    inputValidation, dangerousExec, sqlInjection, passwordHashing, jwtUsage, dependencyScanning,
    lockfile, cookieFlags, tlsVerification, errorLeak, dockerNonRoot, xssSinks,
    ...reviewChecks,
    ...manual,
  ],
});
