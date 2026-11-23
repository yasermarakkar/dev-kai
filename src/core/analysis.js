/**
 * Lightweight static analysis for --review mode:
 *  - taint tracking (request input → variables → sinks), file scoped
 *  - HTTP route inventory (Express/Koa/Fastify/Hono style, NestJS, Next.js)
 *
 * Heuristic by design: no type info, no cross-file flow. Precise enough to
 * point a reviewer at the right lines, cheap enough to run on every commit.
 */
import { extractArgs, lineIndex } from './lexer.js';

const SOURCE_RE = /\b(req|request|ctx\.request|c\.req)\.(body|query|params|headers|cookies|files?)\b|\bsearchParams\.get\s*\(|\b(await\s+)?(req|request|c\.req)\.(json|formData|text)\s*\(\s*\)|\bctx\.(query|params)\b|\bevent\.(body|queryStringParameters|pathParameters)\b/;

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function namesFromPattern(pattern) {
  // `{ a, b: c, d = 1, ...rest }` or `[a, b]` → [a, c, d, rest]
  return pattern
    .replace(/^[{[]|[}\]]$/g, '')
    .split(',')
    .map((p) => p.trim().replace(/^\.\.\./, ''))
    .map((p) => (p.includes(':') ? p.split(':')[1] : p))
    .map((p) => p.split('=')[0].trim())
    .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p));
}

/**
 * Names in a file that (transitively) hold request input.
 * @param {string} code comment-stripped source
 */
export function taintedNames(code) {
  const tainted = new Set();
  const decl = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*|\{[^}]*\}|\[[^\]]*\])\s*=\s*([^;\n]+)/g;
  const assigns = [];
  let m;
  while ((m = decl.exec(code))) assigns.push({ target: m[1], rhs: m[2] });
  // Handler params commonly named after the request body, e.g. ({ body }) => …
  for (let round = 0; round < 4; round++) {
    const before = tainted.size;
    const nameRe = tainted.size ? new RegExp(`\\b(${[...tainted].map(escapeRe).join('|')})\\b`) : null;
    for (const { target, rhs } of assigns) {
      if (SOURCE_RE.test(rhs) || (nameRe && nameRe.test(rhs))) {
        const names = /^[{[]/.test(target) ? namesFromPattern(target) : [target];
        names.forEach((n) => tainted.add(n));
      }
    }
    if (tainted.size === before) break;
  }
  return tainted;
}

export function makeTaintTest(tainted) {
  const nameRe = tainted.size ? new RegExp(`(^|[^\\w$.])(${[...tainted].map(escapeRe).join('|')})\\b`) : null;
  return (expr) => SOURCE_RE.test(expr) || Boolean(nameRe && nameRe.test(expr));
}

/** Is this argument string built from tainted data (interpolation / concat / direct)? */
export function argIsTainted(arg, isTainted) {
  if (!arg) return false;
  if (arg.startsWith('`')) {
    const exprs = [...arg.matchAll(/\$\{([^}]*)\}/g)].map((x) => x[1]);
    return exprs.some(isTainted);
  }
  return isTainted(arg);
}

export const SINKS = [
  { kind: 'SQL injection', re: /\.(query|execute|raw|unsafe|exec|run|all|whereRaw|orderByRaw|havingRaw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(/g, arg: 0, requireBuilt: true },
  { kind: 'Command injection', re: /\b(exec|execSync)\s*\(/g, arg: 0 },
  { kind: 'Code injection', re: /(^|[^.\w])(eval|Function)\s*\(|\bvm\.run\w*\s*\(/g, arg: 0 },
  { kind: 'Path traversal', re: /\b(fs|fsp|promises)\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|unlink|unlinkSync|rm|rmSync|readdir|stat|access)\s*\(|\bres\.(sendFile|download)\s*\(/g, arg: 0 },
  { kind: 'Open redirect', re: /\b(res|reply|ctx|response)\.redirect\s*\(|(^|[^.\w])redirect\s*\(|Response\.redirect\s*\(/g, arg: -1 },
  { kind: 'SSRF', re: /(^|[^.\w])fetch\s*\(|\baxios(\.(get|post|put|patch|delete|request))?\s*\(|\bgot(\.(get|post))?\s*\(|\bhttps?\.(get|request)\s*\(|\bneedle\s*\(|\bsuperagent\.(get|post)\s*\(/g, arg: 0, hostOnly: true },
  { kind: 'NoSQL operator injection', re: /\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate)\s*\(/g, arg: 0, direct: true },
  { kind: 'Reflected XSS', re: /\b(res|reply)\.(send|end|write)\s*\(/g, arg: 0, requireHtml: true },
];

/**
 * Find request input reaching dangerous sinks.
 * @returns {{ kind: string, index: number, line: number, arg: string }[]}
 */
export function findTaintedSinks(code) {
  const tainted = taintedNames(code);
  const isTainted = makeTaintTest(tainted);
  if (!SOURCE_RE.test(code) && !tainted.size) return [];
  const lineOf = lineIndex(code);
  const hits = [];
  for (const sink of SINKS) {
    const re = new RegExp(sink.re.source, 'g');
    let m;
    while ((m = re.exec(code))) {
      const open = m.index + m[0].lastIndexOf('(');
      const { args } = extractArgs(code, open);
      const arg = sink.arg === -1 ? args.at(-1) : args[sink.arg];
      if (!arg) continue;
      let bad;
      if (sink.direct) bad = /^\s*(req|request|ctx\.request)\.(body|query|params)\s*$/.test(arg) || /:\s*(req|request)\.(body|query)\.\w+\s*[},]/.test(arg);
      else if (sink.requireBuilt) bad = (arg.startsWith('`') || /['"]\s*\+|\+\s*['"]/.test(arg)) && argIsTainted(arg, isTainted);
      // SSRF only when the attacker controls scheme/host, not just a path segment
      else if (sink.hostOnly) bad = arg.startsWith('`') ? /^`\$\{([^}]*)\}/.test(arg) && isTainted(arg.match(/^`\$\{([^}]*)\}/)[1]) : !/^['"]/.test(arg) && isTainted(arg);
      else if (sink.requireHtml) bad = arg.startsWith('`') && /</.test(arg) && argIsTainted(arg, isTainted);
      else bad = argIsTainted(arg, isTainted);
      if (bad) hits.push({ kind: sink.kind, index: m.index, line: lineOf(m.index), arg: arg.replace(/\s+/g, ' ').slice(0, 120) });
    }
  }
  return hits;
}

// ---------------- routes ----------------

const AUTH_NAME_RE = /auth|protect|guard|jwt|passport|session|requireUser|isLogged|ensureLogged|loggedIn|verifyToken|verifyUser|clerk|requireRole|hasRole|permit|authorize|acl|rbac|can\(|apiKey/i;
export const PUBLIC_PATH_RE = /(login|signin|sign-in|signup|sign-up|register|logout|webhook|health|healthz|status|ready|readyz|live|livez|callback|oauth|forgot|reset|verify|public|csp-report|metrics|token|refresh)/i;

/**
 * Inventory state-changing routes in one file.
 * @returns {{ method: string, path: string, line: number, protected: boolean, framework: string }[]}
 */
export function findRoutes(file, code) {
  const routes = [];
  const lineOf = lineIndex(code);

  // Express / Koa-router / Fastify shorthand / Hono: app.post('/x', mw, handler)
  const re = /\b([A-Za-z_$][\w$]*)\.(post|put|patch|delete|del)\s*\(\s*(['"`])([^'"`]*)\3/g;
  let m;
  const fileUsesAuth = [...code.matchAll(/\.use\s*\(/g)].map((u) => {
    const { args } = extractArgs(code, u.index + u[0].length - 1);
    return { index: u.index, auth: args.some((a) => AUTH_NAME_RE.test(a)), path: (args[0]?.match(/^['"`]([^'"`]*)/) ?? [])[1] };
  }).filter((u) => u.auth);
  while ((m = re.exec(code))) {
    if (/^(axios|http|https|got|request|superagent|fetch|api|client|ky|\$http|this)$/i.test(m[1])) continue; // HTTP clients
    const open = m.index + m[0].indexOf('(');
    const { args } = extractArgs(code, open);
    const middle = args.slice(1, -1).join(',');
    const options = args.slice(1).join(',');
    const local = AUTH_NAME_RE.test(middle) || /preHandler|onRequest|preValidation/.test(options) && AUTH_NAME_RE.test(options);
    const viaUse = fileUsesAuth.some((u) => u.index < m.index && (!u.path || m[4].startsWith(u.path)));
    routes.push({ method: m[2] === 'del' ? 'DELETE' : m[2].toUpperCase(), path: m[4], line: lineOf(m.index), protected: local || viaUse, framework: 'express-like' });
  }

  // NestJS decorators
  if (/@Controller\s*\(/.test(code)) {
    const guarded = /@UseGuards\s*\(/.test(code);
    const dec = /@(Post|Put|Patch|Delete)\s*\(\s*(?:['"`]([^'"`]*)['"`])?/g;
    while ((m = dec.exec(code))) {
      const window = code.slice(Math.max(0, m.index - 300), m.index + 300);
      const isPublic = /@(Public|AllowAnonymous|SkipAuth)\s*\(/.test(window);
      routes.push({ method: m[1].toUpperCase(), path: m[2] ?? '', line: lineOf(m.index), protected: guarded || isPublic, framework: 'nestjs' });
    }
  }

  // Next.js App Router route handlers and Pages API routes
  const isAppRoute = /(^|\/)app\/(.*\/)?route\.[cm]?[jt]sx?$/.test(file);
  const isPagesApi = /(^|\/)pages\/api\//.test(file);
  if (isAppRoute || isPagesApi) {
    const hasAuthCall = /getServerSession|\bauth\s*\(\s*\)|currentUser|getAuth|getToken|requireAuth|withAuth|getUser|getSession|verifyToken|clerkClient|validateRequest/.test(code);
    const urlPath = `/${file.replace(/^.*?(app|pages)\//, '').replace(/\/?(route|index)?\.[cm]?[jt]sx?$/, '').replace(/^api\/?/, 'api/')}`;
    const methods = isAppRoute
      ? [...code.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(POST|PUT|PATCH|DELETE)\b/g)]
      : [...code.matchAll(/req\.method\s*===?\s*['"`](POST|PUT|PATCH|DELETE)['"`]/g)];
    for (const x of methods) {
      routes.push({ method: x[1], path: urlPath, line: lineOf(x.index), protected: hasAuthCall, framework: 'nextjs' });
    }
  }
  return routes;
}

export { SOURCE_RE };
