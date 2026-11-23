import fs from 'node:fs';
import path from 'node:path';
import { stripComments, lineIndex } from './lexer.js';

const DEFAULT_IGNORE = [
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.nuxt', '.output',
  'out', '.turbo', '.cache', 'vendor', '.vercel', '.svelte-kit', 'tmp',
];

const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.avif', '.bmp', '.svgz',
  '.woff', '.woff2', '.ttf', '.eot', '.otf', '.pdf', '.zip', '.gz', '.tgz', '.rar',
  '.7z', '.mp3', '.mp4', '.mov', '.webm', '.wav', '.exe', '.dll', '.so', '.dylib',
  '.bin', '.lockb', '.sqlite', '.db', '.jar', '.class', '.pyc', '.wasm',
]);

const CODE_EXT = new Set(['.js', '.cjs', '.mjs', '.ts', '.cts', '.mts', '.jsx', '.tsx', '.vue', '.svelte']);

const MAX_FILE_BYTES = 1024 * 1024;

// Tests, fixtures and load/benchmark scripts are not application code.
const TEST_FILE_RE = /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|fixtures?|cypress|playwright|load-?tests?|perf|k6|benchmarks?|bench)\/|\.(test|spec|e2e|k6|bench)\.[cm]?[jt]sx?$/i;

const SERVER_FRAMEWORKS = {
  express: 'Express',
  fastify: 'Fastify',
  koa: 'Koa',
  '@nestjs/core': 'NestJS',
  '@hapi/hapi': 'hapi',
  hono: 'Hono',
  'restify': 'Restify',
  '@adonisjs/core': 'AdonisJS',
};

const FULLSTACK_FRAMEWORKS = {
  next: 'Next.js',
  nuxt: 'Nuxt',
  '@remix-run/node': 'Remix',
  '@sveltejs/kit': 'SvelteKit',
  astro: 'Astro',
};

const FRONTEND_LIBS = {
  react: 'React',
  vue: 'Vue',
  svelte: 'Svelte',
  '@angular/core': 'Angular',
  'solid-js': 'Solid',
  'react-native': 'React Native',
  expo: 'Expo',
};

const DATA_LIBS = {
  prisma: 'Prisma', '@prisma/client': 'Prisma', typeorm: 'TypeORM', sequelize: 'Sequelize',
  mongoose: 'Mongoose', 'drizzle-orm': 'Drizzle', knex: 'Knex', pg: 'node-postgres',
  mysql2: 'mysql2', mongodb: 'MongoDB driver', '@mikro-orm/core': 'MikroORM',
  redis: 'Redis', ioredis: 'Redis',
};

function walk(root, ignore) {
  const out = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(path.join(root, rel), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (ignore.some((pattern) => matchesIgnore(childRel, e.name, pattern))) continue;
      if (e.isDirectory()) stack.push(childRel);
      else if (e.isFile()) out.push(childRel);
    }
  }
  return out.sort();
}

function matchesIgnore(rel, name, pattern) {
  if (!pattern.includes('/')) return name === pattern;
  const p = pattern.replace(/\/$/, '');
  return rel === p || rel.startsWith(`${p}/`);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function pickNames(deps, table) {
  return [...new Set(Object.keys(table).filter((d) => deps.has(d)).map((d) => table[d]))];
}

/**
 * Build the read-only view of a project that every check receives.
 * @param {string} rootDir
 * @param {{ ignore?: string[] }} [config]
 * @param {{ review?: boolean, offline?: boolean, scope?: string }} [options]
 *   review: comment-aware, multi-line matching with code context (slower, more precise)
 *   scope:  an app directory (e.g. "apps/api"). The context then contains that app's files plus
 *           shared repo files (CI, root config, infra) — but not the files of other apps — and
 *           only that app's and the root package's dependencies.
 */
export function createContext(rootDir, config = {}, options = {}) {
  const review = Boolean(options.review);
  const root = path.resolve(rootDir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    throw new Error(`Not a directory: ${root}`);
  }

  const ignore = [...DEFAULT_IGNORE, ...(config.ignore ?? [])];
  const allFiles = walk(root, ignore);

  // Every package.json is an "app" (monorepo friendly).
  const repoApps = allFiles
    // Sample projects under fixtures/mocks are test data, not apps of this repo.
    .filter((f) => path.posix.basename(f) === 'package.json' && !/(^|\/)(fixtures?|__fixtures__|__mocks__|examples?-?fixtures?)\//.test(f))
    .map((f) => {
      const pkg = readJson(path.join(root, f)) ?? {};
      const dir = path.posix.dirname(f);
      return { name: pkg.name ?? (dir === '.' ? path.basename(root) : dir), dir, pkg };
    });

  const scope = options.scope && options.scope !== '.' ? options.scope.replace(/\/$/, '') : null;
  if (scope && !repoApps.some((a) => a.dir === scope)) throw new Error(`No package.json in ${scope}`);
  const appDirs = repoApps.map((a) => a.dir).filter((d) => d !== '.').sort((a, b) => b.length - a.length);
  /** The app a file belongs to: the deepest app directory containing it, or "." for shared repo files. */
  const ownerOf = (f) => appDirs.find((d) => f.startsWith(`${d}/`)) ?? '.';

  const files = scope ? allFiles.filter((f) => { const o = ownerOf(f); return o === scope || o === '.'; }) : allFiles;
  const apps = scope ? repoApps.filter((a) => a.dir === scope || a.dir === '.') : repoApps;
  const fileSet = new Set(files);
  const cache = new Map();

  const deps = new Set();
  const prodDeps = new Set(); // shipped to production (not devDependencies)
  for (const { pkg } of apps) {
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      for (const d of Object.keys(pkg[field] ?? {})) {
        deps.add(d);
        if (field !== 'devDependencies') prodDeps.add(d);
      }
    }
  }

  const rootPkg = apps.find((a) => a.dir === '.')?.pkg ?? null;

  const read = (rel) => {
    if (cache.has(rel)) return cache.get(rel);
    let text = null;
    if (fileSet.has(rel) && !BINARY_EXT.has(path.posix.extname(rel).toLowerCase())) {
      try {
        const abs = path.join(root, rel);
        if (fs.statSync(abs).size <= MAX_FILE_BYTES) text = fs.readFileSync(abs, 'utf8');
      } catch {
        text = null;
      }
    }
    cache.set(rel, text);
    return text;
  };

  const isTestFile = (rel) => TEST_FILE_RE.test(rel);
  const isCodeFile = (rel) => CODE_EXT.has(path.posix.extname(rel).toLowerCase()) && !/\.min\.js$/.test(rel) && !rel.endsWith('.d.ts');
  const codeFiles = files.filter(isCodeFile);
  const appCodeFiles = codeFiles.filter((f) => !isTestFile(f));

  const hasDep = (...names) => names.some((n) => deps.has(n));

  const stack = {
    server: pickNames(deps, SERVER_FRAMEWORKS),
    fullstack: pickNames(deps, FULLSTACK_FRAMEWORKS),
    frontend: pickNames(deps, FRONTEND_LIBS),
    data: pickNames(deps, DATA_LIBS),
    typescript: deps.has('typescript') || files.some((f) => f.endsWith('tsconfig.json')),
    docker: files.some((f) => /(^|\/)Dockerfile[^/]*$/.test(f)),
    ci: files.some((f) => f.startsWith('.github/workflows/') || f === '.gitlab-ci.yml' || f.startsWith('.circleci/') || f === 'azure-pipelines.yml' || f === 'Jenkinsfile' || f === 'bitbucket-pipelines.yml'),
  };
  // Also catch raw node:http servers.
  if (!stack.server.length && appCodeFiles.some((f) => /\b(http|https)\.createServer\s*\(/.test(read(f) ?? ''))) {
    stack.server.push('node:http');
  }
  stack.hasBackend = stack.server.length > 0 || stack.fullstack.length > 0;

  const codeCache = new Map();
  /** Source with comments blanked out (same offsets/lines). Non-JS files returned as-is. */
  const code = (rel) => {
    if (codeCache.has(rel)) return codeCache.get(rel);
    const text = read(rel);
    const out = text && isCodeFile(rel) ? stripComments(text) : text;
    codeCache.set(rel, out);
    return out;
  };

  const contextLines = (lines, lineNo, radius = 2) => {
    const from = Math.max(1, lineNo - radius);
    const to = Math.min(lines.length, lineNo + radius);
    const ctxLines = [];
    for (let l = from; l <= to; l++) ctxLines.push({ line: l, text: lines[l - 1] });
    return ctxLines;
  };

  /**
   * Search files.
   * Quick mode: plain regex, line by line.
   * Review mode: ignores comments, matches across line breaks, attaches surrounding code.
   * @param {RegExp} regex
   * @param {{ files?: string[], filter?: (rel: string) => boolean, limit?: number }} [opts]
   * @returns {{ file: string, line: number, text: string, match: string, context?: {line:number,text:string}[] }[]}
   */
  const grep = (regex, opts = {}) => {
    const re = new RegExp(regex.source, regex.flags.replace('g', ''));
    const pool = (opts.files ?? appCodeFiles).filter(opts.filter ?? (() => true));
    const limit = opts.limit ?? Infinity;
    const hits = [];
    for (const f of pool) {
      const text = review ? code(f) : read(f);
      if (!text) continue;
      if (!re.test(text)) continue; // fast reject
      const original = (read(f) ?? '').split(/\r?\n/);

      if (review) {
        const g = new RegExp(re.source, `${re.flags}g`);
        const lineOf = lineIndex(text);
        const seen = new Set();
        let m;
        while ((m = g.exec(text))) {
          if (m[0] === '') { g.lastIndex++; continue; }
          const line = lineOf(m.index);
          if (seen.has(line)) continue;
          seen.add(line);
          hits.push({ file: f, line, text: original[line - 1] ?? '', match: m[0], context: contextLines(original, line) });
          if (hits.length >= limit) return hits;
        }
        continue;
      }

      for (let i = 0; i < original.length; i++) {
        const m = original[i].match(re);
        if (m) {
          hits.push({ file: f, line: i + 1, text: original[i], match: m[0] });
          if (hits.length >= limit) return hits;
        }
      }
    }
    return hits;
  };

  /** Build a finding at a file/line, with context in review mode. */
  const at = (file, line, text) => {
    const original = (read(file) ?? '').split(/\r?\n/);
    const finding = { file, line, text: text ?? original[line - 1] ?? '' };
    if (review) finding.context = contextLines(original, line);
    return finding;
  };

  /** True if any file in the pool contains the pattern. */
  const contains = (regex, opts = {}) => grep(regex, { ...opts, limit: 1 }).length > 0;

  const findFiles = (pattern) => files.filter((f) => (typeof pattern === 'function' ? pattern(f) : pattern.test(f)));

  return {
    root,
    name: scope ? (repoApps.find((a) => a.dir === scope)?.name ?? scope) : (rootPkg?.name ?? path.basename(root)),
    scope: scope ?? '.',
    review,
    offline: Boolean(options.offline),
    rootPkg,
    apps,
    /** Every package in the repository, regardless of scope (for repo-level checks). */
    repoApps,
    ownerOf,
    deps,
    prodDeps,
    files,
    codeFiles,
    appCodeFiles,
    stack,
    exists: (rel) => fileSet.has(rel),
    read,
    code,
    at,
    hasDep,
    grep,
    contains,
    findFiles,
    isTestFile,
  };
}
