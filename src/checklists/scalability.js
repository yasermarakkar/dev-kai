import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';
import { extractArgs, lineIndex } from '../core/lexer.js';

// ---------- shared ----------

const REDIS = ['redis', 'ioredis', '@upstash/redis', '@redis/client', '@vercel/kv', 'memcached', 'memjs', '@keyv/redis', 'cache-manager-redis-store', 'cache-manager-ioredis-yet', '@nestjs/cache-manager', 'valkey', 'iovalkey'];
const QUEUES = ['bullmq', 'bull', 'bee-queue', 'agenda', 'pg-boss', 'graphile-worker', '@aws-sdk/client-sqs', 'sqs-consumer', 'amqplib', 'amqp-connection-manager', 'kafkajs', '@confluentinc/kafka-javascript', '@google-cloud/pubsub', '@azure/service-bus', 'inngest', '@trigger.dev/sdk', '@temporalio/client', '@nestjs/bull', '@nestjs/bullmq', 'nats', '@upstash/qstash', 'rabbitmq-client'];
const HTTP_CLIENT_CALL = /(^|[^.\w])fetch\s*\(|\baxios(\.(get|post|put|patch|delete|request|head))?\s*\(|\bgot(\.(get|post|put|patch|delete))?\s*\(|\bky(\.(get|post|put|patch|delete))?\s*\(|\bundici\.request\s*\(|\bneedle\s*\(|\bsuperagent\.(get|post|put|delete)\s*\(|\bhttps?\.(get|request)\s*\(/;
const WORKER_FILE = /(^|\/)(workers?|jobs?|queues?|cron|scheduler|tasks?|consumers?)\/|(worker|job|cron|scheduler|consumer)\.[cm]?[jt]s$/i;

const longRunning = (ctx) => ctx.stack.server.length > 0;

/** All HTTP route handlers (any method) in a file: [{ line, body }]. */
function routeHandlers(code) {
  const lineOf = lineIndex(code);
  const out = [];
  const re = /\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|all)\s*\(\s*['"`][^'"`]*['"`]/g;
  let m;
  while ((m = re.exec(code))) {
    if (/^(axios|http|https|got|ky|request|superagent|client|api|this|map|cache|headers|params|searchParams|res|req|config|process|store|redis|db|prisma)$/i.test(m[1])) continue;
    const open = m.index + m[0].indexOf('(');
    const { args } = extractArgs(code, open);
    const body = args.at(-1);
    if (body && /=>|function/.test(body)) out.push({ line: lineOf(m.index), body, offset: code.indexOf(body, open) });
  }
  return out;
}

// ---------- quick checks ----------

const sessions = defineCheck({
  id: 'SCL-001',
  title: 'Sessions live in a shared store, not process memory',
  severity: 'high',
  tags: ['stateless'],
  why: 'express-session\'s default MemoryStore keeps sessions inside one process: users get logged out whenever the load balancer sends them to another replica or the pod restarts — and it leaks memory.',
  fix: 'Use a shared store (connect-redis, connect-pg-simple, connect-mongo, @quixo3/prisma-session-store) or stateless tokens (JWT with short expiry + refresh).',
  run(ctx) {
    if (!ctx.hasDep('express-session', 'koa-session', '@fastify/session', '@fastify/secure-session', 'cookie-session', 'iron-session')) return skip('No server-side session library.');
    if (ctx.hasDep('cookie-session', '@fastify/secure-session', 'iron-session')) return pass('Session stored in a signed/encrypted cookie (stateless).');
    const stores = ['connect-redis', 'connect-pg-simple', 'connect-mongo', 'connect-session-sequelize', '@quixo3/prisma-session-store', 'connect-mongodb-session', 'connect-dynamodb', 'koa-redis', '@fastify/redis', 'connect-session-knex'].filter((s) => ctx.hasDep(s));
    if (stores.length && ctx.contains(/\bstore\s*:/)) return pass(`Session store: ${stores.join(', ')}.`);
    const usages = ctx.grep(/\b(session|expressSession|koaSession)\s*\(\s*\{/);
    return fail(ctx.hasDep('memorystore') ? 'memorystore is still per-process memory.' : 'Sessions use the default in-memory store.', usages);
  },
});

const uploads = defineCheck({
  id: 'SCL-002',
  title: 'Uploaded files go to object storage, not the local disk',
  severity: 'medium',
  tags: ['stateless', 'storage'],
  why: 'Files written to a container\'s disk are invisible to other replicas and lost on every redeploy.',
  fix: 'Stream uploads to S3 / GCS / Azure Blob / R2 (multer-s3, @aws-sdk/lib-storage, presigned URLs for direct browser uploads).',
  run(ctx) {
    const local = [
      ...ctx.grep(/multer\s*\(\s*\{[^}]*\bdest\s*:|multer\.diskStorage\s*\(/),
      ...ctx.grep(/\b(uploadDir|uploadsDir)\s*:|formidable\s*\(\s*\{[^}]*uploadDir/),
      ...ctx.grep(/\b(writeFile|writeFileSync|createWriteStream)\s*\(\s*[^,)]*['"`][^'"`]*(uploads?|public\/files|tmp\/files)\//),
    ];
    const objectStorage = ctx.hasDep('@aws-sdk/client-s3', '@aws-sdk/lib-storage', 'aws-sdk', 'multer-s3', '@google-cloud/storage', '@azure/storage-blob', 'minio', '@vercel/blob', 'uploadthing', 'cloudinary', '@supabase/storage-js');
    if (local.length) return fail('Uploads written to local disk.', unique(local));
    if (ctx.hasDep('multer', 'formidable', 'busboy', '@fastify/multipart', 'koa-body')) {
      return objectStorage ? pass('Uploads go to object storage.') : warn('Upload parser installed but no object storage SDK — check where files end up.');
    }
    return skip('No file upload handling found.');
  },
});

const gracefulShutdown = defineCheck({
  id: 'SCL-003',
  title: 'Graceful shutdown drains in-flight requests on SIGTERM',
  severity: 'high',
  tags: ['deploys', 'load-balancing'],
  why: 'Every deploy and scale-down sends SIGTERM. Without draining, requests in flight are cut off and users see 502s.',
  fix: 'On SIGTERM: fail readiness, stop accepting (`server.close()` / `app.close()`), wait for in-flight requests, close DB/queues, then exit. NestJS: `app.enableShutdownHooks()`. Or use @godaddy/terminus / lightship / http-terminator.',
  docs: ['https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/'],
  run(ctx) {
    if (!longRunning(ctx)) return skip('No long-running server (serverless/framework platforms handle this).');
    if (ctx.hasDep('@godaddy/terminus', 'lightship', 'http-terminator', 'stoppable', 'http-graceful-shutdown', 'close-with-grace') || ctx.contains(/enableShutdownHooks\s*\(|closeWithGrace\s*\(/)) return pass('Shutdown library / hooks in use.');
    const signal = ctx.contains(/process\.(on|once)\s*\(\s*['"`]SIGTERM/);
    const closes = ctx.contains(/\b(server|app|httpServer|fastify|instance)\.close\s*\(/);
    if (signal && closes) return pass('SIGTERM handler closes the server.');
    if (signal) return warn('SIGTERM handled but the HTTP server is not closed — in-flight requests may be cut.');
    return fail('No SIGTERM handling.');
  },
});

const outboundTimeouts = defineCheck({
  id: 'SCL-004',
  title: 'Outbound HTTP calls have timeouts',
  severity: 'high',
  tags: ['resilience'],
  why: 'Default fetch/axios wait forever. One slow downstream service fills your event loop with pending calls and takes every app that depends on you down with it.',
  fix: 'axios: `axios.create({ timeout: 5000 })`. fetch: `fetch(url, { signal: AbortSignal.timeout(5000) })`. got/ky: `timeout`. Pair with retries + backoff for idempotent calls.',
  run(ctx) {
    const calls = ctx.grep(HTTP_CLIENT_CALL);
    if (!calls.length) return skip('No outbound HTTP calls found.');
    const hasTimeout = ctx.contains(/\btimeout\s*:\s*\{?\s*[\w.]+|AbortSignal\.timeout\s*\(|axios\.defaults\.timeout|headersTimeout|bodyTimeout|setTimeout\s*\(\s*\(\)\s*=>\s*\w*\.abort/);
    if (!hasTimeout) return fail(`${calls.length} outbound call(s), no timeout configured anywhere.`, calls);
    return pass('Timeouts configured for outbound calls (run --review for per-call coverage).');
  },
});

const serverTimeouts = defineCheck({
  id: 'SCL-005',
  title: 'Server keep-alive and request timeouts match the load balancer',
  severity: 'medium',
  tags: ['load-balancing'],
  why: 'If Node closes idle keep-alive sockets before the load balancer does (ALB default 60 s, Node default 5 s), the LB reuses a dead socket and returns random 502s.',
  fix: 'Set `server.keepAliveTimeout` above the LB idle timeout (e.g. 65 000) and `server.headersTimeout` slightly higher; set `server.requestTimeout` to bound slow clients. Fastify: `keepAliveTimeout`, `connectionTimeout`.',
  docs: ['https://nodejs.org/api/http.html#serverkeepalivetimeout'],
  run(ctx) {
    if (!longRunning(ctx)) return skip('No long-running Node server.');
    const keepAlive = ctx.contains(/keepAliveTimeout\s*[:=]/);
    const req = ctx.contains(/requestTimeout\s*[:=]|headersTimeout\s*[:=]|connectionTimeout\s*[:=]|server\.setTimeout\s*\(|\.timeout\s*=\s*\d/);
    if (keepAlive && req) return pass('Keep-alive and request timeouts set.');
    if (keepAlive || req) return warn(`Only ${keepAlive ? 'keepAliveTimeout' : 'request/headers timeout'} set.`);
    return fail('Server timeouts left at Node defaults.');
  },
});

const caching = defineCheck({
  id: 'SCL-006',
  title: 'A shared cache or HTTP caching reduces repeated work',
  severity: 'medium',
  tags: ['caching', 'performance'],
  why: 'Without caching every request hits the database; in-process caches are duplicated per replica and go stale independently.',
  fix: 'Cache hot reads in Redis/Valkey (with TTL and explicit invalidation) and set `Cache-Control` / `s-maxage` so CDNs serve public content. Next.js: `revalidate`/`unstable_cache`.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const shared = REDIS.filter((r) => ctx.hasDep(r));
    const http = ctx.contains(/Cache-Control|s-maxage|stale-while-revalidate|export\s+const\s+revalidate|unstable_cache|\bcacheLife\s*\(|"use cache"|'use cache'/);
    if (shared.length) return pass(`Shared cache: ${shared.join(', ')}${http ? ' + HTTP caching' : ''}.`);
    if (http) return pass('HTTP caching headers in use.');
    if (ctx.hasDep('lru-cache', 'node-cache', 'memory-cache', 'quick-lru', 'cache-manager')) return warn('Only in-process caching — each replica has its own copy; use Redis for shared data.');
    return fail('No caching layer or cache headers found.');
  },
});

const backgroundJobs = defineCheck({
  id: 'SCL-007',
  title: 'Scheduled/background work runs once, not on every replica',
  severity: 'medium',
  tags: ['jobs'],
  why: 'A `setInterval` or node-cron job inside the web process runs on every replica: 5 pods = 5 invoice emails. It also competes with requests for CPU.',
  fix: 'Move jobs to a queue (BullMQ, pg-boss, SQS, Cloud Tasks) consumed by a separate worker, use platform cron (K8s CronJob, Cloud Scheduler), or guard with a distributed lock (Redlock, pg advisory lock).',
  run(ctx) {
    const queues = QUEUES.filter((q) => ctx.hasDep(q));
    const inProcess = ctx.grep(/\bcron\.schedule\s*\(|new\s+CronJob\s*\(|schedule\.scheduleJob\s*\(|\bsetInterval\s*\(|@Cron\s*\(|@Interval\s*\(|toad-scheduler|new\s+SimpleIntervalJob/, { filter: (f) => !WORKER_FILE.test(f) && !/\.(jsx|tsx|vue|svelte)$/.test(f) });
    const locked = ctx.contains(/redlock|Redlock|pg_try_advisory_lock|advisory_lock|acquireLock|withLock|leaderElection|isLeader/);
    if (inProcess.length && !locked) {
      return (queues.length ? warn : fail)(`${inProcess.length} timer/cron job(s) inside the web process without a lock${queues.length ? ' (a queue exists — move them there)' : ''}.`, inProcess);
    }
    if (queues.length) return pass(`Background work via ${queues.join(', ')}.`);
    if (inProcess.length) return pass('In-process schedules are guarded by a distributed lock.');
    return skip('No background or scheduled work found.');
  },
});

const sharedRateLimit = defineCheck({
  id: 'SCL-008',
  title: 'Rate limits are shared across replicas',
  severity: 'medium',
  tags: ['load-balancing', 'abuse'],
  why: 'With an in-memory rate-limit store, N replicas allow N× the limit, and counts reset on every deploy.',
  fix: 'Back the limiter with Redis: express-rate-limit + `rate-limit-redis`, rate-limiter-flexible `RateLimiterRedis`, @fastify/rate-limit `redis:`, @nestjs/throttler with a Redis storage — or enforce limits at the gateway.',
  run(ctx) {
    const libs = ['express-rate-limit', 'rate-limiter-flexible', '@fastify/rate-limit', '@nestjs/throttler', 'koa-ratelimit', 'express-slow-down'];
    if (!libs.some((l) => ctx.hasDep(l))) return skip(ctx.hasDep('@upstash/ratelimit') ? 'Upstash rate limiting is Redis-backed.' : 'No in-app rate limiter (see SEC-005).');
    const shared = ctx.hasDep('rate-limit-redis', '@nest-lab/throttler-storage-redis', 'nestjs-throttler-storage-redis', '@upstash/ratelimit')
      || ctx.contains(/RateLimiter(Redis|Postgres|Mongo|Memcache|DynamoDB)|redis\s*:\s*\w+|new\s+RedisStore\s*\(|storage\s*:\s*new\s+\w*Redis/);
    return shared ? pass('Rate limiter uses a shared store.') : fail('Rate limiter uses per-process memory.', ctx.grep(/\b(rateLimit|RateLimiterMemory|ThrottlerModule\.forRoot)\s*\(/));
  },
});

const websockets = defineCheck({
  id: 'SCL-009',
  title: 'Realtime connections (WebSocket / Socket.IO) can scale out',
  severity: 'medium',
  tags: ['load-balancing', 'realtime'],
  why: 'A broadcast from replica A never reaches clients connected to replica B, and Socket.IO polling breaks without sticky sessions.',
  fix: 'Socket.IO: add `@socket.io/redis-adapter` (or redis-streams/postgres adapter) and enable sticky sessions at the LB. Raw ws: fan out via Redis pub/sub, or use a managed service (Ably, Pusher, API Gateway WebSockets).',
  run(ctx) {
    if (ctx.hasDep('socket.io')) {
      const adapter = ctx.hasDep('@socket.io/redis-adapter', '@socket.io/redis-streams-adapter', '@socket.io/postgres-adapter', '@socket.io/mongo-adapter', '@socket.io/cluster-adapter', 'socket.io-redis');
      return adapter ? pass('Socket.IO uses a cross-node adapter.') : fail('Socket.IO without a Redis/cluster adapter.');
    }
    if (ctx.hasDep('ws', 'uWebSockets.js', '@fastify/websocket', 'express-ws')) {
      return ctx.contains(/\.(publish|subscribe|psubscribe)\s*\(/) && REDIS.some((r) => ctx.hasDep(r)) ? pass('WebSocket fan-out via pub/sub.') : warn('Raw WebSockets with no pub/sub fan-out found — broadcasts will be per-replica.');
    }
    return skip('No WebSocket server.');
  },
});

const autoscaling = defineCheck({
  id: 'SCL-010',
  title: 'Horizontal scaling / autoscaling is configured',
  severity: 'medium',
  tags: ['scaling'],
  why: 'A single instance is a single point of failure and cannot absorb traffic spikes.',
  fix: 'Run ≥ 2 replicas and autoscale on CPU/RPS/queue depth: Kubernetes HPA/KEDA, ECS Service Auto Scaling, Cloud Run min/max instances, Fly/Render autoscaling, or PM2 cluster mode on VMs.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const cfg = ctx.files.filter((f) => /\.(ya?ml|tf|json|toml|[cm]?js)$/.test(f));
    const hit = cfg.find((f) => /kind:\s*(HorizontalPodAutoscaler|ScaledObject)|aws_appautoscaling_(target|policy)|autoscaling\.knative\.dev|max_?[Ii]nstances|min_machines_running|auto_?scal|maxReplicas|\breplicas\s*:\s*([2-9]|\d{2,})|instances\s*:\s*(['"]max['"]|-1|[2-9])|exec_mode\s*:\s*['"]cluster/i.test(ctx.read(f) ?? ''));
    if (hit) return pass(`Scaling config in ${hit}.`);
    if (ctx.contains(/cluster\.fork\s*\(|node:cluster/)) return pass('Node cluster mode in use.');
    return warn('No replica/autoscaling config in the repo. If your platform scales automatically, confirm min ≥ 2 and tick SCL-M02.');
  },
});

const resources = defineCheck({
  id: 'SCL-011',
  title: 'Containers declare CPU/memory requests and limits',
  severity: 'medium',
  tags: ['scaling', 'container'],
  why: 'Without requests the scheduler packs pods blindly; without limits one leaking pod starves its neighbours; Node without --max-old-space-size ignores the container limit and gets OOM-killed.',
  fix: 'Set `resources.requests` and `resources.limits` on every container, and size Node\'s heap (`NODE_OPTIONS=--max-old-space-size=…` ≈ 75% of the memory limit).',
  run(ctx) {
    const k8s = ctx.findFiles(/\.ya?ml$/).filter((f) => /kind:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob)/.test(ctx.read(f) ?? ''));
    const ecs = ctx.findFiles(/\.(tf|json)$/).filter((f) => /aws_ecs_task_definition|containerDefinitions/.test(ctx.read(f) ?? ''));
    if (!k8s.length && !ecs.length) return skip('No Kubernetes or ECS definitions.');
    const missing = [
      ...k8s.filter((f) => !/requests\s*:[\s\S]*?(cpu|memory)/.test(ctx.read(f) ?? '') || !/limits\s*:[\s\S]*?memory/.test(ctx.read(f) ?? '')),
      ...ecs.filter((f) => !/"?memory"?\s*[:=]/.test(ctx.read(f) ?? '')),
    ];
    return missing.length ? fail('Workloads without resource requests/limits.', missing.map((f) => ({ file: f }))) : pass('Resource requests and limits declared.');
  },
});

const trustProxy = defineCheck({
  id: 'SCL-012',
  title: 'App trusts the load balancer\'s forwarded headers (correctly)',
  severity: 'medium',
  tags: ['load-balancing'],
  why: 'Behind a load balancer `req.ip` is the LB\'s address: rate limits throttle everyone together, audit logs record the wrong IP, and HTTPS redirects loop. Trusting all proxies lets clients spoof their IP.',
  fix: 'Express: `app.set(\'trust proxy\', 1)` (number of hops, not `true`). Fastify: `trustProxy: 1`. Koa: `app.proxy = true` with `maxIpsCount`.',
  docs: ['https://expressjs.com/en/guide/behind-proxies.html'],
  run(ctx) {
    const fw = ctx.stack.server.filter((s) => ['Express', 'Fastify', 'Koa', 'NestJS'].includes(s));
    if (!fw.length) return skip('No Express/Fastify/Koa/Nest server.');
    const set = ctx.grep(/['"`]trust proxy['"`]\s*,|trustProxy\s*:|app\.proxy\s*=\s*true/);
    if (!set.length) return fail('Proxy trust not configured — req.ip will be the load balancer.');
    const tooOpen = set.filter((h) => /['"`]trust proxy['"`]\s*,\s*true|trustProxy\s*:\s*true/.test(h.text));
    return tooOpen.length ? warn('Trusts every proxy hop (`true`) — clients can spoof X-Forwarded-For. Use the hop count.', tooOpen) : pass('Proxy trust configured with a hop count/allow-list.');
  },
});

const compression = defineCheck({
  id: 'SCL-013',
  title: 'Responses are compressed (app, proxy or CDN)',
  severity: 'low',
  tags: ['performance'],
  why: 'Uncompressed JSON/HTML is 3–10× larger: slower pages, higher bandwidth bills, more time per connection on the LB.',
  fix: 'Prefer compression at the proxy/CDN (nginx `gzip on` / brotli, CloudFront). Otherwise `compression` / `@fastify/compress` / `koa-compress`.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    if (ctx.stack.fullstack.includes('Next.js') && !ctx.contains(/compress\s*:\s*false/, { files: ctx.findFiles(/next\.config/) })) return pass('Next.js compresses by default.');
    if (ctx.hasDep('compression', '@fastify/compress', 'koa-compress', 'shrink-ray-current', 'hono')) return pass('Compression middleware installed.');
    const proxy = ctx.findFiles(/(nginx[^/]*\.conf|\.conf|Caddyfile|cloudfront[^/]*\.(tf|json|ya?ml)|\.tf)$/).some((f) => /gzip\s+on|brotli\s+on|encode\s+(gzip|zstd)|compress\s*=\s*true|Compress:\s*true/i.test(ctx.read(f) ?? ''));
    return proxy ? pass('Compression configured at the proxy/CDN.') : warn('No compression found in app or proxy config — confirm your CDN/LB compresses.');
  },
});

const loadTests = defineCheck({
  id: 'SCL-014',
  title: 'Load tests are kept in the repo',
  severity: 'low',
  tags: ['testing', 'capacity'],
  why: 'Capacity you have not measured is a guess; load-test scripts in git can be re-run before every big launch.',
  fix: 'Add k6, Artillery, Locust or autocannon scenarios for the critical paths (login, search, checkout) and run them against staging.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const k6 = ctx.files.find((f) => /\.[cm]?[jt]s$/.test(f) && /from\s+['"]k6(\/http)?['"]/.test(ctx.read(f) ?? ''));
    const other = ctx.findFiles(/(artillery[^/]*\.ya?ml|locustfile\.py|\.jmx|gatling|loadtest|load-test|perf\/)/i);
    const dep = ctx.hasDep('autocannon', 'artillery', 'k6', 'loadtest', '@grafana/xk6');
    return k6 || other.length || dep ? pass(`Load tests: ${k6 ?? other[0] ?? 'via dependency'}.`) : warn('No load-test scripts found.');
  },
});

// ---------- in-depth (--review) ----------

const moduleState = defineCheck({
  id: 'SCL-R01',
  review: true,
  title: 'No per-process state shared between requests',
  severity: 'high',
  tags: ['stateless'],
  why: 'Module-level Maps/arrays/variables written by request handlers hold data only in one replica — other replicas disagree, it is lost on restart, and it grows until the process is OOM-killed.',
  fix: 'Move shared state to Redis/the database. If it is a deliberate local cache, bound it (lru-cache with max/ttl) and accept per-replica copies.',
  run(ctx) {
    if (!longRunning(ctx) && !ctx.stack.fullstack.length) return skip('No server process.');
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code) continue;
      const lineOf = lineIndex(code);
      const decl = /^(?:export\s+)?(const|let|var)\s+([a-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(new\s+(Map|Set|WeakMap)\s*\(\s*\)|\{\s*\}|\[\s*\]|null|undefined|0|''|"")\s*;?\s*$/gm;
      let m;
      while ((m = decl.exec(code))) {
        const [, kind, name, init] = m;
        const rest = code.slice(m.index + m[0].length);
        const esc = name.replace(/\$/g, '\\$');
        const mutated = new RegExp(`\\b${esc}\\s*\\.\\s*(set|add|push|unshift|splice)\\s*\\(|\\b${esc}\\s*\\[[^\\]]+\\]\\s*=(?!=)`).test(rest)
          || (kind === 'let' && new RegExp(`(^|[^.\\w$])${esc}\\s*([-+*/|&]?=(?!=)|\\+\\+|--)|(\\+\\+|--)${esc}\\b`, 'm').test(rest));
        if (!mutated) continue;
        // Inside a function? Only report when writes happen in indented (function) code.
        if (!new RegExp(`\\n[ \\t]+[^\\n]*\\b${esc}\\b`).test(rest)) continue;
        findings.push(ctx.at(f, lineOf(m.index), `${name} (${init.trim()}) is module-level state written at runtime`));
      }
    }
    return findings.length ? fail(`${findings.length} module-level mutable value(s) used as shared state.`, findings) : pass('No module-level mutable state written by handlers.');
  },
});

const blockingCalls = defineCheck({
  id: 'SCL-R02',
  review: true,
  title: 'Request handlers do not block the event loop',
  severity: 'high',
  tags: ['performance'],
  why: 'A synchronous file read, hash or compression inside a handler freezes every other request on that process — throughput collapses under load.',
  fix: 'Use async versions (`fs.promises`, `bcrypt.hash`, `crypto.pbkdf2`, `zlib.gzip` with callback/stream), move CPU-heavy work to worker_threads or a job queue, and read static files at startup.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const SYNC = /\b(readFileSync|writeFileSync|appendFileSync|readdirSync|statSync|existsSync|execSync|spawnSync|execFileSync|pbkdf2Sync|scryptSync|randomFillSync|gzipSync|gunzipSync|deflateSync|inflateSync|brotliCompressSync|hashSync|compareSync|genSaltSync)\s*\(/;
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code || !SYNC.test(code)) continue;
      const lineOf = lineIndex(code);
      for (const h of routeHandlers(code)) {
        const m = h.body.match(SYNC);
        if (m) findings.push(ctx.at(f, lineOf(h.offset + m.index), `${m[1]}() inside a request handler`));
      }
    }
    return findings.length ? fail(`${findings.length} blocking call(s) in request handlers.`, unique(findings)) : pass('No synchronous blocking calls in request handlers.');
  },
});

const perCallTimeouts = defineCheck({
  id: 'SCL-R03',
  review: true,
  title: 'Every outbound call site has a timeout',
  severity: 'medium',
  tags: ['resilience'],
  why: 'A timeout on one client does not protect the plain `fetch()` someone added later.',
  fix: 'Use one shared HTTP client with a default timeout, or pass `signal: AbortSignal.timeout(ms)` on every fetch.',
  run(ctx) {
    const findings = [];
    const axiosDefault = ctx.contains(/axios\.defaults\.timeout\s*=|axios\.create\s*\(\s*\{[^}]*timeout/);
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code || !HTTP_CLIENT_CALL.test(code)) continue;
      const lineOf = lineIndex(code);
      const re = new RegExp(HTTP_CLIENT_CALL.source, 'g');
      let m;
      while ((m = re.exec(code))) {
        const open = m.index + m[0].lastIndexOf('(');
        const args = extractArgs(code, open).args.join(',');
        const isAxios = /axios/.test(m[0]);
        if (/timeout|signal\s*:|AbortSignal/.test(args)) continue;
        if (isAxios && axiosDefault) continue;
        findings.push(ctx.at(f, lineOf(m.index), `${m[0].replace(/^[^\w]/, '').trim()}…) without timeout`));
      }
    }
    if (!findings.length) return ctx.contains(HTTP_CLIENT_CALL) ? pass('All outbound calls pass a timeout/signal.') : skip('No outbound HTTP calls found.');
    return fail(`${findings.length} outbound call(s) without a timeout.`, findings);
  },
});

// ---------- manual ----------

const manual = [
  {
    id: 'SCL-M01', title: 'Load tested at 2–3× expected peak; the first bottleneck is known', severity: 'high',
    why: 'You want to discover that the DB pool runs out at 400 RPS in staging, not on launch day.',
    fix: 'Run k6/Artillery against a production-like environment, record max RPS, p95 latency and which resource saturated first.',
  },
  {
    id: 'SCL-M02', title: 'Capacity plan: min/max replicas, scaling triggers and limits are documented per app', severity: 'medium',
    why: 'Autoscaling without limits can exhaust DB connections or the budget; without a minimum, one crash means downtime.',
    fix: 'Per app: min ≥ 2, max bounded by DB connection budget, scaling metric, and expected cost at max.',
  },
  {
    id: 'SCL-M03', title: 'Load balancer health checks use readiness, and deregistration delay ≥ request timeout', severity: 'high',
    why: 'Wrong health checks keep sending traffic to broken or shutting-down instances.',
    fix: 'Point LB/target-group checks at /readyz, set connection draining (ALB deregistration delay, K8s preStop sleep) longer than the slowest request.',
  },
  {
    id: 'SCL-M04', title: 'No single points of failure (multi-AZ, ≥2 instances, DB/Redis failover)', severity: 'high',
    why: 'One zone outage or one node reboot should not take an app offline.',
    fix: 'Spread replicas across zones, enable DB multi-AZ/replica failover and Redis replication; test failover once.',
  },
  {
    id: 'SCL-M05', title: 'Websites and static assets are served through a CDN', severity: 'medium',
    why: 'Serving images/JS from Node wastes app capacity and is slow for distant users.',
    fix: 'Put CloudFront/Cloudflare/Fastly/Vercel Edge in front; long cache lifetimes for hashed assets; monitor cache hit ratio.',
  },
  {
    id: 'SCL-M06', title: 'Overload behaviour is designed: back-pressure, circuit breakers, load shedding', severity: 'medium',
    why: 'When a dependency slows down, retries and queues can amplify the problem into a cascading failure across apps.',
    fix: 'Circuit breakers (opossum), bounded queues, retry budgets with jitter, feature flags to switch off expensive features, 429/503 with Retry-After.',
  },
  {
    id: 'SCL-M07', title: 'Deploys are zero-downtime (rolling / blue-green) and verified under traffic', severity: 'medium',
    why: 'If every deploy causes a blip, teams deploy less often and batch more risk into each release.',
    fix: 'Rolling updates with maxUnavailable 0, readiness gates, and a synthetic check watching error rate during each deploy.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'scalability',
  title: 'Scalability',
  description: 'Stateless processes, graceful shutdown, timeouts, caching, background jobs and load-balancer readiness — so every app can run as many replicas as traffic needs.',
  checks: [
    sessions, uploads, gracefulShutdown, outboundTimeouts, serverTimeouts, caching, backgroundJobs,
    sharedRateLimit, websockets, autoscaling, resources, trustProxy, compression, loadTests,
    moduleState, blockingCalls, perCallTimeouts,
    ...manual,
  ],
});
