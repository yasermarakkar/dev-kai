import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';
import { blocksAfter, extractArgs, lineIndex } from '../core/lexer.js';

// ---------- dependency catalogs ----------

const HEALTH_LIBS = ['@nestjs/terminus', '@godaddy/terminus', 'lightship', '@cloudnative/health-connect', 'express-healthcheck', 'fastify-healthcheck', '@hapi/hapi-health'];

const SERVER_ERROR_TRACKERS = [
  '@sentry/node', '@sentry/nestjs', '@sentry/nextjs', '@sentry/remix', '@sentry/sveltekit', '@sentry/nuxt', '@sentry/bun', '@sentry/aws-serverless',
  '@bugsnag/js', '@bugsnag/node', 'rollbar', '@honeybadger-io/js', 'dd-trace', 'newrelic', 'elastic-apm-node', '@highlight-run/node', '@appsignal/nodejs', 'raygun',
];
const BROWSER_ERROR_TRACKERS = [
  '@sentry/browser', '@sentry/react', '@sentry/vue', '@sentry/angular', '@sentry/svelte', '@sentry/nextjs', '@sentry/remix', '@sentry/sveltekit',
  '@sentry/nuxt', '@sentry/react-native', '@sentry/electron', '@datadog/browser-rum', '@datadog/browser-logs', 'logrocket', '@bugsnag/js',
  '@bugsnag/browser', 'rollbar', '@honeybadger-io/js', '@highlight-run/react', 'highlight.run', '@newrelic/browser-agent', 'posthog-js', 'trackjs',
];
const METRICS_LIBS = [
  'prom-client', 'express-prom-bundle', 'fastify-metrics', '@willsoto/nestjs-prometheus', '@opentelemetry/sdk-metrics', '@opentelemetry/exporter-prometheus',
  'hot-shots', 'node-statsd', 'statsd-client', 'dd-trace', 'newrelic', 'elastic-apm-node', '@aws-lambda-powertools/metrics', 'aws-embedded-metrics', 'swagger-stats', 'express-status-monitor',
];
const TRACING_LIBS = [
  '@opentelemetry/sdk-node', '@opentelemetry/sdk-trace-node', '@opentelemetry/sdk-trace-base', '@opentelemetry/auto-instrumentations-node', '@vercel/otel',
  'dd-trace', 'newrelic', 'elastic-apm-node', '@aws-lambda-powertools/tracer', 'aws-xray-sdk', 'aws-xray-sdk-core', '@google-cloud/trace-agent', '@honeycombio/opentelemetry-node',
];
const RUM_LIBS = ['web-vitals', '@vercel/speed-insights', '@vercel/analytics', '@datadog/browser-rum', '@newrelic/browser-agent', 'posthog-js', '@highlight-run/react', 'highlight.run'];
const SOURCEMAP_UPLOADERS = ['@sentry/webpack-plugin', '@sentry/vite-plugin', '@sentry/esbuild-plugin', '@sentry/rollup-plugin', '@sentry/cli', '@datadog/datadog-ci', '@bugsnag/source-maps', '@highlight-run/sourcemap-uploader', 'rollbar-sourcemap-webpack-plugin'];

// ---------- route helpers ----------

const LIVE_PATHS = 'health|healthz|livez|live|liveness|ping|_health|healthcheck|status';
const READY_PATHS = 'ready|readyz|readiness|health/ready|healthz/ready';

/** Locations where a route with one of the given paths is declared. */
function findPathRoutes(ctx, paths) {
  const p = `(?:api/)?(?:${paths})`;
  const decl = ctx.grep(new RegExp(
    `\\.(get|all|use|route|head|on)\\s*\\(\\s*(['"\`][A-Z]+['"\`]\\s*,\\s*)?['"\`]/${p}/?['"\`]` + // express/hono/koa/fastify shorthand
    `|url\\s*:\\s*['"\`]/${p}/?['"\`]` + // fastify.route({ url })
    `|@(Get|Controller|All)\\s*\\(\\s*['"\`]/?${p}/?['"\`]` + // NestJS
    `|req\\.url\\s*===?\\s*['"\`]/${p}['"\`]`, // raw node:http
  ));
  const fileRoutes = ctx.findFiles(new RegExp(`(^|/)(app|pages)/(api/)?(${paths.replace(/\//g, '\\/')})(/route|/index)?\\.[cm]?[jt]sx?$`)).map((f) => ({ file: f, line: 1, text: 'Next.js route file' }));
  return [...decl, ...fileRoutes];
}

/** Character offset where 1-based line `line` starts. */
function lineStart(text, line) {
  let offset = 0;
  for (let l = 1; l < line; l++) {
    const nl = text.indexOf('\n', offset);
    if (nl === -1) return text.length;
    offset = nl + 1;
  }
  return offset;
}

const DEP_CHECK_RE = /\.(query|raw|\$queryRaw|\$queryRawUnsafe|execute|authenticate|ping|command|admin\(\)\.ping|isHealthy|checkHealth|healthCheck)\s*[(`]|\bSELECT\s+1\b|pingCheck|TypeOrmHealthIndicator|PrismaHealthIndicator|MongooseHealthIndicator|db\.(raw|execute)|redis\.(ping|status)|connection\.readyState/i;

// ---------- quick checks ----------

const liveness = defineCheck({
  id: 'MON-001',
  title: 'Health (liveness) endpoint exists',
  severity: 'high',
  tags: ['health'],
  why: 'Load balancers, Kubernetes and uptime monitors need a cheap endpoint to know the process is alive — without it, dead instances keep receiving traffic.',
  fix: 'Expose `GET /healthz` returning 200 quickly (no heavy work). NestJS: @nestjs/terminus. Express: a one-line route or @godaddy/terminus. Next.js: `app/api/health/route.ts`.',
  docs: ['https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const lib = HEALTH_LIBS.filter((l) => ctx.hasDep(l));
    if (lib.length) return pass(`Using ${lib.join(', ')}.`);
    const routes = findPathRoutes(ctx, LIVE_PATHS);
    return routes.length ? pass(`Health route at ${routes[0].file}:${routes[0].line}.`) : fail('No /health, /healthz or similar endpoint found.');
  },
});

const readiness = defineCheck({
  id: 'MON-002',
  title: 'Readiness endpoint checks critical dependencies',
  severity: 'medium',
  tags: ['health'],
  why: 'An app that is up but cannot reach its database should be taken out of rotation, not keep failing user requests.',
  fix: 'Add `GET /readyz` that pings DB/cache/queue with a short timeout and returns 503 when any is down. Keep /healthz dependency-free so a DB blip does not restart every pod.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    if (ctx.hasDep('@nestjs/terminus', '@godaddy/terminus', 'lightship', '@cloudnative/health-connect')) return pass('Health library with readiness support in use.');
    const ready = findPathRoutes(ctx, READY_PATHS);
    if (ready.length) return pass(`Readiness route at ${ready[0].file}:${ready[0].line}.`);
    if (!ctx.stack.data.length) return skip('No database/cache dependency to check.');
    return findPathRoutes(ctx, LIVE_PATHS).length
      ? warn('Only a liveness endpoint — add a separate readiness endpoint that checks the database.')
      : fail('No readiness endpoint found.');
  },
});

const serverErrorTracking = defineCheck({
  id: 'MON-003',
  title: 'Backend errors are sent to an error tracker',
  severity: 'high',
  tags: ['errors'],
  why: 'Logs tell you an error happened if you go looking; an error tracker groups it, counts affected users and pings you.',
  fix: 'Install Sentry (`@sentry/node` / `@sentry/nestjs` / `@sentry/nextjs`) or your APM vendor and initialise it before anything else is imported.',
  docs: ['https://docs.sentry.io/platforms/javascript/guides/node/'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const found = SERVER_ERROR_TRACKERS.filter((l) => ctx.hasDep(l));
    return found.length ? pass(`Using ${found.join(', ')}.`) : fail('No server-side error tracking SDK.');
  },
});

const browserErrorTracking = defineCheck({
  id: 'MON-004',
  title: 'Frontend errors are captured (websites and mobile apps)',
  severity: 'high',
  tags: ['errors', 'frontend'],
  why: 'Errors in the browser or mobile app never reach your server logs — without a client SDK you only hear about them from angry users.',
  fix: 'Add @sentry/react / @sentry/nextjs / @sentry/react-native (or Datadog RUM, LogRocket, Bugsnag) to every website and app, with an error boundary at the root.',
  run(ctx) {
    if (!ctx.stack.frontend.length && !ctx.stack.fullstack.length) return skip('No frontend detected.');
    const found = BROWSER_ERROR_TRACKERS.filter((l) => ctx.hasDep(l));
    return found.length ? pass(`Using ${found.join(', ')}.`) : fail(`Frontend (${[...ctx.stack.frontend, ...ctx.stack.fullstack].join(', ')}) has no error tracking SDK.`);
  },
});

const metrics = defineCheck({
  id: 'MON-005',
  title: 'Application metrics are exposed (rate, errors, latency)',
  severity: 'high',
  tags: ['metrics'],
  why: 'Without request rate, error rate and latency per route you cannot see a slowdown until users complain, or size capacity.',
  fix: 'Export RED metrics: prom-client / express-prom-bundle (Prometheus), OpenTelemetry metrics, or your APM agent. Add DB pool and queue depth gauges.',
  docs: ['https://opentelemetry.io/docs/languages/js/instrumentation/#metrics'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const found = METRICS_LIBS.filter((l) => ctx.hasDep(l));
    return found.length ? pass(`Using ${found.join(', ')}.`) : fail('No metrics library or APM agent found.');
  },
});

const tracing = defineCheck({
  id: 'MON-006',
  title: 'Distributed tracing across apps (OpenTelemetry or APM)',
  severity: 'high',
  tags: ['tracing', 'multi-app'],
  why: 'With several connected apps, tracing is the only way to see which hop made a request slow or fail.',
  fix: 'Add `@opentelemetry/sdk-node` + `@opentelemetry/auto-instrumentations-node` (or dd-trace / New Relic) to every service; propagate W3C `traceparent` headers; send to Jaeger, Tempo, Honeycomb or your APM.',
  docs: ['https://opentelemetry.io/docs/languages/js/getting-started/nodejs/'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const found = TRACING_LIBS.filter((l) => ctx.hasDep(l));
    if (found.length) return pass(`Using ${found.join(', ')}.`);
    if (ctx.contains(/tracesSampleRate|tracesSampler/)) return warn('Only error-tracker performance tracing (Sentry) — fine for one app; add OpenTelemetry for cross-service traces.');
    return fail('No tracing found.');
  },
});

const containerProbes = defineCheck({
  id: 'MON-007',
  title: 'Containers declare health checks / probes',
  severity: 'medium',
  tags: ['health', 'container'],
  why: 'Without probes the orchestrator only restarts a container when it exits — hung processes keep serving errors.',
  fix: 'Dockerfile/compose: `HEALTHCHECK CMD curl -f http://localhost:3000/healthz || exit 1`. Kubernetes: livenessProbe + readinessProbe (+ startupProbe for slow boots).',
  run(ctx) {
    const dockerfiles = ctx.findFiles(/(^|\/)Dockerfile[^/]*$/);
    const compose = ctx.findFiles(/(^|\/)(docker-)?compose[^/]*\.ya?ml$/);
    const k8s = ctx.findFiles(/\.ya?ml$/).filter((f) => /kind:\s*(Deployment|StatefulSet|DaemonSet)/.test(ctx.read(f) ?? ''));
    if (!dockerfiles.length && !compose.length && !k8s.length) return skip('No Dockerfile, compose or Kubernetes manifests.');
    const missing = [];
    for (const f of k8s) if (!/readinessProbe|livenessProbe/.test(ctx.read(f) ?? '')) missing.push({ file: f, text: 'Kubernetes workload without probes' });
    const composeHas = compose.some((f) => /healthcheck:/.test(ctx.read(f) ?? ''));
    if (!k8s.length) {
      for (const f of dockerfiles) if (!/^\s*HEALTHCHECK\s/m.test(ctx.read(f) ?? '') && !composeHas) missing.push({ file: f, text: 'no HEALTHCHECK (and none in compose)' });
    }
    return missing.length ? fail('Container health checks missing.', missing) : pass('Health checks / probes declared.');
  },
});

const alertsAsCode = defineCheck({
  id: 'MON-008',
  title: 'Alerts are defined as code',
  severity: 'medium',
  tags: ['alerting'],
  why: 'Click-ops alerts drift, get deleted and are not reviewed; alerts in git are versioned with the service they protect.',
  fix: 'Keep alert rules in the repo: Prometheus/Alertmanager rule files, Terraform (datadog_monitor, aws_cloudwatch_metric_alarm, grafana_rule_group), or Checkly/Sentry config.',
  run(ctx) {
    const iac = ctx.findFiles(/\.(ya?ml|json|tf|ts|js)$/).filter((f) => !ctx.codeFiles.includes(f) || /checkly|monitor|alert/i.test(f));
    const hits = iac.filter((f) => /^\s*-?\s*alert:\s*\S|resource\s+"(datadog_monitor|aws_cloudwatch_metric_alarm|grafana_rule_group|newrelic_alert_condition|newrelic_nrql_alert_condition|google_monitoring_alert_policy|azurerm_monitor_metric_alert|sentry_issue_alert|sentry_metric_alert|pagerduty_service)"|AWS::CloudWatch::Alarm|new\s+(ApiCheck|BrowserCheck)\s*\(|"type"\s*:\s*"(metric alert|query alert)"/m.test(ctx.read(f) ?? ''));
    if (hits.length) return pass(`Alert definitions in ${hits.slice(0, 3).join(', ')}${hits.length > 3 ? '…' : ''}.`);
    return warn('No alert definitions in the repo. If alerts live only in a vendor UI, tick MON-M02 after reviewing them.');
  },
});

const errorTags = defineCheck({
  id: 'MON-009',
  title: 'Errors are tagged with release and environment',
  severity: 'low',
  tags: ['errors'],
  why: 'Without release and environment tags you cannot tell whether an error came from staging or prod, or which deploy introduced it.',
  fix: 'Sentry.init({ dsn: process.env.SENTRY_DSN, environment: process.env.APP_ENV, release: process.env.GIT_SHA }). Keep the DSN in env, not code.',
  run(ctx) {
    const inits = ctx.grep(/\b(Sentry|Bugsnag|Rollbar|Honeybadger)\.(init|start|configure)\s*\(|new\s+Rollbar\s*\(/);
    if (!inits.length) return skip('No error tracker initialisation found.');
    const files = [...new Set(inits.map((h) => h.file))];
    const text = files.map((f) => ctx.read(f) ?? '').join('\n');
    const hardDsn = ctx.grep(/dsn\s*:\s*['"`]https:\/\/[a-f0-9]+@/i, { files });
    const tagged = /\b(environment|releaseStage|appVersion)\s*:/.test(text) && /\b(release|appVersion|codeVersion)\s*:|SENTRY_RELEASE|withSentryConfig/.test(text);
    if (hardDsn.length) return warn('DSN hardcoded in source — move to env so environments do not mix.', hardDsn);
    return tagged ? pass('Release and environment set on error tracker init.') : fail('Error tracker initialised without release/environment tags.', inits);
  },
});

const webVitals = defineCheck({
  id: 'MON-010',
  title: 'Real-user performance (Web Vitals / RUM) is measured',
  severity: 'low',
  tags: ['frontend', 'performance'],
  why: 'Lab tests miss slow devices and networks; real-user LCP/INP/CLS show what customers actually feel (and affect SEO).',
  fix: 'Add @vercel/speed-insights, `web-vitals` reporting, Datadog RUM or Sentry browser tracing to each website.',
  run(ctx) {
    if (!ctx.stack.frontend.length && !ctx.stack.fullstack.length) return skip('No frontend detected.');
    if (ctx.stack.frontend.every((f) => f === 'React Native' || f === 'Expo') && !ctx.stack.fullstack.length) return skip('Mobile-only frontend.');
    const found = RUM_LIBS.filter((l) => ctx.hasDep(l));
    if (found.length) return pass(`Using ${found.join(', ')}.`);
    if (ctx.contains(/reportWebVitals|useReportWebVitals|browserTracingIntegration|BrowserTracing/)) return pass('Web Vitals reporting in code.');
    return fail('No real-user monitoring found.');
  },
});

const sourceMaps = defineCheck({
  id: 'MON-011',
  title: 'Source maps are uploaded to the error tracker',
  severity: 'low',
  tags: ['frontend', 'errors'],
  why: 'Minified stack traces (`a.b is not a function at main.3f2a.js:1:48213`) are useless during an incident.',
  fix: 'Upload source maps in CI with @sentry/vite-plugin / @sentry/webpack-plugin / withSentryConfig (Next.js) and do not serve them publicly.',
  run(ctx) {
    const tracker = BROWSER_ERROR_TRACKERS.filter((l) => ctx.hasDep(l));
    if (!tracker.length) return skip('No frontend error tracker (see MON-004).');
    const uploader = SOURCEMAP_UPLOADERS.filter((l) => ctx.hasDep(l));
    if (uploader.length || ctx.contains(/withSentryConfig|sentry-cli\s+sourcemaps|datadog-ci\s+sourcemaps/, { files: ctx.files.filter((f) => ctx.codeFiles.includes(f) || /package\.json|\.ya?ml$/.test(f)) })) {
      return pass('Source map upload configured.');
    }
    return fail(`Using ${tracker.join(', ')} but no source map upload step found.`);
  },
});

// ---------- in-depth (--review) ----------

const shallowHealth = defineCheck({
  id: 'MON-R01',
  review: true,
  title: 'Health/readiness handlers actually exercise dependencies',
  severity: 'medium',
  tags: ['health'],
  why: 'A readiness check that always returns 200 hides a dead database from the load balancer.',
  fix: 'In the readiness handler run a cheap dependency call (`SELECT 1`, `redis.ping()`) with a timeout and return 503 on failure.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    if (!ctx.stack.data.length) return skip('No database/cache dependency.');
    if (ctx.hasDep('@nestjs/terminus') && ctx.contains(/HealthIndicator|pingCheck/)) return pass('Terminus health indicators in use.');
    const routes = [...findPathRoutes(ctx, READY_PATHS), ...findPathRoutes(ctx, LIVE_PATHS)];
    if (!routes.length) return skip('No health routes (see MON-001).');
    const shallow = [];
    let deep = 0;
    for (const r of routes) {
      const code = ctx.code(r.file) ?? '';
      let body = code;
      if (r.text !== 'Next.js route file') {
        const offset = lineStart(code, r.line);
        const open = code.indexOf('(', offset);
        const { args } = open === -1 ? { args: [] } : extractArgs(code, open);
        body = args.at(-1) ?? '';
        // handler passed by name → look up its definition in the same file
        if (/^[A-Za-z_$][\w$.]*$/.test(body)) {
          const name = body.split('.').pop();
          const def = code.search(new RegExp(`(function\\s+${name}\\b|${name}\\s*[=:]\\s*(async\\s*)?(\\(|function))`));
          body = def === -1 ? body : code.slice(def, def + 1500);
        }
      }
      if (DEP_CHECK_RE.test(body)) deep++;
      else shallow.push(ctx.at(r.file, r.line, `${r.text.trim().slice(0, 80)} — returns without touching DB/cache`));
    }
    if (deep) return pass(`${deep} health handler(s) check dependencies.`);
    return warn(`App uses ${ctx.stack.data.join(', ')} but no health handler checks it.`, shallow);
  },
});

const publicMetrics = defineCheck({
  id: 'MON-R02',
  review: true,
  title: 'Metrics endpoint is not publicly exposed',
  severity: 'medium',
  tags: ['metrics', 'security'],
  why: '/metrics leaks route names, versions, traffic volume and internal hostnames, and can be scraped to plan attacks.',
  fix: 'Serve metrics on a separate internal port (e.g. 9464), restrict by network policy, or require a bearer token for the scraper.',
  run(ctx) {
    const routes = ctx.grep(/\.(get|all|use)\s*\(\s*['"`]\/metrics['"`]/);
    if (!routes.length) return skip('No /metrics route on the app server.');
    const open = routes.filter((r) => {
      const code = ctx.code(r.file) ?? '';
      const { args } = extractArgs(code, code.indexOf('(', lineStart(code, r.line)));
      return !args.slice(1, -1).some((a) => /auth|token|basic|internal|allow|ipFilter|guard/i.test(a));
    });
    if (!open.length) return pass('/metrics is guarded.');
    const separatePort = ctx.contains(/listen\s*\(\s*(9\d{3}|process\.env\.METRICS_PORT|metricsPort)/);
    return separatePort
      ? warn('/metrics has no guard — confirm it is only bound on the internal metrics port.', open)
      : fail('/metrics served on the public app port without auth.', open);
  },
});

const silentServerErrors = defineCheck({
  id: 'MON-R03',
  review: true,
  title: 'Handled 5xx errors are still reported',
  severity: 'medium',
  tags: ['errors'],
  why: 'A catch block that returns 500 without logging or reporting makes the failure invisible to dashboards and alerts.',
  fix: 'In every catch that returns 5xx: `logger.error({ err })` and/or `Sentry.captureException(err)` — or call `next(err)` and handle centrally.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code || !/catch/.test(code) || !/\b5\d\d\b/.test(code)) continue;
      const lineOf = lineIndex(code);
      for (const b of blocksAfter(code, /\bcatch\s*(\([^)]*\))?\s*\{/)) {
        const responds5xx = /\.(status|code|sendStatus)\s*\(\s*5\d\d\s*\)|status\s*:\s*5\d\d|statusCode\s*=\s*5\d\d/.test(b.body);
        const reported = /captureException|captureError|notify\s*\(|\.error\s*\(|\.fatal\s*\(|\.warn\s*\(|next\s*\(\s*\w+\s*\)|throw\b|recordException|reportError/.test(b.body);
        if (responds5xx && !reported) findings.push(ctx.at(f, lineOf(b.open), 'catch returns 5xx without logging/reporting'));
      }
    }
    return findings.length ? fail(`${findings.length} catch block(s) return 5xx silently.`, unique(findings)) : pass('All handled 5xx responses are logged or reported.');
  },
});

// ---------- manual ----------

const manual = [
  {
    id: 'MON-M01', title: 'SLOs defined for each user-facing app (availability, latency) with error budgets', severity: 'high',
    why: 'Without a target, every alert is a debate and you cannot tell "slow" from "fine".',
    fix: 'e.g. 99.9% of API requests succeed, p95 < 300 ms over 30 days. Alert on burn rate, not on single spikes.',
  },
  {
    id: 'MON-M02', title: 'Alerts reach an on-call person with escalation, and each links a runbook', severity: 'high',
    why: 'An alert in a muted Slack channel at 3 a.m. is the same as no alert.',
    fix: 'Route to PagerDuty / Opsgenie / Grafana OnCall with an escalation policy; every alert has an owner and a runbook link.',
  },
  {
    id: 'MON-M03', title: 'External uptime / synthetic checks for every website and public API', severity: 'high',
    why: 'Internal metrics look healthy when DNS, TLS, CDN or the whole region is down.',
    fix: 'Checkly, Better Stack, Pingdom or Datadog Synthetics from several regions; include login and checkout flows; alert on TLS expiry.',
  },
  {
    id: 'MON-M04', title: 'Dashboards per app show RED metrics plus infrastructure (USE)', severity: 'medium',
    why: 'During an incident you need one screen that shows what is broken, not a query editor.',
    fix: 'Per service: request rate, error rate, p50/p95/p99 latency, saturation (CPU, memory, DB pool, queue depth). Link from alerts.',
  },
  {
    id: 'MON-M05', title: 'Databases, caches and queues are monitored with alerts', severity: 'high',
    why: 'Most outages start in the data layer: full disks, connection exhaustion, replication lag, growing queues.',
    fix: 'Alert on disk > 80%, connections > 80% of max, replication lag, slow queries, queue age/depth, cache eviction rate.',
  },
  {
    id: 'MON-M06', title: 'Status page and incident communication process exist', severity: 'low',
    why: 'Customers and support need one place to learn what is happening.',
    fix: 'Public/private status page (Better Stack, Atlassian Statuspage, Instatus) updated during incidents; post-mortems for major ones.',
  },
  {
    id: 'MON-M07', title: 'Alert noise is reviewed regularly — every page is actionable', severity: 'medium',
    why: 'Noisy alerts train people to ignore the one that matters.',
    fix: 'Monthly review: delete or tune alerts that fired without action; track pages per on-call shift.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'monitoring',
  title: 'Monitoring',
  description: 'Health checks, error tracking, metrics, tracing and alerting — so you learn about problems before your users do, in every app.',
  checks: [
    liveness, readiness, serverErrorTracking, browserErrorTracking, metrics, tracing,
    containerProbes, alertsAsCode, errorTags, webVitals, sourceMaps,
    shallowHealth, publicMetrics, silentServerErrors,
    ...manual,
  ],
});
