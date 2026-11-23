import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';
import { extractArgs, lineIndex } from '../core/lexer.js';
import { findRoutes, PUBLIC_PATH_RE } from '../core/analysis.js';

// ---------- shared patterns ----------

/** A call that writes an audit/activity record. */
const AUDIT_CALL_SRC = String.raw`\b(audit|auditLog|auditTrail|recordAudit|logAudit|writeAudit|createAudit|addAudit|auditEvent|logActivity|recordActivity|activityLog|securityEvent|logSecurityEvent)\s*\(|\b(audit\w*|AuditLog|AuditTrail|ActivityLog|auditLog|activityLog|auditService|auditLogger)\s*\.\s*(log|record|create|insert|add|write|emit|track|save|info|warn|push)\s*\(|\.(auditLog|auditTrail|activityLog|auditEvent)\s*\.\s*(create|insert|add)\s*\(|emit\s*\(\s*['"\x60]audit`;
const AUDIT_CALL = new RegExp(AUDIT_CALL_SRC, 'i');

const AUDIT_LIBS = [
  'sequelize-paper-trail', 'mongoose-audit-trail', 'mongoose-history', 'mongoose-diff-history', 'typeorm-auditing', '@bemit/audit',
  'prisma-audit-log', 'objection-audit', 'audit-log', '@retracedhq/retraced', 'retraced', '@boxyhq/saml-jackson', 'pgaudit',
  '@aws-sdk/client-cloudtrail', 'paper-trail',
];

/** Schema / table declarations for an audit store. */
const AUDIT_MODEL_RE = new RegExp([
  String.raw`\bmodel\s+(Audit\w*|ActivityLog|EventLog|SecurityEvent)\s*\{`, // Prisma
  String.raw`create\s+table\s+(if\s+not\s+exists\s+)?["\x60\[]?(\w+\.)?(audit\w*|activity_log\w*|event_log\w*|security_event\w*)`, // SQL
  String.raw`@Entity\s*\(\s*(\{[^}]*name\s*:\s*)?['"\x60](audit\w*|activity\w*)`, // TypeORM
  String.raw`class\s+(Audit\w*|ActivityLog)\b[^{]*\{`, // entity classes
  String.raw`model\s*\(\s*['"\x60](Audit\w*|ActivityLog)['"\x60]`, // Mongoose
  String.raw`define\s*\(\s*['"\x60](audit\w*|activity_log)['"\x60]`, // Sequelize
  String.raw`(pg|mysql|sqlite)Table\s*\(\s*['"\x60](audit\w*|activity_log)['"\x60]`, // Drizzle
  String.raw`createTable\s*\(\s*['"\x60](audit\w*|activity_log)['"\x60]`, // Knex
].join('|'), 'i');

const FIELD_GROUPS = [
  { name: 'actor (who)', re: /\b(actor\w*|user_?id|userId|performed_?by|performedBy|principal\w*|admin_?id|created_?by|createdBy)\b/i },
  { name: 'action (what)', re: /\b(action|event(_?type|Type|_?name|Name)?|operation|activity|verb)\b/i },
  { name: 'target (on what)', re: /\b(target\w*|resource\w*|entity\w*|object_?(id|type)|objectId|record_?id|recordId|subject\w*)\b/i },
  { name: 'timestamp (when)', re: /\b(created_?at|createdAt|timestamp|occurred_?at|occurredAt|logged_?at|time|date)\b/i },
  { name: 'source (from where)', re: /\b(ip(_?address|Address)?|user_?agent|userAgent|source|origin|client\w*|session_?id|sessionId|request_?id|requestId)\b/i },
];

const SENSITIVE = /\b(password|passwd|secret|token|apiKey|api_key|cardNumber|cvv|ssn)\b/i;

function auditModels(ctx) {
  const pool = ctx.files.filter((f) => /\.(prisma|sql|[cm]?[jt]sx?)$/.test(f) && !ctx.isTestFile(f));
  return ctx.grep(AUDIT_MODEL_RE, { files: pool });
}

/** Text of an audit model declaration: following block or ~1500 chars. */
function modelBody(ctx, hit) {
  const text = ctx.read(hit.file) ?? '';
  const lines = text.split('\n');
  const start = lines.slice(0, hit.line - 1).join('\n').length;
  return text.slice(start, start + 1500);
}

function hasAuditing(ctx) {
  return ctx.contains(AUDIT_CALL) || auditModels(ctx).length > 0 || AUDIT_LIBS.some((l) => ctx.hasDep(l));
}

// ---------- quick checks ----------

const trailExists = defineCheck({
  id: 'AUD-001',
  title: 'An audit trail exists (who did what, when)',
  severity: 'high',
  tags: ['trail'],
  why: 'When a customer asks "who changed this?" or a breach is investigated, application logs are too noisy, too short-lived and too easy to alter.',
  fix: 'Create a dedicated audit store (an `audit_log` table, a separate collection or an external service like Retraced/WorkOS Audit Logs) and one `recordAudit()` helper every app uses.',
  docs: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#which-events-to-log'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const libs = AUDIT_LIBS.filter((l) => ctx.hasDep(l));
    const models = auditModels(ctx);
    const calls = ctx.grep(AUDIT_CALL, { limit: 1 });
    if (libs.length || models.length) return pass(`Audit store: ${[...libs, ...models.slice(0, 2).map((m) => `${m.file}:${m.line}`)].join(', ')}.`);
    if (calls.length) return warn('Audit calls exist but no dedicated audit table/model was found — make sure they go to durable storage, not just the app log.', calls);
    return fail('No audit trail: no audit model, table, library or audit calls found.');
  },
});

const recordShape = defineCheck({
  id: 'AUD-002',
  title: 'Audit records capture actor, action, target, time and source',
  severity: 'medium',
  tags: ['trail', 'schema'],
  why: 'An entry missing "who" or "on what" cannot answer the question it exists for.',
  fix: 'Store at least: actor_id (+ actor type), action (e.g. `order.refund`), target type + id, created_at (UTC, server time), ip / user agent / request id, and optional before/after diff.',
  run(ctx) {
    const models = auditModels(ctx);
    if (!models.length) return skip('No audit model/table found (see AUD-001).');
    const findings = [];
    for (const m of models) {
      const body = modelBody(ctx, m);
      const missing = FIELD_GROUPS.filter((g) => !g.re.test(body)).map((g) => g.name);
      if (missing.length) findings.push({ file: m.file, line: m.line, text: `missing: ${missing.join(', ')}` });
    }
    return findings.length ? fail(`${findings.length} audit model(s) are missing key fields.`, findings) : pass(`${models.length} audit model(s) have actor, action, target, time and source fields.`);
  },
});

const authEvents = defineCheck({
  id: 'AUD-003',
  title: 'Authentication events are audited (login, logout, failures, password/MFA changes)',
  severity: 'high',
  tags: ['auth'],
  why: 'Credential stuffing, account takeover and insider misuse all show up first in authentication events.',
  fix: 'Record `auth.login.success`, `auth.login.failure` (with reason, no password), `auth.logout`, `auth.password.reset`, `auth.mfa.changed` with user id, IP and user agent.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const authFiles = ctx.appCodeFiles.filter((f) => /['"`]\/(api\/)?(auth\/)?(login|signin|sign-in|logout|reset-password|forgot-password)\b|passport\.authenticate|signIn\s*\(|authorize\s*:\s*async/.test(ctx.read(f) ?? ''));
    if (!authFiles.length) {
      return ctx.hasDep('next-auth', '@auth/core', '@clerk/nextjs', '@auth0/nextjs-auth0', 'firebase', '@supabase/supabase-js')
        ? warn('Auth is delegated to a provider — enable and export its audit/event log (and tick AUD-M05).')
        : skip('No login/logout handlers found.');
    }
    const audited = authFiles.filter((f) => AUDIT_CALL.test(ctx.read(f) ?? '') || /(logger|log)\.(info|warn)\s*\([^)]*(login|sign.?in)\s*(failed|failure|success|succeeded)/i.test(ctx.read(f) ?? ''));
    if (audited.length === authFiles.length) return pass(`Auth events recorded in ${audited.join(', ')}.`);
    return fail('Login/logout handlers without audit events.', authFiles.filter((f) => !audited.includes(f)).map((f) => ({ file: f })));
  },
});

const privilegedActions = defineCheck({
  id: 'AUD-004',
  title: 'Admin and permission changes are audited',
  severity: 'high',
  tags: ['admin', 'authz'],
  why: 'Role grants, impersonation and admin edits are exactly what auditors and incident responders ask for first.',
  fix: 'Audit every role/permission change, user impersonation, admin data edit, data export and settings change — include before/after values.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const PRIV = /['"`]\/(api\/)?admin\b|\b(role|roles|permissions?|isAdmin|is_admin)\s*:\s*(req|request|body|input|data)\.|impersonat|\.(grant|revoke)(Role|Permission)\s*\(|update\w*Role\s*\(/i;
    const privFiles = ctx.appCodeFiles.filter((f) => PRIV.test(ctx.read(f) ?? ''));
    if (!privFiles.length) return skip('No admin routes or role-change code found.');
    const missing = privFiles.filter((f) => !AUDIT_CALL.test(ctx.read(f) ?? ''));
    if (!missing.length) return pass(`${privFiles.length} file(s) with privileged actions all record audit events.`);
    return fail(`${missing.length} file(s) change roles or run admin actions without audit events.`, missing.map((f) => ctx.grep(PRIV, { files: [f], limit: 1 })[0] ?? { file: f }));
  },
});

const tamperEvident = defineCheck({
  id: 'AUD-005',
  title: 'Audit records are append-only / tamper-evident',
  severity: 'high',
  tags: ['integrity'],
  why: 'An attacker (or insider) with app credentials will try to delete the evidence. If the app can UPDATE or DELETE audit rows, the trail proves nothing.',
  fix: 'Grant the app role INSERT/SELECT only (`REVOKE UPDATE, DELETE ON audit_log`), add a trigger that rejects updates, hash-chain entries (`prev_hash`), or ship to write-once storage (S3 Object Lock, CloudTrail Lake, a SIEM).',
  run(ctx) {
    if (!hasAuditing(ctx)) return skip('No audit trail (see AUD-001).');
    const mutations = ctx.grep(/\b(audit\w*|AuditLog|ActivityLog|auditLog|activityLog)\s*\.\s*(update\w*|delete\w*|destroy|remove|deleteMany|truncate|upsert)\s*\(|(update|delete\s+from|truncate)\s+["`]?(audit\w*|activity_log)/i);
    if (mutations.length) return fail('Application code updates or deletes audit records.', mutations);
    const sqlAndIac = ctx.files.filter((f) => /\.(sql|tf|ya?ml|json|prisma|[cm]?[jt]s)$/.test(f));
    const protectedHit = sqlAndIac.find((f) => /revoke\s+[^;]*(update|delete)[^;]*on\s+[^;]*(audit|activity)|before\s+(update|delete)\s+on\s+["`]?(audit|activity)|prev_?hash|previousHash|hash_?chain|ObjectLock(Mode|Configuration|Enabled)|object_lock|cloudtrail|WORM|immutable\s*:\s*true/i.test(ctx.read(f) ?? ''));
    if (protectedHit) return pass(`Append-only protection found in ${protectedHit}.`);
    return warn('No code mutates audit records, but nothing prevents it either (no REVOKE/trigger/hash chain/WORM storage found).');
  },
});

const changeHistory = defineCheck({
  id: 'AUD-006',
  title: 'Core records track who created/changed them and are soft-deleted',
  severity: 'medium',
  tags: ['data'],
  why: 'createdBy/updatedBy and soft deletes let you answer "who touched this record" and recover from mistakes without restoring backups.',
  fix: 'Add created_by / updated_by columns (set from the session, not the client) and deleted_at (Sequelize `paranoid: true`, TypeORM `@DeleteDateColumn`, Prisma extension). For regulated data, keep a history table.',
  run(ctx) {
    if (!ctx.stack.data.length) return skip('No database layer detected.');
    const pool = ctx.files.filter((f) => /\.(prisma|sql|[cm]?[jt]s)$/.test(f) && !ctx.isTestFile(f));
    const who = ctx.contains(/\b(created_?by|createdBy|updated_?by|updatedBy|modified_?by|modifiedBy|@CreatedBy|@UpdatedBy)\b/, { files: pool });
    const soft = ctx.contains(/\b(deleted_?at|deletedAt|paranoid\s*:\s*true|@DeleteDateColumn|softDelete|is_?deleted|isDeleted)\b/, { files: pool });
    const history = ctx.contains(/\b(\w+_history|\w+History|temporal|SYSTEM\s+VERSIONING|paper_?trail|versions?\s*table)\b/i, { files: pool });
    if (who && (soft || history)) return pass(`Found ${[who && 'created/updated by', soft && 'soft delete', history && 'history tables'].filter(Boolean).join(', ')}.`);
    if (who || soft || history) return warn(`Only ${[who && 'created/updated by', soft && 'soft delete', history && 'history tables'].filter(Boolean).join(', ')} — add the rest.`);
    return fail('No created_by/updated_by, soft delete or history tables found.');
  },
});

const noSecretsInAudit = defineCheck({
  id: 'AUD-007',
  title: 'Audit records do not contain secrets',
  severity: 'medium',
  tags: ['privacy'],
  why: 'Audit logs are kept for years and widely read during investigations — a password in an audit diff is a long-lived leak.',
  fix: 'Exclude credentials and tokens from audit payloads and before/after diffs; mask card numbers and personal identifiers.',
  run(ctx) {
    if (!hasAuditing(ctx)) return skip('No audit trail (see AUD-001).');
    const hits = ctx.grep(new RegExp(`(${AUDIT_CALL_SRC})[^;]*${SENSITIVE.source}`, 'i'));
    return hits.length ? fail('Audit calls include sensitive fields.', hits) : pass('No secrets passed to audit calls.');
  },
});

const retention = defineCheck({
  id: 'AUD-008',
  title: 'Audit retention period is enforced',
  severity: 'low',
  tags: ['retention', 'compliance'],
  why: 'Compliance frameworks require keeping audit data for a minimum time (often 1 year+), and privacy law requires not keeping it forever.',
  fix: 'Implement the policy: Mongo TTL index (`expireAfterSeconds`), partition drop / scheduled purge job, or storage lifecycle rules (S3 `Expiration`). Document the period.',
  run(ctx) {
    if (!hasAuditing(ctx)) return skip('No audit trail (see AUD-001).');
    const found = ctx.files.some((f) => /\.(sql|tf|ya?ml|json|[cm]?[jt]s)$/.test(f) && /expireAfterSeconds|AUDIT_RETENTION|retention_?days|retentionDays|retention_?period|lifecycle_rule|LifecycleConfiguration|interval\s+'\d+\s+(days?|months?|years?)'[^;]*audit|audit[^;]*interval\s+'\d+/i.test(ctx.read(f) ?? ''));
    return found ? pass('Retention configuration found.') : warn('No retention rule found for audit data — define one (and tick AUD-M01).');
  },
});

// ---------- in-depth (--review) ----------

const GLOBAL_AUDIT_RE = /\.use\s*\(\s*[^)]*audit|AuditInterceptor|@Audit\s*\(|useGlobalInterceptors\s*\([^)]*Audit|\$use\s*\([^)]*audit|\$extends\s*\([^)]*audit|plugin\s*\(\s*\w*[Aa]udit|addHook\s*\(\s*['"`]onResponse['"`][^)]*audit|afterCreate|afterUpdate|afterDestroy|@AfterInsert|@AfterUpdate|@AfterRemove|EntitySubscriberInterface/i;

const routesAudited = defineCheck({
  id: 'AUD-R01',
  review: true,
  title: 'State-changing routes record an audit event',
  severity: 'medium',
  tags: ['trail', 'routes'],
  why: 'Coverage gaps are the norm: the audit helper exists but half the write endpoints never call it.',
  fix: 'Call `recordAudit()` in each mutating handler, or add one central mechanism (audit middleware/interceptor, ORM hooks/subscribers) so new routes are covered by default.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    if (ctx.contains(GLOBAL_AUDIT_RE)) return pass('Central audit hook (middleware/interceptor/ORM hooks) in place.');
    const findings = [];
    let total = 0;
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code) continue;
      const routes = findRoutes(f, code).filter((r) => !PUBLIC_PATH_RE.test(r.path) || /login|signin|logout/i.test(r.path));
      if (!routes.length) continue;
      const lines = code.split('\n');
      for (const r of routes) {
        total++;
        let body;
        if (r.framework === 'express-like') {
          const start = lines.slice(0, r.line - 1).join('\n').length;
          const open = code.indexOf('(', start);
          body = extractArgs(code, open).args.at(-1) ?? '';
        } else {
          body = code.slice(lines.slice(0, r.line - 1).join('\n').length, lines.slice(0, r.line + 40).join('\n').length);
        }
        if (!AUDIT_CALL.test(body)) findings.push(ctx.at(f, r.line, `${r.method} ${r.path || '(dynamic)'} — no audit call in handler`));
      }
    }
    if (!total) return skip('No state-changing routes found.');
    if (!findings.length) return pass(`All ${total} mutating route(s) record audit events.`);
    return (findings.length === total ? fail : warn)(`${findings.length} of ${total} mutating route(s) do not record an audit event.`, findings);
  },
});

const spoofedActor = defineCheck({
  id: 'AUD-R02',
  review: true,
  title: 'Audit actor comes from the authenticated session, not the request',
  severity: 'high',
  tags: ['integrity', 'auth'],
  why: 'If the actor id is read from the body or a header, any user can write audit entries in someone else\'s name.',
  fix: 'Take the actor from the verified session/token (`req.user.id`, `ctx.state.user`, `session.user.id`) inside the audit helper itself.',
  run(ctx) {
    if (!hasAuditing(ctx)) return skip('No audit trail (see AUD-001).');
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code || !AUDIT_CALL.test(code)) continue;
      const lineOf = lineIndex(code);
      const re = new RegExp(AUDIT_CALL_SRC, 'gi');
      let m;
      while ((m = re.exec(code))) {
        const open = m.index + m[0].lastIndexOf('(');
        const args = extractArgs(code, open).args.join(',');
        if (/\b(actor\w*|user_?id|userId|performedBy|by)\s*:\s*(req|request|ctx\.request)\.(body|query|params|headers)\b|\b(actor\w*|userId|by)\s*:\s*(body|input|data|payload)\.\w+/i.test(args)
          || /^\s*(req|request)\.(body|query)\.\w*(user|actor)\w*\s*,/i.test(args)) {
          findings.push(ctx.at(f, lineOf(m.index), 'actor taken from request input'));
        }
      }
    }
    return findings.length ? fail('Audit actor can be spoofed.', unique(findings)) : pass('Audit actors come from server-side identity.');
  },
});

const deniedAccess = defineCheck({
  id: 'AUD-R03',
  review: true,
  title: 'Authorization denials (403) are recorded',
  severity: 'medium',
  tags: ['authz', 'security'],
  why: 'Repeated 403s are the signature of someone probing for IDOR / privilege escalation — but only if they are recorded.',
  fix: 'Record `authz.denied` with actor, resource and required permission wherever access is refused (ideally in the central guard).',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const denials = ctx.grep(/\.(status|sendStatus|code)\s*\(\s*403\s*\)|new\s+ForbiddenException|status\s*:\s*403|createError\s*\(\s*403|HTTPException\s*\(\s*403|throw\s+new\s+\w*Forbidden\w*/);
    if (!denials.length) return skip('No 403 responses found.');
    const silent = denials.filter((d) => {
      const lines = (ctx.code(d.file) ?? '').split('\n');
      const window = lines.slice(Math.max(0, d.line - 6), d.line + 3).join('\n');
      return !AUDIT_CALL.test(window) && !/\b(logger|log|this\.logger|req\.log)\.(warn|info|error)\s*\(/.test(window);
    });
    if (!silent.length) return pass(`${denials.length} authorization denial(s) are logged or audited.`);
    return fail(`${silent.length} of ${denials.length} 403 response(s) are not recorded.`, silent);
  },
});

// ---------- manual ----------

const manual = [
  {
    id: 'AUD-M01', title: 'Audit requirements are mapped to your obligations (SOC 2, ISO 27001, GDPR, HIPAA, PCI)', severity: 'high',
    why: 'Each framework dictates which events to record and for how long; guessing leaves gaps that fail audits.',
    fix: 'Write a one-page audit policy: event catalog, required fields, retention per event type, owners. Review yearly.',
  },
  {
    id: 'AUD-M02', title: 'Audit data is stored separately from app data, with restricted access', severity: 'high',
    why: 'If the same credentials that run the app can read and delete audit data, a compromise erases the trail.',
    fix: 'Separate database/schema, bucket or account; app can only append; read access limited to security/compliance roles and itself audited.',
  },
  {
    id: 'AUD-M03', title: 'Suspicious audit events raise alerts', severity: 'medium',
    why: 'An audit trail nobody watches only helps after the damage is done.',
    fix: 'Alert on: many failed logins, new admin role granted, impersonation, mass export/delete, access from new country, audit pipeline gaps.',
  },
  {
    id: 'AUD-M04', title: 'Audit history can be searched and exported for an investigation or customer request', severity: 'medium',
    why: 'Enterprise customers and regulators will ask for "all actions by user X between dates" — it must take minutes, not a project.',
    fix: 'Provide an internal (and optionally customer-facing) audit log viewer with filters and CSV/JSON export.',
  },
  {
    id: 'AUD-M05', title: 'Platform audit logs are enabled (cloud, database, git hosting, CI, identity provider)', severity: 'high',
    why: 'Many incidents happen outside your code: a leaked cloud key, a changed CI secret, a DB console query.',
    fix: 'Enable AWS CloudTrail / GCP Audit Logs / Azure Activity Log, pgaudit or DB audit, GitHub/GitLab audit log streaming, IdP sign-in logs; centralise them.',
  },
  {
    id: 'AUD-M06', title: 'All apps use synchronized clocks and UTC timestamps', severity: 'low',
    why: 'Reconstructing a timeline across services fails when clocks drift or timezones mix.',
    fix: 'NTP everywhere (default on managed platforms); store and compare timestamps in UTC (ISO 8601).',
  },
  {
    id: 'AUD-M07', title: 'Reads of sensitive data (PII, financial, health) are audited, not just writes', severity: 'medium',
    why: 'Data theft is reads. Regulations like HIPAA require access logging.',
    fix: 'Record access to sensitive records and all bulk exports with actor, purpose and record count.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'auditing',
  title: 'Auditing',
  description: 'A durable, trustworthy record of who did what, when and from where — for security investigations, customer questions and compliance.',
  checks: [
    trailExists, recordShape, authEvents, privilegedActions, tamperEvident, changeHistory, noSecretsInAudit, retention,
    routesAudited, spoofedActor, deniedAccess,
    ...manual,
  ],
});
