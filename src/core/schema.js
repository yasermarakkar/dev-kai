/**
 * Database schema model built from the project's schema sources:
 * Prisma schema, SQL migrations, Mongoose schemas, TypeORM entities, Sequelize models.
 *
 * Output (per table): columns, foreign keys and the set of columns that lead an index
 * (only the leading column of a B-tree index helps lookups on that column alone).
 */
import { extractArgs, lineIndex } from './lexer.js';

const norm = (s) => s.replace(/["`[\]]/g, '').split('.').pop().toLowerCase();
const camelToSnake = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

/** Equivalent names for one column (camelCase and snake_case). */
export function columnKeys(name) {
  const n = name.replace(/["`]/g, '');
  return new Set([n.toLowerCase(), camelToSnake(n), n.replace(/_([a-z])/g, (_, c) => c.toUpperCase()).toLowerCase()]);
}

function table(schema, name, file, line) {
  const key = norm(name);
  if (!schema.tables.has(key)) {
    schema.tables.set(key, { name: key, file, line, columns: new Set(), fks: [], indexed: new Set(), source: '' });
  }
  return schema.tables.get(key);
}

function addIndexed(t, col) {
  for (const k of columnKeys(col)) t.indexed.add(k);
}

// ---------------- Prisma ----------------

function parsePrisma(schema, file, text) {
  const lineOf = lineIndex(text);
  const provider = text.match(/datasource\s+\w+\s*\{[^}]*provider\s*=\s*"(\w+)"/);
  if (provider) schema.dialects.add(provider[1].toLowerCase());
  const modelRe = /^\s*model\s+(\w+)\s*\{/gm;
  let m;
  while ((m = modelRe.exec(text))) {
    const open = text.indexOf('{', m.index);
    const close = text.indexOf('\n}', open);
    const body = text.slice(open + 1, close === -1 ? undefined : close);
    const mapped = body.match(/@@map\(\s*"(\w+)"\s*\)/);
    const t = table(schema, mapped ? mapped[1] : m[1], file, lineOf(m.index));
    t.source = 'prisma';
    t.aliases = new Set([m[1].toLowerCase(), m[1].charAt(0).toLowerCase() + m[1].slice(1)]);
    let offset = open + 1;
    for (const raw of body.split('\n')) {
      const line = raw.replace(/\/\/.*$/, '').trim();
      const here = lineOf(offset);
      offset += raw.length + 1;
      if (!line) continue;
      const block = line.match(/^@@(index|unique|id)\s*\(\s*\[([^\]]+)\]/);
      if (block) {
        const first = block[2].split(',')[0].trim().replace(/\(.*$/, '');
        addIndexed(t, first);
        continue;
      }
      const field = line.match(/^(\w+)\s+(\w+)(\[\])?\??\s*(.*)$/);
      if (!field) continue;
      const [, name, type, list, attrs] = field;
      const relation = attrs.match(/@relation\([^)]*fields\s*:\s*\[([^\]]+)\]/);
      if (relation) {
        const first = relation[1].split(',')[0].trim();
        t.fks.push({ column: first, references: type, file, line: here });
        continue;
      }
      if (list || /^[A-Z]/.test(type) && !/^(String|Int|BigInt|Float|Decimal|Boolean|DateTime|Json|Bytes|Unsupported)$/.test(type)) continue; // relation field or enum
      t.columns.add(name);
      if (/@id\b|@unique\b/.test(attrs)) addIndexed(t, name);
    }
  }
}

// ---------------- SQL ----------------

function parseSql(schema, file, text) {
  const clean = text.replace(/--.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '));
  const lineOf = lineIndex(clean);
  if (/\bAUTO_INCREMENT\b|ENGINE\s*=\s*InnoDB/i.test(clean)) schema.dialects.add('mysql');
  if (/\bBIGSERIAL\b|\bSERIAL\b|\bTIMESTAMPTZ\b|\bJSONB\b|\bCONCURRENTLY\b/i.test(clean)) schema.dialects.add('postgresql');

  const createRe = /create\s+table\s+(?:if\s+not\s+exists\s+)?([\w."`[\]]+)\s*\(/gi;
  let m;
  while ((m = createRe.exec(clean))) {
    const open = clean.indexOf('(', m.index + m[0].length - 1);
    const { args } = extractArgs(clean, open);
    const t = table(schema, m[1], file, lineOf(m.index));
    t.source = t.source || 'sql';
    for (const def of args) {
      const d = def.replace(/\s+/g, ' ').trim();
      const tableLevel = d.match(/^(?:constraint \S+ )?(primary key|unique|foreign key)\s*\(([^)]+)\)(.*)$/i);
      if (tableLevel) {
        const first = tableLevel[2].split(',')[0].trim();
        if (/foreign/i.test(tableLevel[1])) {
          const ref = tableLevel[3].match(/references\s+([\w."`]+)/i);
          t.fks.push({ column: norm(first), references: ref ? norm(ref[1]) : '?', file, line: lineOf(clean.indexOf(def, open)) });
        } else addIndexed(t, norm(first));
        continue;
      }
      if (/^(constraint|check|exclude|index|key)\b/i.test(d)) {
        const k = d.match(/^(?:unique )?(?:index|key)\s+\S*\s*\(([^)]+)\)/i);
        if (k) addIndexed(t, norm(k[1].split(',')[0]));
        continue;
      }
      const col = d.match(/^([\w"`]+)\s+/);
      if (!col) continue;
      const name = norm(col[1]);
      t.columns.add(name);
      if (/\bprimary key\b|\bunique\b/i.test(d)) addIndexed(t, name);
      const ref = d.match(/\breferences\s+([\w."`]+)/i);
      if (ref) t.fks.push({ column: name, references: norm(ref[1]), file, line: lineOf(clean.indexOf(def, open)) });
    }
  }

  const idxRe = /create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?(?:[\w"`]+\s+)?on\s+(?:only\s+)?([\w."`]+)\s*(?:using\s+\w+\s*)?\(\s*([^,)\s]+)/gi;
  while ((m = idxRe.exec(clean))) addIndexed(table(schema, m[1], file, lineOf(m.index)), norm(m[2]));

  const alterFk = /alter\s+table\s+(?:only\s+)?([\w."`]+)[^;]*?foreign\s+key\s*\(\s*([^,)\s]+)[^;]*?references\s+([\w."`]+)/gi;
  while ((m = alterFk.exec(clean))) table(schema, m[1], file, lineOf(m.index)).fks.push({ column: norm(m[2]), references: norm(m[3]), file, line: lineOf(m.index) });
  const alterPk = /alter\s+table\s+(?:only\s+)?([\w."`]+)[^;]*?(primary\s+key|unique)\s*\(\s*([^,)\s]+)/gi;
  while ((m = alterPk.exec(clean))) addIndexed(table(schema, m[1], file, lineOf(m.index)), norm(m[3]));
}

// ---------------- Mongoose ----------------

function parseMongoose(schema, file, code) {
  if (!/new\s+(mongoose\.)?Schema\s*\(|\bSchema\s*\(/.test(code)) return;
  schema.dialects.add('mongodb');
  const lineOf = lineIndex(code);
  const modelName = (code.match(/model\s*\(\s*['"`](\w+)['"`]/) ?? [])[1] ?? file.split('/').pop().replace(/\.\w+$/, '');
  const t = table(schema, modelName, file, 1);
  t.source = 'mongoose';
  t.aliases = new Set([modelName.toLowerCase()]);
  addIndexed(t, '_id');
  const re = /new\s+(?:mongoose\.)?Schema\s*\(\s*\{/g;
  let m;
  while ((m = re.exec(code))) {
    const open = code.indexOf('{', m.index);
    t.line = lineOf(m.index);
    for (const entry of extractArgs(code, open).args) {
      const kv = entry.match(/^['"]?(\w+)['"]?\s*:\s*([\s\S]*)$/);
      if (!kv) continue;
      t.columns.add(kv[1]);
      if (/\b(index|unique)\s*:\s*true/.test(kv[2])) addIndexed(t, kv[1]);
      if (/\bref\s*:/.test(kv[2])) t.fks.push({ column: kv[1], references: (kv[2].match(/ref\s*:\s*['"`](\w+)/) ?? [])[1] ?? '?', file, line: lineOf(code.indexOf(entry, open)), mongo: true });
    }
  }
  const idx = /\.index\s*\(\s*\{\s*['"]?([\w.]+)['"]?\s*:/g;
  while ((m = idx.exec(code))) addIndexed(t, m[1]);
}

// ---------------- TypeORM ----------------

function parseTypeorm(schema, file, code) {
  if (!/@Entity\s*\(/.test(code)) return;
  const lineOf = lineIndex(code);
  const cls = /@Entity\s*\(\s*(?:['"`](\w+)['"`]|\{[^}]*name\s*:\s*['"`](\w+)['"`][^}]*\})?\s*\)[\s\S]*?class\s+(\w+)/g;
  let m;
  while ((m = cls.exec(code))) {
    const t = table(schema, m[1] ?? m[2] ?? camelToSnake(m[3]), file, lineOf(m.index));
    t.source = 'typeorm';
    t.aliases = new Set([m[3].toLowerCase()]);
    const bodyStart = code.indexOf('{', m.index + m[0].length - 1);
    const body = code.slice(bodyStart, extractArgs(code, bodyStart).end);
    const before = code.slice(Math.max(0, m.index - 400), m.index);
    for (const ci of before.matchAll(/@(Index|Unique)\s*\(\s*(?:['"`]\w+['"`]\s*,\s*)?\[\s*['"`](\w+)/g)) addIndexed(t, ci[2]);
    const propRe = /((?:@\w+\s*\([^)]*\)\s*)+)(\w+)\s*[!?]?\s*:/g;
    let p;
    while ((p = propRe.exec(body))) {
      const decos = p[1];
      const name = p[2];
      if (/@PrimaryGeneratedColumn|@PrimaryColumn/.test(decos)) addIndexed(t, name);
      if (/@Index\s*\(|unique\s*:\s*true|@Unique/.test(decos)) addIndexed(t, name);
      if (/@(ManyToOne|OneToOne)\s*\(/.test(decos)) {
        const jc = decos.match(/@JoinColumn\s*\(\s*\{[^}]*name\s*:\s*['"`](\w+)/);
        const col = jc ? jc[1] : `${name}Id`;
        t.fks.push({ column: col, references: name, file, line: lineOf(bodyStart + p.index) });
        if (/@Index\s*\(/.test(decos)) addIndexed(t, col);
      } else if (/@(Column|CreateDateColumn|UpdateDateColumn|DeleteDateColumn|PrimaryGeneratedColumn|PrimaryColumn)/.test(decos)) {
        t.columns.add(name);
      }
    }
  }
}

// ---------------- Sequelize ----------------

function parseSequelize(schema, file, code) {
  const lineOf = lineIndex(code);
  const re = /\.define\s*\(\s*['"`](\w+)['"`]\s*,\s*\{|\.init\s*\(\s*\{/g;
  let m;
  while ((m = re.exec(code))) {
    const open = code.indexOf('{', m.index + m[0].length - 1);
    const { args: fields, end } = extractArgs(code, open);
    const rest = code.slice(end, end + 1500);
    const name = m[1] ?? (rest.match(/(tableName|modelName)\s*:\s*['"`](\w+)/) ?? [])[2] ?? (code.slice(0, m.index).match(/class\s+(\w+)\s+extends\s+Model/g) ?? []).pop()?.split(/\s+/)[1];
    if (!name) continue;
    const t = table(schema, name, file, lineOf(m.index));
    t.source = 'sequelize';
    t.aliases = new Set([name.toLowerCase()]);
    addIndexed(t, 'id');
    for (const f of fields) {
      const kv = f.match(/^['"]?(\w+)['"]?\s*:\s*([\s\S]*)$/);
      if (!kv) continue;
      t.columns.add(kv[1]);
      if (/\b(unique|primaryKey)\s*:\s*true/.test(kv[2])) addIndexed(t, kv[1]);
      if (/\breferences\s*:/.test(kv[2])) t.fks.push({ column: kv[1], references: (kv[2].match(/model\s*:\s*['"`]?(\w+)/) ?? [])[1] ?? '?', file, line: lineOf(code.indexOf(f, open)) });
    }
    for (const ix of rest.matchAll(/fields\s*:\s*\[\s*['"`](\w+)/g)) addIndexed(t, ix[1]);
  }
}

/**
 * Build the schema model for a project context.
 * @returns {{ tables: Map<string, any>, dialects: Set<string>, sources: string[] }}
 */
export function buildSchema(ctx) {
  if (ctx._schema) return ctx._schema;
  const schema = { tables: new Map(), dialects: new Set(), sources: [] };
  for (const f of ctx.files) {
    if (ctx.isTestFile(f)) continue;
    if (f.endsWith('.prisma')) { parsePrisma(schema, f, ctx.read(f) ?? ''); schema.sources.push(f); continue; }
    if (f.endsWith('.sql')) { parseSql(schema, f, ctx.read(f) ?? ''); schema.sources.push(f); continue; }
    if (!ctx.codeFiles.includes(f)) continue;
    const code = ctx.code(f) ?? '';
    const before = schema.tables.size;
    if (/mongoose|Schema\s*\(/.test(code)) parseMongoose(schema, f, code);
    if (/@Entity\s*\(/.test(code)) parseTypeorm(schema, f, code);
    if (/\.define\s*\(\s*['"`]|\.init\s*\(\s*\{|extends\s+Model\b/.test(code)) parseSequelize(schema, f, code);
    // knex / raw SQL migrations in JS: createTable + table.index(...)
    if (/createTable\s*\(/.test(code)) {
      for (const ct of code.matchAll(/createTable\s*\(\s*['"`](\w+)['"`]/g)) {
        const t = table(schema, ct[1], f, 1);
        t.source = 'knex';
        const seg = code.slice(ct.index, ct.index + 3000);
        for (const c of seg.matchAll(/\.(?:integer|bigInteger|string|uuid|text|boolean|timestamp|date|decimal|float|increments|bigIncrements)\s*\(\s*['"`](\w+)/g)) t.columns.add(c[1]);
        for (const p of seg.matchAll(/\.(?:increments|bigIncrements)\s*\(\s*['"`](\w+)|\.(?:primary|unique|index)\s*\(\s*\[?\s*['"`](\w+)/g)) addIndexed(t, p[1] ?? p[2]);
        for (const c of seg.matchAll(/['"`](\w+)['"`]\s*\)[^;\n]*?\.(unique|primary|index)\s*\(/g)) addIndexed(t, c[1]);
        for (const fk of seg.matchAll(/['"`](\w+)['"`]\s*\)[^;\n]*?\.references\s*\(\s*['"`]([\w.]+)/g)) t.fks.push({ column: fk[1], references: fk[2].split('.')[0], file: f, line: lineIndex(code)(ct.index) });
      }
    }
    if (schema.tables.size > before) schema.sources.push(f);
  }
  ctx._schema = schema;
  return schema;
}

/** Is this column covered by an index (as leading column) on the table? */
export function isIndexed(t, column) {
  for (const k of columnKeys(column)) if (t.indexed.has(k)) return true;
  return false;
}

/** Resolve a code-side model / table reference (e.g. `prisma.orderItem`, `FROM order_items`, `Order`) to a table. */
export function resolveTable(schema, ref) {
  if (!ref) return null;
  const r = ref.toLowerCase();
  const candidates = [r, camelToSnake(ref), `${r}s`, `${camelToSnake(ref)}s`, r.replace(/s$/, '')];
  for (const c of candidates) if (schema.tables.has(c)) return schema.tables.get(c);
  for (const t of schema.tables.values()) if (t.aliases?.has(r)) return t;
  return null;
}
