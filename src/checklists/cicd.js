import path from 'node:path';
import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';

// ---------- shared ----------

const CI_FILE = /^(\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.yml|\.gitlab\/ci\/.+\.ya?ml|\.circleci\/config\.yml|azure-pipelines\.yml|\.azure-pipelines\/.+\.ya?ml|bitbucket-pipelines\.yml|Jenkinsfile|\.buildkite\/.+\.ya?ml|\.drone\.yml|\.woodpecker\.ya?ml|\.woodpecker\/.+\.ya?ml|cloudbuild\.ya?ml|buildspec\.ya?ml|\.travis\.yml)$/;
const GH_WORKFLOW = /^\.github\/workflows\/[^/]+\.ya?ml$/;
const TEST_FRAMEWORKS = ['jest', 'vitest', 'mocha', 'ava', 'tap', 'uvu', '@playwright/test', 'playwright', 'cypress', 'jasmine', '@japa/runner', 'node-tap', 'karma', '@web/test-runner', 'bun-types'];
const LINTERS = ['eslint', '@biomejs/biome', 'oxlint', 'standard', 'xo', 'tslint', 'rome'];
const CRITICAL_NAME = /(auth|login|session|payment|billing|checkout|order|invoice|refund|account|admin|webhook|permission|role|subscription|transfer)/i;

const ciFiles = (ctx) => ctx.findFiles(CI_FILE);
const ciText = (ctx) => ciFiles(ctx).map((f) => ctx.read(f) ?? '').join('\n');

const scriptsOf = (ctx) => ctx.apps.map((a) => ({ app: a, scripts: a.pkg.scripts ?? {} }));

/** Test files (code files the context classifies as tests, excluding fixtures and load tests). */
const testFiles = (ctx) => ctx.codeFiles.filter((f) => ctx.isTestFile(f) && !/(^|\/)(fixtures?|__mocks__|load-?tests?|perf|k6|bench(marks?)?)\//.test(f) && !/\.(k6|bench)\./.test(f));

/** Expand `npm run x` → the script body, so CI calling `npm run ci` still counts. */
function ciCommands(ctx) {
  let text = ciText(ctx);
  const scripts = Object.assign({}, ...scriptsOf(ctx).map((s) => s.scripts));
  for (let i = 0; i < 2; i++) {
    text = text.replace(/\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?([\w:.-]+)/g, (m, name) => (scripts[name] ? `${m} ${scripts[name]}` : m));
  }
  return text;
}

/** Each `uses:` reference in GitHub workflows: [{ file, line, ref, owner, version }]. */
function actionRefs(ctx) {
  const out = [];
  for (const f of ctx.findFiles(GH_WORKFLOW)) {
    (ctx.read(f) ?? '').split('\n').forEach((text, i) => {
      const m = text.match(/^\s*-?\s*uses\s*:\s*['"]?([^'"\s#]+)/);
      if (!m || m[1].startsWith('./') || m[1].startsWith('docker://')) return;
      const [name, version = ''] = m[1].split('@');
      out.push({ file: f, line: i + 1, text: text.trim(), ref: m[1], owner: name.split('/')[0], version });
    });
  }
  return out;
}

// ---------- quick checks ----------

const pipeline = defineCheck({
  id: 'CI-001',
  title: 'A CI pipeline runs on every change',
  severity: 'high',
  tags: ['ci'],
  why: 'Without CI, "it works on my machine" is the only quality gate, and every check in these checklists depends on someone remembering to run it.',
  fix: 'Add a pipeline (GitHub Actions, GitLab CI, CircleCI…) that runs on every pull request and push to main: install, lint, typecheck, test, build.',
  run(ctx) {
    const files = ciFiles(ctx);
    if (!files.length) return fail('No CI configuration found.');
    const onPr = /pull_request|merge_request|on:\s*\[?[^\]\n]*push|branches\s*:|only\s*:|rules\s*:|workflow:|trigger\s*:|pr\s*:/.test(ciText(ctx));
    return onPr ? pass(`CI: ${files.join(', ')}.`) : warn('CI config exists but no push/pull-request trigger was found.', files.map((f) => ({ file: f })));
  },
});

const testsExist = defineCheck({
  id: 'CI-002',
  title: 'Automated tests exist and `npm test` runs them',
  severity: 'high',
  tags: ['tests'],
  why: 'Tests are what make every other improvement (refactors, upgrades, scaling work) safe to ship.',
  fix: 'Pick a runner (Vitest, Jest, node:test, Playwright for E2E), add tests for the critical flows first (auth, payments, orders) and set `"test"` in package.json.',
  run(ctx) {
    if (!ctx.apps.length) return skip('No Node project.');
    const tests = testFiles(ctx);
    const framework = TEST_FRAMEWORKS.filter((t) => ctx.hasDep(t));
    const placeholder = scriptsOf(ctx).filter(({ scripts }) => !scripts.test || /no test specified|exit 1/.test(scripts.test));
    const appsWithCode = ctx.apps.filter((a) => ctx.appCodeFiles.some((f) => ctx.ownerOf(f) === a.dir));
    if (!tests.length) return fail('No test files found.');
    if (placeholder.length === ctx.apps.length) return fail(`${tests.length} test file(s) but no working "test" script.`, placeholder.map(({ app }) => ({ file: path.posix.join(app.dir, 'package.json') })));
    const missing = appsWithCode.filter((a) => !a.pkg.scripts?.test || /no test specified/.test(a.pkg.scripts.test));
    if (missing.length && ctx.apps.length > 1) return warn(`${missing.length} app(s) have no test script.`, missing.map((a) => ({ file: path.posix.join(a.dir, 'package.json') })));
    return pass(`${tests.length} test file(s)${framework.length ? ` using ${framework.join(', ')}` : ''}.`);
  },
});

const ciRunsTests = defineCheck({
  id: 'CI-003',
  title: 'CI runs the test suite',
  severity: 'high',
  tags: ['ci', 'tests'],
  why: 'Tests that only run locally stop running the day someone is in a hurry.',
  fix: 'Add a test step (`npm test`, `pnpm -r test`, `turbo run test`) to the CI job that runs on pull requests, and make it a required check.',
  run(ctx) {
    if (!ciFiles(ctx).length) return skip('No CI (see CI-001).');
    const cmds = ciCommands(ctx);
    return /\b(npm|pnpm|yarn|bun)\s+(run\s+)?test\b|\b(vitest|jest|mocha|ava|playwright\s+test|cypress\s+run|node\s+--test|tap)\b|turbo\s+(run\s+)?test|nx\s+(affected|run-many)[^\n]*test/.test(cmds)
      ? pass('CI runs tests.')
      : fail('CI does not run any tests.', ciFiles(ctx).map((f) => ({ file: f })));
  },
});

const lintTypecheck = defineCheck({
  id: 'CI-004',
  title: 'Lint and type checks run in CI',
  severity: 'medium',
  tags: ['ci', 'quality'],
  why: 'Linters and the type checker catch whole classes of bugs (unused awaits, undefined variables, wrong types) before review.',
  fix: 'Add ESLint (or Biome) with a CI step `npm run lint`; for TypeScript add `tsc --noEmit` (or `npm run typecheck`).',
  run(ctx) {
    if (!ctx.apps.length) return skip('No Node project.');
    const cmds = ciFiles(ctx).length ? ciCommands(ctx) : '';
    const lintConfigured = LINTERS.some((l) => ctx.hasDep(l)) || ctx.findFiles(/(^|\/)(\.eslintrc(\.\w+)?|eslint\.config\.[cm]?[jt]s|biome\.jsonc?|\.oxlintrc\.json)$/).length > 0;
    const lintInCi = /\b(eslint|biome\s+(ci|check|lint)|oxlint|next\s+lint|xo|standard)\b|\b(npm|pnpm|yarn|bun)\s+(run\s+)?lint\b/.test(cmds);
    const ts = ctx.stack.typescript;
    const tscInCi = !ts || /\btsc\b[^\n]*(--noEmit|-p|--build|-b)|\b(npm|pnpm|yarn|bun)\s+(run\s+)?(typecheck|type-check|types|check-types|tsc)\b|vue-tsc|svelte-check|astro\s+check|next\s+build/.test(cmds);
    const missing = [!lintConfigured ? 'no linter configured' : !lintInCi ? 'linter not run in CI' : null, !tscInCi ? 'TypeScript not type-checked in CI' : null].filter(Boolean);
    if (!missing.length) return pass(ts ? 'Lint and typecheck run in CI.' : 'Lint runs in CI.');
    return (missing.length === 2 || !lintConfigured ? fail : warn)(missing.join('; ') + '.');
  },
});

const coverage = defineCheck({
  id: 'CI-005',
  title: 'Test coverage is measured with a minimum threshold',
  severity: 'medium',
  tags: ['tests', 'quality'],
  why: 'A threshold stops coverage from quietly eroding, and the report shows which critical files have no tests at all.',
  fix: 'Vitest: `coverage: { thresholds: { lines: 70 } }`; Jest: `coverageThreshold`; c8/nyc `--check-coverage`. Upload to Codecov/Coveralls to see it on every PR.',
  run(ctx) {
    if (!testFiles(ctx).length) return skip('No tests (see CI-002).');
    const configs = ctx.findFiles(/(^|\/)(jest\.config\.[cm]?[jt]s|vitest\.config\.[cm]?[jt]s|vite\.config\.[cm]?[jt]s|\.c8rc(\.json)?|\.nycrc(\.json)?|package\.json|codecov\.ya?ml|\.github\/workflows\/.+)$/);
    const text = configs.map((f) => ctx.read(f) ?? '').join('\n');
    const threshold = /coverageThreshold|thresholds\s*:|check-coverage|--lines\s+\d|"lines"\s*:\s*\d|fail_ci_if_error|target\s*:\s*\d+%|--test-coverage-(lines|branches|functions)=\d/.test(text);
    const measured = threshold || /--coverage|coverage\s*:\s*\{|\bc8\b|\bnyc\b|codecov|coveralls|--experimental-test-coverage/.test(text);
    if (threshold) return pass('Coverage threshold enforced.');
    if (measured) return warn('Coverage is measured but no minimum is enforced.');
    return fail('Coverage is not measured.');
  },
});

const ownership = defineCheck({
  id: 'CI-006',
  title: 'Code ownership and PR templates are defined',
  severity: 'low',
  tags: ['review'],
  why: 'CODEOWNERS routes changes (migrations, auth, infra) to the people who must review them; a PR template prompts for tests, rollout and risk.',
  fix: 'Add `.github/CODEOWNERS` (or GitLab equivalent) and a pull request template with a short checklist.',
  run(ctx) {
    const owners = ctx.findFiles(/(^|\/)(\.github\/|\.gitlab\/|docs\/)?CODEOWNERS$/);
    const template = ctx.findFiles(/(^|\/)(\.github\/)?(pull_request_template\.md|PULL_REQUEST_TEMPLATE(\.md|\/.+))$|\.gitlab\/merge_request_templates\//i);
    if (owners.length && template.length) return pass('CODEOWNERS and PR template present.');
    if (owners.length || template.length) return warn(`Missing ${owners.length ? 'PR template' : 'CODEOWNERS'}.`);
    return warn('No CODEOWNERS or PR template.');
  },
});

const delivery = defineCheck({
  id: 'CI-007',
  title: 'Deployments are automated (CD), not run from laptops',
  severity: 'medium',
  tags: ['cd'],
  why: 'Manual deploys are slow, unrepeatable and need production credentials on developer machines.',
  fix: 'Deploy from the pipeline after tests pass (container push + rollout, or the platform\'s Git integration). Keep production credentials only in CI.',
  run(ctx) {
    const cmds = ciFiles(ctx).length ? ciCommands(ctx) : '';
    const inCi = /\bdeploy\b|vercel\b|netlify\s+deploy|flyctl\s+deploy|fly\s+deploy|aws\s+ecs\s+update-service|ecs-deploy|kubectl\s+(apply|set\s+image|rollout)|helm\s+(upgrade|install)|argocd|serverless\s+deploy|sls\s+deploy|cdk\s+deploy|railway\s+up|gcloud\s+(run|app)\s+deploy|docker\s+(push|buildx[^\n]*--push)|terraform\s+apply|pulumi\s+up|render-deploy|heroku|npm\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|changeset\s+publish|semantic-release|changesets\/action/i.test(cmds);
    const platform = ctx.findFiles(/(^|\/)(vercel\.json|netlify\.toml|render\.ya?ml|fly\.toml|app\.ya?ml|Procfile|railway\.(json|toml)|amplify\.ya?ml|apprunner\.ya?ml|skaffold\.ya?ml|argocd\/.+|\.platform\.app\.yaml)$/);
    if (inCi) return pass('Deploy step in CI.');
    if (platform.length) return pass(`Platform Git deploys (${platform[0]}).`);
    return fail('No automated deployment found.');
  },
});

const environments = defineCheck({
  id: 'CI-008',
  title: 'Changes pass through a staging/preview environment first',
  severity: 'medium',
  tags: ['cd', 'environments'],
  why: 'Migrations, config and integrations break in ways tests do not catch; staging is where you find out without customers.',
  fix: 'Deploy every merge to staging (or a preview per PR), run smoke tests there, then promote the same artifact to production — ideally with a required approval on the production environment.',
  run(ctx) {
    if (!ctx.stack.hasBackend && !ctx.stack.frontend.length) return skip('Library/CLI package — no environment to stage.');
    const text = ciText(ctx);
    const files = ctx.files.filter((f) => /\.(ya?ml|json|toml|tf)$/.test(f) || /\.env\.[\w-]+\.(example|sample)$/.test(f));
    const staged = /\b(staging|stage|preview|uat|qa|preprod|pre-prod)\b/i.test(text) || files.some((f) => /staging|preview|preprod/i.test(f));
    const prodGate = /environment\s*:\s*(\n\s*name\s*:\s*)?['"]?(production|prod)\b|when\s*:\s*manual|approval|requires\s*:\s*\[?\s*\w*hold|type\s*:\s*approval/i.test(text);
    if (!ciFiles(ctx).length && !staged) return skip('No CI/CD config (see CI-001).');
    if (staged && prodGate) return pass('Staging/preview environment and gated production deploys.');
    if (staged) return warn('Staging/preview exists, but production deploys have no environment gate/approval.');
    return fail('No staging or preview environment referenced.');
  },
});

const reproducibleInstalls = defineCheck({
  id: 'CI-009',
  title: 'CI and image builds use frozen-lockfile installs',
  severity: 'medium',
  tags: ['ci', 'supply-chain'],
  why: '`npm install` in CI can update the lockfile and pull versions nobody reviewed — the build is no longer what was tested.',
  fix: 'Use `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable` / `--frozen-lockfile`, `bun install --frozen-lockfile` in CI and Dockerfiles; cache the package store.',
  run(ctx) {
    const sources = [...ciFiles(ctx), ...ctx.findFiles(/(^|\/)Dockerfile[^/]*$/).filter((f) => !ctx.isTestFile(f))];
    if (!sources.length) return skip('No CI or Dockerfiles.');
    // A "loose" install is a project install (no package names) without a frozen-lockfile flag.
    const isLoose = (cmd) => {
      const flagsOnly = (rest) => rest.trim().split(/\s+/).filter(Boolean).every((t) => t.startsWith('-'));
      let m;
      if ((m = cmd.match(/^npm\s+(install|i)\b(.*)$/))) return flagsOnly(m[2]) && !/(^|\s)(-g|--global)\b/.test(m[2]);
      if ((m = cmd.match(/^yarn(\s+install)?(\s+.*)?$/))) return flagsOnly(m[2] ?? '') && !/--frozen-lockfile|--immutable/.test(m[2] ?? '');
      if ((m = cmd.match(/^pnpm\s+(install|i)\b(.*)$/))) return flagsOnly(m[2]) && !/--frozen-lockfile/.test(m[2]);
      if ((m = cmd.match(/^bun\s+(install|i)\b(.*)$/))) return flagsOnly(m[2]) && !/--frozen-lockfile/.test(m[2]);
      return false;
    };
    const loose = [];
    for (const f of sources) {
      (ctx.read(f) ?? '').split('\n').forEach((line, i) => {
        const body = line.replace(/^\s*(-\s*)?(run\s*:\s*\|?|RUN\s+(--mount=\S+\s+)*|script\s*:\s*|-\s+)/i, '').replace(/^\s*-\s+/, '');
        const cmds = body.split(/&&|;|\|\|/).map((c) => c.trim().replace(/^['"]|['"]$/g, ''));
        if (cmds.some(isLoose)) loose.push({ file: f, line: i + 1, text: line.trim() });
      });
    }
    return loose.length ? fail('Installs that can change the lockfile.', loose) : pass('Frozen-lockfile installs everywhere.');
  },
});

const pinnedActions = defineCheck({
  id: 'CI-010',
  title: 'Third-party CI actions are pinned to a commit SHA',
  severity: 'medium',
  tags: ['ci', 'supply-chain'],
  why: 'A tag like `@v3` or a branch like `@main` can be moved by the action\'s author (or an attacker) to run new code with your secrets — as happened with tj-actions/changed-files in 2025.',
  fix: 'Pin third-party actions to a full commit SHA with the version as a comment (`uses: owner/action@<40-char-sha> # v3.1.0`); let Dependabot/Renovate update them.',
  docs: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions'],
  run(ctx) {
    const refs = actionRefs(ctx);
    if (!refs.length) return skip('No GitHub Actions workflows.');
    const firstParty = /^(actions|github|docker|aws-actions|azure|google-github-actions|hashicorp)$/i;
    const branch = refs.filter((r) => !r.version || /^(main|master|latest|dev|develop|HEAD)$/i.test(r.version));
    const tagged3p = refs.filter((r) => !firstParty.test(r.owner) && r.version && !/^[0-9a-f]{40}$/.test(r.version) && !branch.includes(r));
    if (branch.length) return fail(`${branch.length} action(s) on a branch or unpinned.`, [...branch, ...tagged3p]);
    if (tagged3p.length) return warn(`${tagged3p.length} third-party action(s) pinned to a movable tag.`, tagged3p);
    return pass('Actions are pinned (third-party by SHA).');
  },
});

const workflowSafety = defineCheck({
  id: 'CI-011',
  title: 'Workflows use least-privilege tokens and are safe from injection',
  severity: 'high',
  tags: ['ci', 'security'],
  why: 'PR titles, branch names and issue bodies are attacker-controlled; interpolating them into `run:` executes their shell code with your token. `pull_request_target` + checking out PR code hands secrets to forks.',
  fix: 'Set `permissions: contents: read` at the top and grant more per job; pass untrusted values via `env:` and quote them ("$TITLE"); never check out PR head code in `pull_request_target`; never echo secrets.',
  docs: ['https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/'],
  run(ctx) {
    const wf = ctx.findFiles(GH_WORKFLOW);
    if (!wf.length) return skip('No GitHub Actions workflows.');
    const findings = [];
    for (const f of wf) {
      const text = ctx.read(f) ?? '';
      const lines = text.split('\n');
      if (!/^permissions\s*:/m.test(text) && !/^\s{4}permissions\s*:/m.test(text)) findings.push({ file: f, line: 1, text: 'no permissions: block (token defaults may be read/write)' });
      const UNTRUSTED = /\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)\b[^}]*\.(title|body|message|name|label|ref|email|head_ref)|head_ref)\s*\}\}/;
      let runIndent = -1; // indentation of the current `run:` key, -1 when outside a run block
      lines.forEach((l, i) => {
        const indent = l.match(/^\s*/)[0].length;
        const runKey = l.match(/^(\s*)(-\s+)?run\s*:\s*(.*)$/);
        let inShell = false;
        if (runKey) {
          runIndent = runKey[1].length + (runKey[2] ? 2 : 0);
          inShell = !/^[|>][-+]?\s*$/.test(runKey[3]) && runKey[3].length > 0; // inline command
        } else if (runIndent >= 0 && l.trim() && indent > runIndent) {
          inShell = true; // continuation of a multi-line run: block
        } else if (l.trim()) {
          runIndent = -1;
        }
        if (/permissions\s*:\s*write-all/.test(l)) findings.push({ file: f, line: i + 1, text: l.trim() });
        if (inShell && UNTRUSTED.test(l)) findings.push({ file: f, line: i + 1, text: `untrusted input in shell: ${l.trim()}` });
        if (inShell && /\b(echo|printf)\b[^\n]*\$\{\{\s*secrets\./.test(l)) findings.push({ file: f, line: i + 1, text: `secret printed: ${l.trim().replace(/secrets\.\w+/g, 'secrets.****')}` });
      });
      if (/pull_request_target/.test(text) && /ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref/.test(text)) {
        findings.push({ file: f, line: lines.findIndex((l) => /pull_request_target/.test(l)) + 1, text: 'pull_request_target checks out untrusted PR code' });
      }
    }
    const serious = findings.filter((x) => !/no permissions/.test(x.text));
    if (serious.length) return fail(`${serious.length} dangerous workflow pattern(s).`, unique(findings));
    if (findings.length) return warn('Workflows without an explicit permissions block.', findings);
    return pass('Workflows set least-privilege permissions; no injection patterns.');
  },
});

const hooks = defineCheck({
  id: 'CI-012',
  title: 'Formatting and quick checks run before commit',
  severity: 'low',
  tags: ['dx', 'quality'],
  why: 'Pre-commit hooks keep noise (formatting, lint autofixes) out of review and give feedback in seconds instead of after a CI run.',
  fix: 'Add Prettier or Biome format checks, and husky/lefthook + lint-staged to run them on staged files.',
  run(ctx) {
    if (!ctx.apps.length) return skip('No Node project.');
    const hook = ctx.hasDep('husky', 'lefthook', 'simple-git-hooks', 'pre-commit', '@commitlint/cli') || ctx.findFiles(/(^|\/)(\.husky\/|lefthook\.ya?ml|\.pre-commit-config\.yaml)/).length > 0;
    const format = ctx.hasDep('prettier', '@biomejs/biome', 'dprint') || ctx.findFiles(/(^|\/)(\.prettierrc[^/]*|prettier\.config\.[cm]?js|biome\.jsonc?|\.editorconfig|dprint\.json)$/).length > 0;
    if (hook && format) return pass('Formatter + git hooks configured.');
    return warn(`Missing ${[!format && 'a formatter', !hook && 'git hooks'].filter(Boolean).join(' and ')}.`);
  },
});

const monorepo = defineCheck({
  id: 'CI-013',
  title: 'Multi-app repos build and test only what changed',
  severity: 'low',
  tags: ['ci', 'multi-app'],
  why: 'With several apps in one repo, rebuilding everything on every change makes CI slow and flaky; unrelated breakages block unrelated teams.',
  fix: 'Use workspaces (npm/pnpm/yarn) with Turborepo or Nx (`turbo run test --filter=...[origin/main]`, `nx affected -t test`) and remote caching.',
  run(ctx) {
    const apps = ctx.repoApps.filter((a) => a.dir !== '.'); // repo-level: all packages, even in a per-app scan
    if (apps.length < 2) return skip('Single-app repository.');
    const tool = ctx.hasDep('turbo', 'nx', 'lerna', '@nrwl/workspace', 'lage', 'moon', '@moonrepo/cli', 'wireit');
    const workspaces = Boolean(ctx.rootPkg?.workspaces) || ctx.exists('pnpm-workspace.yaml');
    const affected = /--filter|affected|changed-files|paths\s*:|dorny\/paths-filter|turbo\s+run[^\n]*\.\.\./.test(ciText(ctx));
    if (tool && affected) return pass('Monorepo tooling with affected-only CI.');
    if (tool || workspaces) return warn(`${tool ? 'Monorepo tool present' : 'Workspaces configured'} but CI does not filter by changed apps.`);
    return fail(`${apps.length} apps without workspace/monorepo tooling.`);
  },
});

const releases = defineCheck({
  id: 'CI-014',
  title: 'Releases are versioned with a changelog',
  severity: 'low',
  tags: ['releases'],
  why: 'When several apps depend on each other, "which version is in production and what changed?" must have an instant answer.',
  fix: 'Use Changesets, release-please or semantic-release (with Conventional Commits), and tag images/deploys with the version or git SHA.',
  run(ctx) {
    if (!ctx.apps.length) return skip('No Node project.');
    const tooling = ctx.hasDep('@changesets/cli', 'semantic-release', 'release-please', 'standard-version', 'release-it', 'lerna', 'auto', 'np', '@release-it/conventional-changelog')
      || ctx.findFiles(/(^|\/)(\.changeset\/|\.releaserc[^/]*|release-please-config\.json|\.release-it\.json)/).length > 0
      || /release-please-action|changesets\/action|semantic-release/.test(ciText(ctx));
    const changelog = ctx.findFiles(/(^|\/)CHANGELOG\.md$/i).length > 0;
    if (tooling) return pass('Release tooling configured.');
    return changelog ? warn('CHANGELOG exists but releases are not automated.') : warn('No release/versioning process found.');
  },
});

// ---------- in-depth (--review) ----------

const criticalCoverage = defineCheck({
  id: 'CI-R01',
  review: true,
  title: 'Critical modules (routes, auth, payments, orders) have tests',
  severity: 'high',
  tags: ['tests'],
  why: 'An overall coverage number hides the fact that the payment module has zero tests.',
  fix: 'Add at least one test per listed module, starting with auth, payments and anything that writes data.',
  run(ctx) {
    const tests = testFiles(ctx);
    if (!tests.length) return skip('No tests (see CI-002).');
    const testText = tests.map((f) => ctx.read(f) ?? '').join('\n');
    const referenced = (f) => {
      const base = path.posix.basename(f).replace(/\.[cm]?[jt]sx?$/, '');
      if (base === 'index') return new RegExp(`['"\`][^'"\`]*${path.posix.basename(path.posix.dirname(f))}(/index)?(\\.[cm]?[jt]sx?)?['"\`]`).test(testText);
      return new RegExp(`['"\`][^'"\`]*\\b${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\.[cm]?[jt]sx?)?['"\`]`).test(testText);
    };
    const critical = ctx.appCodeFiles.filter((f) => !/\.(jsx|tsx|vue|svelte)$/.test(f) && (CRITICAL_NAME.test(path.posix.basename(f)) || /\.(get|post|put|patch|delete)\s*\(\s*['"`]\//.test(ctx.code(f) ?? '')));
    if (!critical.length) return skip('No route or critical-domain modules found.');
    const untested = critical.filter((f) => !referenced(f));
    if (!untested.length) return pass(`All ${critical.length} critical module(s) are imported by tests.`);
    return (untested.length === critical.length ? fail : warn)(`${untested.length} of ${critical.length} critical module(s) are not imported by any test.`, untested.map((f) => ({ file: f })));
  },
});

const focusedTests = defineCheck({
  id: 'CI-R02',
  review: true,
  title: 'No focused (.only) or silently skipped tests',
  severity: 'medium',
  tags: ['tests'],
  why: 'One forgotten `.only` makes CI run a single test and report green; skipped tests rot quietly.',
  fix: 'Remove `.only`; turn skips into tracked tickets or delete them. Enable `--forbid-only` (Mocha/Playwright) or the ESLint rule `no-only-tests`.',
  run(ctx) {
    const tests = testFiles(ctx);
    if (!tests.length) return skip('No tests (see CI-002).');
    const only = ctx.grep(/\b(describe|it|test|context|suite)\.only\s*\(|\b(fit|fdescribe|ftest)\s*\(/, { files: tests });
    const skipped = ctx.grep(/\b(describe|it|test|context|suite)\.(skip|todo)\s*\(|\b(xit|xdescribe|xtest)\s*\(/, { files: tests });
    if (only.length) return fail(`${only.length} focused test(s) — the rest of the suite is not running.`, [...only, ...skipped]);
    if (skipped.length > 3) return warn(`${skipped.length} skipped tests.`, skipped);
    return pass(skipped.length ? `${skipped.length} skipped test(s), no focused tests.` : 'No focused or skipped tests.');
  },
});

const jobHygiene = defineCheck({
  id: 'CI-R03',
  review: true,
  title: 'CI jobs have timeouts and cancel superseded runs',
  severity: 'low',
  tags: ['ci'],
  why: 'A hung job burns runner minutes for up to 6 hours (GitHub default); pushing twice to a PR runs everything twice.',
  fix: 'Set `timeout-minutes` on every job and a `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }` for PR workflows.',
  run(ctx) {
    const wf = ctx.findFiles(GH_WORKFLOW);
    if (!wf.length) return skip('No GitHub Actions workflows.');
    const findings = [];
    for (const f of wf) {
      const text = ctx.read(f) ?? '';
      const jobs = (text.match(/^jobs\s*:\s*\n([\s\S]*)/m) ?? [])[1] ?? '';
      const jobNames = [...jobs.matchAll(/^ {2}([\w-]+)\s*:\s*$/gm)].map((m) => m[1]);
      const timeouts = (jobs.match(/^\s{4}timeout-minutes\s*:/gm) ?? []).length;
      if (jobNames.length && timeouts < jobNames.length) findings.push({ file: f, text: `${jobNames.length - timeouts} of ${jobNames.length} job(s) without timeout-minutes` });
      if (/pull_request/.test(text) && !/concurrency\s*:/.test(text)) findings.push({ file: f, text: 'PR workflow without concurrency cancel-in-progress' });
    }
    return findings.length ? warn('Workflow hygiene gaps.', findings) : pass('Jobs have timeouts; PR runs are de-duplicated.');
  },
});

// ---------- manual ----------

const manual = [
  {
    id: 'CI-M01', title: 'Main branch is protected: required reviews and required status checks, no force-push', severity: 'high',
    why: 'Without protection, CI is advisory — anyone can merge red builds or rewrite history.',
    fix: 'Branch protection / rulesets: ≥1 approving review (CODEOWNERS for sensitive paths), required CI checks, linear history, no bypass for admins.',
  },
  {
    id: 'CI-M02', title: 'Production deploys require passing smoke tests (and rollback automatically on failure)', severity: 'high',
    why: 'Tests prove the code works; smoke tests prove the deploy works — config, secrets, migrations, networking.',
    fix: 'After each deploy hit /readyz and 2–3 critical flows; fail the pipeline and roll back if they fail or error rate spikes.',
  },
  {
    id: 'CI-M03', title: 'CI secrets are per-environment, short-lived (OIDC) and rotated', severity: 'high',
    why: 'Long-lived cloud keys in CI are a top target in supply-chain attacks.',
    fix: 'Use OIDC federation to AWS/GCP/Azure instead of static keys; scope secrets to environments with required reviewers; rotate the rest.',
  },
  {
    id: 'CI-M04', title: 'Delivery metrics are tracked (deploy frequency, lead time, change failure rate, MTTR)', severity: 'low',
    why: 'You cannot tell whether process changes help without the four DORA metrics.',
    fix: 'Pull them from your CI/CD and incident tools monthly; review trends, not absolutes.',
  },
  {
    id: 'CI-M05', title: 'Code review has a checklist (security, migrations, observability, rollback)', severity: 'medium',
    why: 'Reviewers look at what they are reminded to look at.',
    fix: 'Keep a short checklist in the PR template; require a second reviewer for migrations, auth and infra changes.',
  },
  {
    id: 'CI-M06', title: 'Flaky tests are tracked and fixed; CI stays under ~15 minutes', severity: 'medium',
    why: 'Flaky or slow CI trains people to re-run and ignore failures.',
    fix: 'Quarantine flaky tests with an owner and deadline; parallelize/shard; cache dependencies and builds.',
  },
  {
    id: 'CI-M07', title: 'Every app has the same pipeline shape (shared templates)', severity: 'low',
    why: 'With many apps, copy-pasted pipelines drift: one app quietly stops running tests or security scans.',
    fix: 'Use reusable workflows / CI templates for install-lint-test-build-deploy; apps only configure what differs.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'cicd',
  title: 'CI/CD & quality',
  description: 'Tests, linting, pipelines, deploy automation, environments and supply-chain safety — so every change to every app is checked the same way before it ships.',
  checks: [
    pipeline, testsExist, ciRunsTests, lintTypecheck, coverage, ownership, delivery, environments,
    reproducibleInstalls, pinnedActions, workflowSafety, hooks, monorepo, releases,
    criticalCoverage, focusedTests, jobHygiene,
    ...manual,
  ],
});
