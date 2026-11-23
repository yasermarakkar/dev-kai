import fs from 'node:fs';
import path from 'node:path';
import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';
import { lineIndex } from '../core/lexer.js';

// ---------- shared ----------

const MARKUP = /\.(jsx|tsx|vue|svelte|html|astro)$/;
const STYLE = /\.(css|scss|sass|less|pcss)$/;
const IMAGE = /\.(png|jpe?g|gif|webp|avif|bmp|tiff?)$/i;
const IMAGE_BUDGET = 300 * 1024;

const markupFiles = (ctx) => ctx.files.filter((f) => MARKUP.test(f) && !ctx.isTestFile(f) && !/(^|\/)(\.storybook|stories|coverage|docs?)\//.test(f) && !/\.stories\./.test(f));
const styleFiles = (ctx) => ctx.files.filter((f) => STYLE.test(f) && !ctx.isTestFile(f));
const hasFrontend = (ctx) => ctx.stack.frontend.length > 0 || ctx.stack.fullstack.length > 0 || markupFiles(ctx).length > 0;
const isNext = (ctx) => ctx.stack.fullstack.includes('Next.js');
const isMobileOnly = (ctx) => ctx.stack.frontend.length > 0 && ctx.stack.frontend.every((f) => f === 'React Native' || f === 'Expo') && !ctx.stack.fullstack.length;

/** Opening tags `<tag …>` (multi-line aware) in a file: [{ tag, attrs, line, index }]. */
function tags(text, names) {
  const out = [];
  const lineOf = lineIndex(text);
  const re = new RegExp(`<(${names})(?=[\\s/>])((?:[^>"'{}]|"[^"]*"|'[^']*'|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*)\\/?>`, 'g');
  let m;
  while ((m = re.exec(text))) out.push({ tag: m[1], attrs: m[2], line: lineOf(m.index), index: m.index, raw: m[0] });
  return out;
}
const hasAttr = (attrs, name) => new RegExp(`(^|\\s)(${name})(\\s*=|\\s|$)`, 'i').test(attrs);
const webOnly = (ctx, run) => (isMobileOnly(ctx) ? skip('Mobile-only frontend (web checks do not apply).') : run());

// ---------- colour contrast (WCAG 2.x) ----------

function parseColor(v) {
  const s = v.trim().toLowerCase();
  if (s === 'white') return [255, 255, 255];
  if (s === 'black') return [0, 0, 0];
  let m = s.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/);
  if (m) {
    const h = m[1].length === 3 ? m[1].split('').map((c) => c + c).join('') : m[1];
    return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  }
  m = s.match(/^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)(?:[\s,/]+([\d.]+%?))?\s*\)$/);
  if (m && (m[4] === undefined || Number.parseFloat(m[4]) >= (m[4].endsWith('%') ? 100 : 1))) return [m[1], m[2], m[3]].map(Number);
  return null;
}
function luminance([r, g, b]) {
  const ch = [r, g, b].map((c) => {
    const x = c / 255;
    return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}
export function contrastRatio(a, b) {
  const [l1, l2] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (l1 + 0.05) / (l2 + 0.05);
}

// Tailwind default palette (text shades that fail 4.5:1 on white / pass on dark).
const TW_LOW_ON_WHITE = /\btext-(gray|slate|zinc|neutral|stone)-(100|200|300|400)\b|\btext-(red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-(100|200|300|400)\b|\btext-white\/(10|20|30|40|50)\b/;

// ---------- quick: performance ----------

const imageWeight = defineCheck({
  id: 'FE-001',
  title: 'Image assets are compressed and in modern formats',
  severity: 'medium',
  tags: ['performance', 'images'],
  why: 'Images are usually the largest bytes on a page; a 2 MB hero PNG alone can push LCP past 4 s on mobile.',
  fix: `Keep images under ~${IMAGE_BUDGET / 1024} KB: convert to WebP/AVIF, resize to the displayed size, and serve responsive sizes (next/image, @unpic/react, an image CDN).`,
  run(ctx) {
    if (!hasFrontend(ctx)) return skip('No frontend detected.');
    const images = ctx.files.filter((f) => IMAGE.test(f) && !ctx.isTestFile(f));
    if (!images.length) return skip('No image assets in the repo.');
    const heavy = [];
    for (const f of images) {
      try {
        const size = fs.statSync(path.join(ctx.root, f)).size;
        if (size > IMAGE_BUDGET) heavy.push({ file: f, text: `${Math.round(size / 1024)} KB` });
      } catch { /* unreadable */ }
    }
    const legacy = images.filter((f) => /\.(png|jpe?g|gif|bmp|tiff?)$/i.test(f));
    if (heavy.length) return fail(`${heavy.length} image(s) over ${IMAGE_BUDGET / 1024} KB.`, heavy.sort((a, b) => parseInt(b.text, 10) - parseInt(a.text, 10)));
    if (legacy.length > 5 && !ctx.hasDep('next', 'sharp', '@unpic/react', 'vite-plugin-image-optimizer', 'vite-imagetools', 'imagemin', '@astrojs/image', 'astro')) {
      return warn(`${legacy.length} PNG/JPEG/GIF images and no image optimisation in the build.`);
    }
    return pass(`${images.length} image(s), all within budget.`);
  },
});

const imgTags = defineCheck({
  id: 'FE-002',
  title: 'Images declare dimensions and lazy-load below the fold',
  severity: 'medium',
  tags: ['performance', 'cls'],
  why: 'Images without width/height make the page jump as they load (CLS); eager off-screen images compete with the content users came for.',
  fix: 'Set `width`/`height` (or aspect-ratio) on every image and `loading="lazy"` for below-the-fold ones. In Next.js use `next/image`; in Astro use `<Image />`.',
  run(ctx) {
    if (!hasFrontend(ctx)) return skip('No frontend detected.');
    return webOnly(ctx, () => {
      const findings = [];
      let total = 0;
      for (const f of markupFiles(ctx)) {
        for (const t of tags(ctx.read(f) ?? '', 'img')) {
          total++;
          const missing = [];
          if (!hasAttr(t.attrs, 'width') || !hasAttr(t.attrs, 'height')) missing.push('width/height');
          if (!hasAttr(t.attrs, 'loading') && !/fetchpriority\s*=\s*["']?high/i.test(t.attrs)) missing.push('loading');
          if (isNext(ctx)) missing.push('use next/image');
          if (missing.length) findings.push({ file: f, line: t.line, text: `<img> missing ${missing.join(', ')}` });
        }
      }
      if (!total) return pass('No raw <img> tags (framework image components or none).');
      return findings.length ? (findings.length > total / 2 ? fail : warn)(`${findings.length} of ${total} <img> tag(s) need attention.`, findings) : pass(`${total} <img> tag(s) have dimensions and loading hints.`);
    });
  },
});

const HEAVY_DEPS = [
  { name: 'moment', alt: 'date-fns, dayjs or Intl.DateTimeFormat (moment is ~70 KB gz and unmaintained)' },
  { name: 'jquery', alt: 'native DOM APIs (jQuery alongside a component framework doubles the work)', framework: true },
  { name: 'lodash', alt: 'lodash-es with per-function imports, or native methods', test: /import\s+_\s+from\s+['"]lodash['"]|require\(\s*['"]lodash['"]\s*\)|import\s+\*\s+as\s+_\s+from\s+['"]lodash['"]/ },
  { name: 'core-js', alt: 'targeted polyfills via browserslist (full core-js is ~60 KB+)', test: /import\s+['"]core-js['"]|require\(\s*['"]core-js['"]\s*\)/ },
  { name: '@mui/icons-material', alt: 'path imports (`@mui/icons-material/Delete`)', test: /from\s+['"]@mui\/icons-material['"]/ },
  { name: 'react-icons', alt: 'importing from the specific pack subpath', test: /import\s+\*\s+as\s+\w+\s+from\s+['"]react-icons/ },
  { name: 'aws-sdk', alt: 'AWS SDK v3 modular clients (v2 is several MB)', framework: true },
  { name: 'chart.js', alt: 'tree-shaken registration (`Chart.register(...)` only what you use)', test: /from\s+['"]chart\.js\/auto['"]/ },
];

const bundleWeight = defineCheck({
  id: 'FE-003',
  title: 'No oversized or non-tree-shakeable libraries in the client bundle',
  severity: 'medium',
  tags: ['performance', 'bundle'],
  why: 'Every KB of JavaScript has to be downloaded, parsed and executed before the page is interactive — mid-range phones pay 3–5× more than your laptop.',
  fix: 'Swap the listed libraries for lighter ones or import only what you use; check with `npx vite-bundle-visualizer` / `@next/bundle-analyzer`.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const clientFiles = ctx.appCodeFiles.filter((f) => MARKUP.test(f) || /(^|\/)(src|app|pages|components|client|web)\//.test(f));
    const findings = [];
    for (const d of HEAVY_DEPS) {
      if (!ctx.prodDeps.has(d.name)) continue;
      if (d.test) {
        const hits = ctx.grep(d.test, { files: clientFiles });
        hits.forEach((h) => findings.push({ ...h, text: `${d.name} → ${d.alt}` }));
      } else if (!d.framework || ctx.stack.frontend.length || ctx.stack.fullstack.length) {
        const used = ctx.grep(new RegExp(`from\\s+['"]${d.name}['"]|require\\(\\s*['"]${d.name}['"]`), { files: clientFiles, limit: 1 });
        if (used.length) findings.push({ ...used[0], text: `${d.name} → ${d.alt}` });
      }
    }
    return findings.length ? warn(`${findings.length} heavy import(s) in client code.`, unique(findings)) : pass('No known heavy client libraries.');
  },
});

const codeSplitting = defineCheck({
  id: 'FE-004',
  title: 'Routes and heavy components are code-split',
  severity: 'medium',
  tags: ['performance', 'bundle'],
  why: 'A single-page app that ships every route in one bundle makes the first visit pay for pages the user never opens.',
  fix: 'Lazy-load routes and heavy widgets (`React.lazy` + `Suspense`, `defineAsyncComponent`, `next/dynamic`, `import()`); frameworks with file routing (Next, Nuxt, SvelteKit, Remix, Astro) do it per route.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    if (ctx.stack.fullstack.length) return pass(`${ctx.stack.fullstack.join(', ')} splits per route.`);
    const routes = ctx.hasDep('react-router', 'react-router-dom', '@tanstack/react-router', 'vue-router', '@angular/router', 'wouter', '@solidjs/router');
    if (!routes) return skip('No client-side router.');
    return ctx.contains(/\blazy\s*\(\s*\(\)\s*=>\s*import\(|React\.lazy\s*\(|defineAsyncComponent\s*\(|loadChildren\s*:|component\s*:\s*\(\)\s*=>\s*import\(|lazy\s*:\s*\(\)\s*=>\s*import\(|loadable\s*\(/)
      ? pass('Lazy-loaded routes/components found.')
      : fail('Client router with no lazy-loaded routes — the whole app ships in one bundle.');
  },
});

const perfBudget = defineCheck({
  id: 'FE-005',
  title: 'Performance budgets are enforced in CI',
  severity: 'medium',
  tags: ['performance', 'ci'],
  why: 'Pages get slower one dependency at a time; a budget makes the regression fail the PR instead of surfacing months later.',
  fix: 'Add Lighthouse CI (`@lhci/cli` with assertions on LCP/CLS/TBT) or size-limit/bundlewatch with a KB budget, and run it in CI.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const lib = ctx.hasDep('@lhci/cli', 'size-limit', '@size-limit/preset-app', '@size-limit/file', 'bundlesize', 'bundlewatch', 'unlighthouse', '@unlighthouse/cli');
    const cfg = ctx.findFiles(/(^|\/)(lighthouserc(\.\w+)?|\.lighthouserc(\.\w+)?|\.size-limit(\.\w+)?|bundlewatch\.config\.\w+|budget\.json)$/).length > 0;
    const ci = ctx.findFiles(/^\.github\/workflows\/|\.gitlab-ci\.yml$/).some((f) => /lhci|lighthouse|size-limit|bundlewatch|bundlesize|treosh\/lighthouse-ci-action/.test(ctx.read(f) ?? ''));
    if ((lib || cfg) && ci) return pass('Performance budget runs in CI.');
    if (lib || cfg) return warn('Budget configured but not run in CI.');
    return fail('No performance or bundle-size budget.');
  },
});

const fonts = defineCheck({
  id: 'FE-006',
  title: 'Web fonts do not block text rendering',
  severity: 'low',
  tags: ['performance'],
  why: 'Without `font-display: swap` text stays invisible until the font downloads (FOIT) — on slow networks that is seconds of blank page.',
  fix: 'Use `next/font` / `@fontsource` (self-hosted, preloaded), or add `&display=swap` to Google Fonts URLs and `font-display: swap` to every @font-face.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const files = [...markupFiles(ctx), ...styleFiles(ctx)];
    const findings = [
      ...ctx.grep(/fonts\.googleapis\.com\/css2?\?(?![^"')]*display=(swap|optional|fallback))[^"')]*/, { files }),
    ];
    for (const f of styleFiles(ctx)) {
      const css = ctx.read(f) ?? '';
      const lineOf = lineIndex(css);
      for (const m of css.matchAll(/@font-face\s*\{([^}]*)\}/g)) if (!/font-display\s*:/.test(m[1])) findings.push({ file: f, line: lineOf(m.index), text: '@font-face without font-display' });
    }
    if (findings.length) return fail('Fonts that block text rendering.', findings);
    return pass(ctx.hasDep('next') || ctx.hasDep('@fontsource/inter') ? 'Optimised font loading.' : 'No blocking font declarations found.');
  },
});

const thirdPartyScripts = defineCheck({
  id: 'FE-007',
  title: 'Third-party scripts load async/deferred',
  severity: 'medium',
  tags: ['performance', 'security'],
  why: 'A synchronous analytics or chat script in <head> blocks rendering until someone else\'s server answers — and runs with full access to your page.',
  fix: 'Add `async`/`defer` (or `type="module"`), use `next/script` with `strategy="afterInteractive"`/`"lazyOnload"`, self-host where possible and add Subresource Integrity for CDN scripts.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const findings = [];
    for (const f of markupFiles(ctx)) {
      for (const t of tags(ctx.read(f) ?? '', 'script')) {
        if (!/\bsrc\s*=\s*["'{`]?\s*(https?:)?\/\//.test(t.attrs)) continue;
        if (!hasAttr(t.attrs, 'async|defer') && !/type\s*=\s*["']module/.test(t.attrs)) findings.push({ file: f, line: t.line, text: `blocking third-party <script>: ${t.raw.slice(0, 100)}` });
      }
      for (const t of tags(ctx.read(f) ?? '', 'Script')) {
        if (/strategy\s*=\s*["']beforeInteractive/.test(t.attrs)) findings.push({ file: f, line: t.line, text: 'next/script beforeInteractive — only for scripts the page cannot render without' });
      }
    }
    return findings.length ? fail(`${findings.length} render-blocking third-party script(s).`, findings) : pass('Third-party scripts are non-blocking.');
  },
});

const publicSourceMaps = defineCheck({
  id: 'FE-008',
  title: 'Production source maps are not served publicly',
  severity: 'low',
  tags: ['security', 'build'],
  why: 'Public source maps hand anyone your original source (comments, internal URLs, feature flags) and add download weight for tools that fetch them.',
  fix: 'Generate hidden maps and upload them to the error tracker: Vite `build.sourcemap: \'hidden\'`, webpack `hidden-source-map`, Next.js keep `productionBrowserSourceMaps` off (Sentry uploads its own).',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const cfg = ctx.findFiles(/(^|\/)(vite|next|webpack|nuxt|astro|svelte|rollup)\.config\.[cm]?[jt]s$/);
    const hits = ctx.grep(/productionBrowserSourceMaps\s*:\s*true|sourcemap\s*:\s*(true|['"]inline['"])|devtool\s*:\s*['"](source-map|inline-source-map|eval[\w-]*)['"]/, { files: cfg });
    return hits.length ? fail('Production build publishes full source maps.', hits) : pass('Source maps are off or hidden in production builds.');
  },
});

// ---------- quick: accessibility ----------

const altText = defineCheck({
  id: 'FE-010',
  title: 'Images have alternative text',
  severity: 'high',
  tags: ['a11y', 'wcag-1.1.1'],
  why: 'Screen-reader users hear "image" or the file name instead of the content; missing alt is the most common WCAG failure on the web.',
  fix: 'Give every image an `alt`: describe meaningful images, use `alt=""` for purely decorative ones. Same for `next/image`, `<Image>` and `role="img"` SVGs (`aria-label`).',
  docs: ['https://www.w3.org/WAI/tutorials/images/decision-tree/'],
  run(ctx) {
    if (!hasFrontend(ctx)) return skip('No frontend detected.');
    const findings = [];
    let total = 0;
    for (const f of markupFiles(ctx)) {
      for (const t of tags(ctx.read(f) ?? '', 'img|Image|NuxtImg|NextImage')) {
        total++;
        if (!hasAttr(t.attrs, 'alt|aria-label|aria-labelledby') && !/role\s*=\s*["']presentation/.test(t.attrs)) findings.push({ file: f, line: t.line, text: `<${t.tag}> without alt` });
      }
    }
    if (!total) return skip('No images in markup.');
    return findings.length ? fail(`${findings.length} of ${total} image(s) have no alt text.`, findings) : pass(`All ${total} image(s) have alt text.`);
  },
});

const formLabels = defineCheck({
  id: 'FE-011',
  title: 'Form fields have labels',
  severity: 'high',
  tags: ['a11y', 'wcag-1.3.1', 'wcag-4.1.2'],
  why: 'An input with only a placeholder has no accessible name — screen readers announce "edit text" and the hint disappears as soon as the user types.',
  fix: 'Pair each field with `<label htmlFor="id">` (or wrap it in the label), or give it `aria-label`/`aria-labelledby`. Placeholders are not labels.',
  run(ctx) {
    if (!hasFrontend(ctx)) return skip('No frontend detected.');
    const findings = [];
    let total = 0;
    for (const f of markupFiles(ctx)) {
      const text = ctx.read(f) ?? '';
      const labelled = new Set([...text.matchAll(/(?:htmlFor|for)\s*=\s*["'{]\s*["'`]?([\w-]+)/g)].map((m) => m[1]));
      const wrapped = [...text.matchAll(/<label\b[^>]*>([\s\S]*?)<\/label>/g)].map((m) => m[1]);
      for (const t of tags(text, 'input|select|textarea')) {
        if (/type\s*=\s*["'](hidden|submit|button|reset|image)["']/.test(t.attrs)) continue;
        total++;
        if (hasAttr(t.attrs, 'aria-label|aria-labelledby|title')) continue;
        const id = (t.attrs.match(/\bid\s*=\s*["'{]\s*["'`]?([\w-]+)/) ?? [])[1];
        if (id && labelled.has(id)) continue;
        if (wrapped.some((w) => w.includes(t.raw))) continue;
        findings.push({ file: f, line: t.line, text: `<${t.tag}> without a label${hasAttr(t.attrs, 'placeholder') ? ' (placeholder only)' : ''}` });
      }
    }
    if (!total) return skip('No form fields in markup.');
    return findings.length ? fail(`${findings.length} of ${total} form field(s) have no label.`, findings) : pass(`All ${total} form field(s) are labelled.`);
  },
});

const semanticControls = defineCheck({
  id: 'FE-012',
  title: 'Clickable elements are real buttons/links (keyboard accessible)',
  severity: 'high',
  tags: ['a11y', 'wcag-2.1.1'],
  why: 'A `<div onClick>` cannot be reached with Tab or activated with Enter/Space, and screen readers do not announce it as interactive.',
  fix: 'Use `<button>` for actions and `<a href>` for navigation. If you truly must use a div: `role="button" tabIndex={0}` and an `onKeyDown` for Enter/Space.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const findings = [];
    for (const f of markupFiles(ctx)) {
      const text = ctx.read(f) ?? '';
      for (const t of tags(text, 'div|span|li|td|tr|img|p|section|article')) {
        if (!/\b(onClick|@click|v-on:click|on:click|\(click\))\s*=/.test(t.attrs)) continue;
        const ok = hasAttr(t.attrs, 'role') && /tabIndex|tabindex/.test(t.attrs) && /onKeyDown|onKeyUp|@keydown|@keyup|on:keydown|\(keydown\)/.test(t.attrs);
        if (!ok) findings.push({ file: f, line: t.line, text: `<${t.tag}> with a click handler` });
      }
      for (const t of tags(text, 'a')) {
        if (/href\s*=\s*["'](#|javascript:[^"']*)["']/.test(t.attrs) || (!hasAttr(t.attrs, 'href') && /onClick|@click/.test(t.attrs))) findings.push({ file: f, line: t.line, text: '<a> used as a button (href="#" / javascript: / no href)' });
      }
    }
    return findings.length ? fail(`${findings.length} non-semantic interactive element(s).`, findings) : pass('Interactive elements are buttons and links.');
  },
});

const documentBasics = defineCheck({
  id: 'FE-013',
  title: 'Pages declare a language and a title',
  severity: 'medium',
  tags: ['a11y', 'seo', 'wcag-3.1.1', 'wcag-2.4.2'],
  why: 'Without `lang`, screen readers pronounce text with the wrong voice; without a title, tabs, bookmarks and search results say nothing useful.',
  fix: '`<html lang="en">` in index.html / app/layout; `<title>` or Next.js `metadata.title` (per page where possible).',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const docs = ctx.findFiles(/(^|\/)(index\.html|app\.html|_document\.[jt]sx?|layout\.[jt]sx?|app\.vue|nuxt\.config\.[jt]s|Layout\.astro|\+layout\.svelte|[\w-]+\.html)$/).filter((f) => !ctx.isTestFile(f));
    if (!docs.length) return skip('No HTML document or root layout found.');
    const text = docs.map((f) => ctx.read(f) ?? '').join('\n');
    const missing = [];
    if (!/<html[^>]*\blang\s*=|htmlAttrs\s*:\s*\{[^}]*lang|lang\s*:\s*['"]\w/.test(text)) missing.push('lang attribute');
    if (!/<title[\s>]|metadata\s*[:=][^;]*title|title\s*:\s*['"`]|useHead|<Head>|generateMetadata|<svelte:head>/.test(text) && !ctx.contains(/export\s+const\s+metadata|generateMetadata|useHead\s*\(|<title/, { files: markupFiles(ctx) })) missing.push('title');
    return missing.length ? fail(`Missing ${missing.join(' and ')}.`, docs.map((f) => ({ file: f }))) : pass('Language and title declared.');
  },
});

const a11yTooling = defineCheck({
  id: 'FE-014',
  title: 'Accessibility is linted and tested automatically',
  severity: 'medium',
  tags: ['a11y', 'ci'],
  why: 'Automated checks catch ~30–40% of WCAG issues for free on every PR, so manual testing can focus on the rest.',
  fix: 'Add eslint-plugin-jsx-a11y (React) / eslint-plugin-vuejs-accessibility (Vue) / angular-eslint template a11y, plus axe in tests (@axe-core/playwright, jest-axe, vitest-axe) or pa11y-ci in CI.',
  run(ctx) {
    if (!hasFrontend(ctx)) return skip('No frontend detected.');
    const lint = ctx.hasDep('eslint-plugin-jsx-a11y', 'eslint-plugin-vuejs-accessibility', 'eslint-plugin-svelte', '@angular-eslint/eslint-plugin-template', 'eslint-plugin-astro', 'eslint-config-next', 'eslint-plugin-react-native-a11y', '@biomejs/biome');
    const tests = ctx.hasDep('@axe-core/playwright', '@axe-core/react', 'axe-core', 'jest-axe', 'vitest-axe', 'cypress-axe', 'pa11y', 'pa11y-ci', '@storybook/addon-a11y', '@chromatic-com/storybook', 'axe-playwright', '@testing-library/jest-native');
    if (lint && tests) return pass('A11y lint rules and automated a11y tests.');
    if (lint || tests) return warn(`Only ${lint ? 'lint rules' : 'automated tests'} for accessibility.`);
    return fail('No accessibility linting or testing.');
  },
});

const zoom = defineCheck({
  id: 'FE-015',
  title: 'Users can zoom (viewport does not disable scaling)',
  severity: 'medium',
  tags: ['a11y', 'wcag-1.4.4'],
  why: '`user-scalable=no` or `maximum-scale=1` stops low-vision users from zooming on mobile.',
  fix: 'Use `<meta name="viewport" content="width=device-width, initial-scale=1">` with no scale limits (Next.js: `export const viewport = { width: \'device-width\', initialScale: 1 }`).',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const hits = ctx.grep(/user-scalable\s*=\s*(no|0)|maximum-scale\s*=\s*1(\.0)?\b|userScalable\s*:\s*false|maximumScale\s*:\s*1\b/, { files: [...markupFiles(ctx), ...ctx.appCodeFiles] });
    return hits.length ? fail('Zoom is disabled.', unique(hits)) : pass('Zoom is allowed.');
  },
});

const focusStyles = defineCheck({
  id: 'FE-016',
  title: 'Focus indicators are visible',
  severity: 'medium',
  tags: ['a11y', 'wcag-2.4.7'],
  why: 'Removing the focus outline leaves keyboard users unable to see where they are on the page.',
  fix: 'Never remove outlines without a replacement; style `:focus-visible` (e.g. `outline: 2px solid currentColor; outline-offset: 2px`). Tailwind: pair `outline-none` with `focus-visible:ring-2`.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const css = styleFiles(ctx);
    const removed = ctx.grep(/outline\s*:\s*(none|0)\b/, { files: css });
    const replaced = ctx.contains(/:focus-visible/, { files: [...css, ...markupFiles(ctx)] }) || ctx.contains(/focus-visible:|focus:ring|focus:outline-(?!none)/, { files: markupFiles(ctx) });
    const twRemoved = ctx.grep(/\b(outline-none|focus:outline-none)\b/, { files: markupFiles(ctx) }).filter((h) => !/focus(-visible)?:ring|focus-visible:outline/.test(h.text));
    const findings = [...removed, ...twRemoved];
    if (!findings.length) return pass('No focus outlines removed.');
    return replaced ? warn(`${findings.length} place(s) remove outlines; :focus-visible styles exist — confirm they cover these.`, findings) : fail('Focus outlines removed with no :focus-visible replacement.', findings);
  },
});

const reducedMotion = defineCheck({
  id: 'FE-017',
  title: 'Animations respect "reduce motion"',
  severity: 'low',
  tags: ['a11y', 'wcag-2.3.3'],
  why: 'Large or looping animations can trigger nausea and vestibular disorders; the OS setting exists to switch them off.',
  fix: 'Wrap non-essential animation in `@media (prefers-reduced-motion: no-preference)` (or reduce it under `reduce`); Framer Motion: `useReducedMotion` / `MotionConfig reducedMotion="user"`; Tailwind: `motion-safe:`.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const files = [...styleFiles(ctx), ...markupFiles(ctx), ...ctx.appCodeFiles];
    const animates = ctx.hasDep('framer-motion', 'motion', 'gsap', 'animejs', 'lottie-web', 'lottie-react', 'react-spring', '@react-spring/web', 'aos')
      || ctx.contains(/@keyframes|animation\s*:\s*[^;]*\b(infinite|\d+m?s)\b|\banimate-(spin|ping|bounce|pulse)\b/, { files });
    if (!animates) return skip('No animations found.');
    return ctx.contains(/prefers-reduced-motion|useReducedMotion|reducedMotion\s*=|motion-safe:|motion-reduce:/, { files })
      ? pass('Reduced-motion preference handled.')
      : warn('Animations present but prefers-reduced-motion is never checked.');
  },
});

// ---------- in-depth (--review) ----------

const iconOnly = defineCheck({
  id: 'FE-R01',
  review: true,
  title: 'Icon-only buttons and links have an accessible name',
  severity: 'high',
  tags: ['a11y', 'wcag-4.1.2'],
  why: 'A button containing only an SVG is announced as "button" — users cannot tell close from delete.',
  fix: 'Add `aria-label="Close"` (or visually hidden text) to icon-only buttons/links, and `aria-hidden="true"` on the icon itself.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const findings = [];
    for (const f of markupFiles(ctx)) {
      const text = ctx.read(f) ?? '';
      const lineOf = lineIndex(text);
      for (const m of text.matchAll(/<(button|a|Button|IconButton|Link)\b((?:[^>"'{}]|"[^"]*"|'[^']*'|\{(?:[^{}]|\{[^{}]*\})*\})*)>([\s\S]*?)<\/\1>/g)) {
        if (hasAttr(m[2], 'aria-label|aria-labelledby|title')) continue;
        const inner = m[3]
          .replace(/<svg[\s\S]*?<\/svg>/g, '')
          .replace(/<[A-Z]\w*(Icon|Svg)?\b[^>]*\/>/g, '') // <XIcon /> components
          .replace(/<[^>]+>/g, '')
          .replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, '')
          .trim();
        const hasVisuallyHidden = /sr-only|visually-hidden|VisuallyHidden|screen-reader/.test(m[3]);
        if (!inner && !hasVisuallyHidden) findings.push({ file: f, line: lineOf(m.index), text: `<${m[1]}> with only an icon and no aria-label` });
      }
    }
    return findings.length ? fail(`${findings.length} icon-only control(s) without a name.`, findings) : pass('Icon-only controls are labelled.');
  },
});

const headings = defineCheck({
  id: 'FE-R02',
  review: true,
  title: 'Headings form a logical outline',
  severity: 'medium',
  tags: ['a11y', 'wcag-1.3.1'],
  why: 'Screen-reader users navigate by headings; skipped levels or several h1s make the page structure confusing.',
  fix: 'One `<h1>` per page, then h2 → h3 without skipping levels. Style headings with CSS, not by picking a smaller tag.',
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const findings = [];
    const pages = markupFiles(ctx).filter((f) => /(^|\/)(pages|app|routes|views|src\/pages)\/|\.html$|(^|\/)(page|index|App)\.[jt]sx$|\+page\.svelte$/.test(f));
    for (const f of pages) {
      const text = ctx.read(f) ?? '';
      const lineOf = lineIndex(text);
      const hs = [...text.matchAll(/<h([1-6])\b/g)].map((m) => ({ level: Number(m[1]), line: lineOf(m.index) }));
      if (!hs.length) continue;
      const h1s = hs.filter((h) => h.level === 1);
      if (h1s.length > 1) findings.push({ file: f, line: h1s[1].line, text: `${h1s.length} <h1> elements on one page` });
      for (let i = 1; i < hs.length; i++) {
        if (hs[i].level > hs[i - 1].level + 1) findings.push({ file: f, line: hs[i].line, text: `h${hs[i - 1].level} → h${hs[i].level} skips a level` });
      }
    }
    return findings.length ? warn(`${findings.length} heading structure issue(s).`, findings) : pass('Heading levels are sequential.');
  },
});

const contrast = defineCheck({
  id: 'FE-R03',
  review: true,
  title: 'Text colour contrast meets WCAG AA (4.5:1)',
  severity: 'high',
  tags: ['a11y', 'wcag-1.4.3'],
  why: 'Light grey on white is the most common accessibility failure after alt text — unreadable in sunlight and for low-vision users.',
  fix: 'Keep body text ≥ 4.5:1 and large text (≥ 24 px / 19 px bold) ≥ 3:1. Check with the browser devtools contrast picker; darken greys (e.g. #767676 is the lightest grey that passes on white).',
  docs: ['https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html'],
  run(ctx) {
    if (!hasFrontend(ctx) || isMobileOnly(ctx)) return skip('No web frontend detected.');
    const findings = [];
    for (const f of styleFiles(ctx)) {
      const css = ctx.read(f) ?? '';
      const lineOf = lineIndex(css);
      // Page background (body/html/:root) is the fallback when a rule sets only a colour.
      const pageBg = (css.match(/(?:^|\})\s*(?:html|body|:root)[^{]*\{[^}]*background(?:-color)?\s*:\s*(#[0-9a-f]{3,6}|white|black|rgba?\([^)]*\))/i) ?? [])[1];
      for (const m of css.matchAll(/([^{}]+)\{([^}]*)\}/g)) {
        const body = m[2];
        const fg = (body.match(/(?:^|;|\s)color\s*:\s*(#[0-9a-f]{3,6}|white|black|rgba?\([^)]*\))/i) ?? [])[1];
        if (!fg) continue;
        const bg = (body.match(/background(?:-color)?\s*:\s*(#[0-9a-f]{3,6}|white|black|rgba?\([^)]*\))/i) ?? [])[1] ?? pageBg ?? '#ffffff';
        const a = parseColor(fg);
        const b = parseColor(bg);
        if (!a || !b) continue;
        const ratio = contrastRatio(a, b);
        const large = /font-size\s*:\s*(2[4-9]|[3-9]\d)px|font-size\s*:\s*([1-9]\.\d+|[2-9])r?em/.test(body) || /\bh1\b/.test(m[1]);
        if (ratio < (large ? 3 : 4.5)) findings.push({ file: f, line: lineOf(m.index + m[1].length), text: `${m[1].trim().slice(0, 40)}: ${fg} on ${bg} = ${ratio.toFixed(2)}:1` });
      }
    }
    for (const h of ctx.grep(TW_LOW_ON_WHITE, { files: markupFiles(ctx) })) {
      if (/\b(dark:)?bg-(gray|slate|zinc|neutral|stone|black)-(700|800|900|950)\b|\bbg-black\b/.test(h.text)) continue;
      findings.push({ ...h, text: `low-contrast Tailwind text class: ${h.text.match(TW_LOW_ON_WHITE)[0]}` });
    }
    return findings.length ? fail(`${findings.length} low-contrast text style(s).`, unique(findings)) : pass('Checked text colours meet 4.5:1.');
  },
});

const renderPitfalls = defineCheck({
  id: 'FE-R04',
  review: true,
  title: 'No React render pitfalls (missing keys, effects that run every render)',
  severity: 'medium',
  tags: ['performance', 'react'],
  why: 'Lists without stable keys re-mount items and lose input state; `useEffect` without a dependency array re-runs (and often re-fetches) on every render.',
  fix: 'Give list items a stable `key` from the data (not the index for reorderable lists); always pass a dependency array to `useEffect`/`useMemo`/`useCallback`.',
  run(ctx) {
    if (!ctx.hasDep('react', 'preact', 'react-native')) return skip('Not a React app.');
    const files = ctx.appCodeFiles.filter((f) => /\.(jsx|tsx|js|ts)$/.test(f));
    const findings = [];
    for (const f of files) {
      const code = ctx.code(f);
      if (!code) continue;
      const lineOf = lineIndex(code);
      for (const m of code.matchAll(/\.map\s*\(\s*(?:\(\s*[^)]*\)|\w+)\s*=>\s*\(?\s*<([A-Za-z][\w.]*)((?:[^>"'{}]|"[^"]*"|'[^']*'|\{(?:[^{}]|\{[^{}]*\})*\})*)>/g)) {
        if (!/\bkey\s*=/.test(m[2])) findings.push(ctx.at(f, lineOf(m.index), `<${m[1]}> rendered in .map() without a key`));
      }
      for (const m of code.matchAll(/\buse(Effect|LayoutEffect)\s*\(\s*(async\s*)?\(\s*\)\s*=>\s*\{/g)) {
        // find the end of the callback, then check for a deps argument
        let depth = 0;
        let i = code.indexOf('{', m.index + m[0].length - 1);
        for (; i < code.length; i++) {
          if (code[i] === '{') depth++;
          else if (code[i] === '}' && --depth === 0) break;
        }
        const after = code.slice(i + 1, i + 40);
        if (/^\s*\)/.test(after)) findings.push(ctx.at(f, lineOf(m.index), `use${m[1]} without a dependency array`));
      }
    }
    return findings.length ? fail(`${findings.length} React render pitfall(s).`, findings) : pass('List keys and effect dependencies look correct.');
  },
});

// ---------- manual ----------

const manual = [
  {
    id: 'FE-M01', title: 'Core Web Vitals are "good" for real users (p75: LCP < 2.5 s, INP < 200 ms, CLS < 0.1)', severity: 'high',
    why: 'Field data from real devices is what users feel — and what Google ranks on.',
    fix: 'Check CrUX / PageSpeed Insights / your RUM tool per key page and device type; fix the worst page first.',
  },
  {
    id: 'FE-M02', title: 'Key flows work with keyboard only (tab order, visible focus, modals trap and restore focus, skip link)', severity: 'high',
    why: 'Keyboard access underpins screen readers, switch devices and power users; automated tools cannot judge tab order.',
    fix: 'Unplug the mouse and complete sign-up, checkout and settings; fix anything you cannot reach or escape.',
  },
  {
    id: 'FE-M03', title: 'Key flows are tested with a screen reader (VoiceOver, NVDA, TalkBack)', severity: 'high',
    why: 'Only a real screen reader shows whether labels, live regions and error messages make sense in context.',
    fix: 'Each release, run the top 3 flows with VoiceOver (macOS/iOS) and NVDA (Windows); log issues like bugs.',
  },
  {
    id: 'FE-M04', title: 'Accessibility target (WCAG 2.2 AA) is documented, with an accessibility statement', severity: 'medium',
    why: 'Many markets now require it (European Accessibility Act from June 2025, ADA, Section 508) and enterprise customers ask for it.',
    fix: 'State the target, known gaps and a contact; schedule an external audit for major releases.',
  },
  {
    id: 'FE-M05', title: 'Sites work on slow networks and low-end devices (and show error/offline states)', severity: 'medium',
    why: 'Your customers are not all on fibre and flagship phones.',
    fix: 'Test with DevTools "Slow 4G" + 4× CPU throttling; make loading, error and offline states explicit.',
  },
  {
    id: 'FE-M06', title: 'Layouts reflow at 320 px and 200% zoom without losing content', severity: 'medium',
    why: 'Low-vision users zoom; small phones are 320–360 px wide. Horizontal scrolling and clipped text block them.',
    fix: 'Test each key page at 320 px width and 200% browser zoom; avoid fixed heights for text containers.',
  },
  {
    id: 'FE-M07', title: 'Design system components are accessible by default', severity: 'medium',
    why: 'With several apps and websites, fixing a11y once in shared components fixes it everywhere.',
    fix: 'Build on accessible primitives (Radix, React Aria, Headless UI, Reach), document a11y props, test components with axe in Storybook.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'frontend',
  title: 'Frontend & a11y',
  description: 'Page weight, loading behaviour and WCAG 2.2 AA basics for every website and web app — fast for everyone, usable by everyone.',
  checks: [
    imageWeight, imgTags, bundleWeight, codeSplitting, perfBudget, fonts, thirdPartyScripts, publicSourceMaps,
    altText, formLabels, semanticControls, documentBasics, a11yTooling, zoom, focusStyles, reducedMotion,
    iconOnly, headings, contrast, renderPitfalls,
    ...manual,
  ],
});
