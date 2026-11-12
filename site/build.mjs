#!/usr/bin/env node
// Builds the goraz documentation site from docs/**/*.md into _site/.
//
//   cd site && npm ci && npm run build
//
// The Markdown stays readable on GitHub; this script adds the layout,
// navigation, syntax highlighting and link rewriting for GitHub Pages.
// It is documentation tooling only and is not part of the Go module.
import { execSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import GithubSlugger from "github-slugger";
import { Marked } from "marked";
import { createHighlighter } from "shiki";
import { home, layout } from "./layout.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const docs = join(root, "docs");
const out = join(root, "_site");

// The latest release tag, so the badge in the top bar matches the release.
const version = (() => {
  try {
    return execSync("git describe --tags --abbrev=0", { cwd: root, stdio: ["ignore", "pipe", "ignore"] }).toString().trim().replace(/^v/, "");
  } catch {
    return "0.1.0";
  }
})();

export const SITE = {
  name: "goraz",
  version,
  url: "https://mtnaskari.github.io/goraz/",
  repo: "https://github.com/mtnaskari/goraz",
  tagline: "Encrypted secrets, API tokens and passwords for Go services and the command line. No server required.",
};

/** Sidebar order. Every page in docs/ must appear here. */
export const NAV = [
  {
    group: "Start",
    intro: "Install goraz and use it on your own machine.",
    items: [
      ["index", "Overview"],
      ["guides/getting-started", "Get started"],
      ["guides/replace-dotenv-file", "Replace a .env file"],
      ["guides/password-manager-cli", "Passwords and one-time codes"],
    ],
  },
  {
    group: "Production",
    intro: "Give services only the secrets they need.",
    items: [
      ["guides/api-tokens-in-go-service", "Tokens in a Go service"],
      ["guides/issue-api-tokens-in-go", "Issue API tokens"],
      ["guides/docker-secrets", "Docker"],
      ["guides/kubernetes-secrets", "Kubernetes"],
      ["guides/systemd-credentials", "systemd"],
      ["guides/ci-secrets", "CI pipelines"],
    ],
  },
  {
    group: "Plan and respond",
    intro: "Decide whether it fits, and fix problems.",
    items: [
      ["guides/alternatives", "Compared with others"],
      ["limits", "Limits and performance"],
      ["guides/secret-or-key-leaked", "A secret has leaked"],
      ["guides/troubleshooting", "Troubleshooting"],
    ],
  },
  {
    group: "Reference",
    intro: "Every command, guarantee and byte.",
    items: [
      ["cli-reference", "Command reference"],
      ["threat-model", "Threat model"],
      ["security-design", "Security design"],
      ["feature-matrix", "Feature matrix"],
      ["research/comparison", "Research"],
    ],
  },
];

const LANGS = ["bash", "go", "ini", "yaml", "json", "toml", "text"];
const LABELS = { bash: "Terminal", go: "Go", ini: "INI", yaml: "YAML", json: "JSON", toml: "TOML" };
const highlighter = await createHighlighter({ themes: ["github-light", "github-dark-dimmed"], langs: LANGS.filter((l) => l !== "text") });

const escapeHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const stripTags = (s) => s.replace(/<[^>]+>/g, "");

/** Splits YAML front matter (title and description only) from the body. */
function frontMatter(source) {
  const match = /^---\n([\s\S]*?)\n---\n/.exec(source);
  if (!match) return { meta: {}, body: source };
  const meta = {};
  for (const line of match[1].split("\n")) {
    const kv = /^(\w+):\s*(.*)$/.exec(line);
    if (kv) meta[kv[1]] = kv[2].replace(/^["']|["']$/g, "");
  }
  return { meta, body: source.slice(match[0].length) };
}

/** Output path of a page, relative to the site root. */
const pageFile = (slug) => (slug === "index" ? "index.html" : `${slug}.html`);

/** Rewrites a Markdown link from the page `from` to the built site or to GitHub. */
function rewriteHref(href, from) {
  if (/^[a-z]+:/i.test(href) || href.startsWith("#")) return href;
  const [path, hash] = href.split("#");
  const anchor = hash ? `#${hash}` : "";
  const resolved = posix.normalize(posix.join(posix.dirname(`docs/${from}`), path));
  if (!resolved.startsWith("docs/")) return `${SITE.repo}/blob/main/${resolved}${anchor}`;
  const inDocs = resolved.slice("docs/".length);
  if (inDocs.endsWith(".md")) {
    const target = pageFile(inDocs.slice(0, -3));
    let rel = posix.relative(posix.dirname(from), target);
    if (target === "index.html") rel = rel.replace(/index\.html$/, "") || "./";
    return `${rel}${anchor}`;
  }
  return posix.relative(posix.dirname(from), inDocs) + anchor;
}

const ICONS = {
  note: '<path d="M12 16v-4M12 8h.01"/><circle cx="12" cy="12" r="9"/>',
  tip: '<path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.5 1 2.5h6c0-1 .3-1.8 1-2.5A6 6 0 0 0 12 3z"/>',
  important: '<path d="M12 8v5M12 16h.01"/><path d="M4 4h16v12H8l-4 4z"/>',
  warning: '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
  caution: '<path d="M12 8v5M12 16h.01"/><path d="M8.5 2.5h7l5 5v7l-5 5h-7l-5-5v-7z"/>',
};

function renderPage(markdown, slug) {
  const slugger = new GithubSlugger();
  const headings = [];
  let title = "";
  let description = "";

  const marked = new Marked({ gfm: true });
  marked.use({
    renderer: {
      heading({ tokens, depth, text }) {
        const html = this.parser.parseInline(tokens);
        const id = slugger.slug(stripTags(text).replace(/`/g, ""));
        if (depth === 1) {
          title ||= stripTags(html);
          return `<h1 id="${id}">${html}</h1>\n`;
        }
        if (depth <= 3) headings.push({ depth, id, text: stripTags(html) });
        return `<h${depth} id="${id}"><a class="anchor" href="#${id}" aria-hidden="true" tabindex="-1">#</a>${html}</h${depth}>\n`;
      },
      paragraph({ tokens }) {
        const html = this.parser.parseInline(tokens);
        if (!description) description = stripTags(html).replace(/\s+/g, " ").trim();
        return `<p>${html}</p>\n`;
      },
      link({ href, title: t, tokens }) {
        const text = this.parser.parseInline(tokens);
        const target = rewriteHref(href, `${slug}.md`);
        const external = /^https?:/.test(target) && !target.startsWith(SITE.url);
        return `<a href="${escapeHtml(target)}"${t ? ` title="${escapeHtml(t)}"` : ""}${external ? ' rel="noopener"' : ""}>${text}</a>`;
      },
      code({ text, lang }) {
        const language = lang === "sh" || lang === "shell" ? "bash" : lang || "text";
        const known = LANGS.includes(language) && language !== "text";
        const html = known
          ? highlighter.codeToHtml(text, { lang: language, themes: { light: "github-light", dark: "github-dark-dimmed" }, defaultColor: false })
          : `<pre class="shiki"><code>${escapeHtml(text)}</code></pre>`;
        const label = LABELS[language] ?? "";
        return `<div class="code">${label ? `<div class="code-label">${label}</div>` : ""}<button class="copy" type="button" aria-label="Copy code">Copy</button>${html}</div>\n`;
      },
      table(token) {
        const cell = (c, tag) => `<${tag}${c.align ? ` style="text-align:${c.align}"` : ""}>${this.parser.parseInline(c.tokens)}</${tag}>`;
        const head = token.header.map((c) => cell(c, "th")).join("");
        const body = token.rows.map((row) => `<tr>${row.map((c) => cell(c, "td")).join("")}</tr>`).join("");
        return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>\n`;
      },
      blockquote({ tokens }) {
        const html = this.parser.parse(tokens);
        const alert = /^<p>\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*/.exec(html);
        if (!alert) return `<blockquote>${html}</blockquote>\n`;
        const kind = alert[1].toLowerCase();
        const body = html.slice(alert[0].length);
        return `<div class="callout callout-${kind}"><div class="callout-title"><svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[kind]}</svg>${kind[0].toUpperCase() + kind.slice(1)}</div><p>${body}</div>\n`;
      },
    },
  });

  const html = marked.parse(markdown);
  return { html, title, description, headings };
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(join(docs, "assets"), join(out, "assets"), { recursive: true });
cpSync(join(docs, "assets", "favicon.svg"), join(out, "favicon.svg"));
cpSync(join(docs, "assets", "favicon.ico"), join(out, "favicon.ico"));
cpSync(join(here, "style.css"), join(out, "assets", "style.css"));
cpSync(join(here, "app.js"), join(out, "assets", "app.js"));

const order = NAV.flatMap((g) => g.items);
const descriptions = {};
const pages = [];

for (const [slug] of order) {
  const file = join(docs, `${slug}.md`);
  if (!existsSync(file)) throw new Error(`NAV lists ${slug}.md, which does not exist`);
  descriptions[slug] = frontMatter(readFileSync(file, "utf8")).meta.description ?? "";
}

for (const [i, [slug, label]] of order.entries()) {
  const { meta, body } = frontMatter(readFileSync(join(docs, `${slug}.md`), "utf8"));
  const page = renderPage(body, slug);
  if (meta.title) page.metaTitle = meta.title;
  if (meta.description) page.description = meta.description;
  const link = (target) => {
    if (!target) return undefined;
    const rel = posix.relative(posix.dirname(slug), pageFile(target[0]));
    return { href: target[0] === "index" ? rel.replace(/index\.html$/, "") || "./" : rel, label: target[1] };
  };
  const html =
    slug === "index"
      ? home({ site: SITE, nav: NAV, descriptions })
      : layout({ site: SITE, nav: NAV, slug, page, prev: link(order[i - 1]), next: link(order[i + 1]) });
  const dest = join(out, pageFile(slug));
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, html);
  pages.push(slug);
}

writeFileSync(
  join(out, "404.html"),
  layout({
    site: SITE,
    nav: NAV,
    slug: "404",
    page: {
      title: "Page not found",
      description: "This page does not exist.",
      headings: [],
      html: '<h1>Page not found</h1><p>This page does not exist. Start from the <a href="/goraz/">overview</a> or <a href="/goraz/guides/getting-started.html">get started</a>.</p>',
    },
    absolute: true,
  }),
);
writeFileSync(
  join(out, "sitemap.xml"),
  `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${pages
    .map((p) => `  <url><loc>${SITE.url}${p === "index" ? "" : pageFile(p)}</loc></url>`)
    .join("\n")}\n</urlset>\n`,
);
writeFileSync(join(out, "robots.txt"), `User-agent: *\nAllow: /\nSitemap: ${SITE.url}sitemap.xml\n`);
writeFileSync(join(out, ".nojekyll"), "");
console.log(`Built ${pages.length} pages into _site/`);
