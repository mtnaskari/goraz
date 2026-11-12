const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

const ICON = {
  github:
    '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>',
  sun: '<svg viewBox="0 0 24 24" aria-hidden="true" class="i-sun"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  moon: '<svg viewBox="0 0 24 24" aria-hidden="true" class="i-moon"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>',
  menu: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>',
  arrowL: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15 18l-6-6 6-6"/></svg>',
  arrowR: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>',
  edit: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg>',
  lock: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
};

// Applied before paint so the page never flashes the wrong theme.
const THEME_BOOT = `<script>try{var t=localStorage.getItem("goraz-theme");if(t)document.documentElement.dataset.theme=t}catch(e){}</script>`;

const href = (base, slug) => (slug === "index" ? `${base}./` : `${base}${slug}.html`);

function head({ site, title, description, path, base }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${site.url}${path}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="${site.name}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:url" content="${site.url}${path}">
<meta property="og:image" content="${site.url}assets/banner-light.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="theme-color" content="#f6f4f0" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#131211" media="(prefers-color-scheme: dark)">
<link rel="icon" href="${base}favicon.svg" type="image/svg+xml">
<link rel="icon" href="${base}favicon.ico" sizes="any">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&family=Vazirmatn:wght@400;600&display=swap">
<link rel="stylesheet" href="${base}assets/style.css">
${THEME_BOOT}
</head>`;
}

function topbar({ site, base, withMenu }) {
  return `<header class="topbar">
  <div class="topbar-inner">
    ${withMenu ? `<button class="icon-btn menu-btn" type="button" aria-label="Open navigation" aria-expanded="false" aria-controls="sidebar">${ICON.menu}</button>` : ""}
    <a class="brand" href="${base}./">
      <img class="logo-light" src="${base}assets/logo.svg" alt="" width="28" height="28">
      <img class="logo-dark" src="${base}assets/logo-white.svg" alt="" width="28" height="28">
      <span>goraz</span>
    </a>
    <span class="version">v${site.version}</span>
    <nav class="top-links" aria-label="Main">
      <a href="${base}guides/getting-started.html">Get started</a>
      <a href="${base}cli-reference.html">Commands</a>
      <a href="https://pkg.go.dev/github.com/mtnaskari/goraz">Go API</a>
    </nav>
    <div class="top-actions">
      <a class="icon-btn" href="${site.repo}" aria-label="goraz on GitHub">${ICON.github}</a>
      <button class="icon-btn theme-btn" type="button" aria-label="Switch colour theme">${ICON.sun}${ICON.moon}</button>
    </div>
  </div>
</header>`;
}

function sidebar({ nav, slug, base }) {
  return `<aside class="sidebar" id="sidebar">
  <nav aria-label="Documentation">
${nav
  .map(
    (g) => `    <div class="nav-group">
      <p class="nav-title">${esc(g.group)}</p>
      <ul>
${g.items.map(([s, label]) => `        <li><a href="${href(base, s)}"${s === slug ? ' aria-current="page"' : ""}>${esc(label)}</a></li>`).join("\n")}
      </ul>
    </div>`,
  )
  .join("\n")}
  </nav>
</aside>`;
}

function footer({ site }) {
  return `<footer class="site-footer">
  <p>goraz is open source under the <a href="${site.repo}/blob/main/LICENSE">Apache-2.0 license</a>. Copyright 2026 Matin Askari.</p>
  <p><a href="${site.repo}">GitHub</a> · <a href="https://pkg.go.dev/github.com/mtnaskari/goraz">pkg.go.dev</a> · <a href="${site.repo}/releases">Releases</a> · <a href="${site.repo}/issues">Issues</a> · <a href="${site.repo}/blob/main/SECURITY.md">Security</a></p>
</footer>`;
}

export function layout({ site, nav, slug, page, prev, next, absolute = false }) {
  const depth = slug.split("/").length - 1;
  const base = absolute ? "/goraz/" : "../".repeat(depth);
  const path = slug === "404" ? "404.html" : `${slug}.html`;
  const title = page.metaTitle ?? `${page.title} · ${site.name}`;
  const toc = page.headings.filter((h) => h.depth === 2 || h.depth === 3);
  return `${head({ site, title, description: page.description, path, base })}
<body>
<a class="skip" href="#content">Skip to content</a>
${topbar({ site, base, withMenu: true })}
<div class="shell">
${sidebar({ nav, slug, base })}
<div class="scrim" hidden></div>
<main id="content" class="main">
  <article class="prose">
${page.html}
  </article>
  ${
    prev || next
      ? `<nav class="pager" aria-label="Previous and next pages">
    ${prev ? `<a class="pager-prev" href="${prev.href}"><span>${ICON.arrowL}Previous</span><strong>${esc(prev.label)}</strong></a>` : "<span></span>"}
    ${next ? `<a class="pager-next" href="${next.href}"><span>Next${ICON.arrowR}</span><strong>${esc(next.label)}</strong></a>` : "<span></span>"}
  </nav>`
      : ""
  }
  ${slug === "404" ? "" : `<p class="edit"><a href="${site.repo}/edit/main/docs/${slug}.md">${ICON.edit}Edit this page on GitHub</a></p>`}
  ${footer({ site })}
</main>
${
  toc.length > 1
    ? `<aside class="toc" aria-label="On this page">
  <p class="toc-title">On this page</p>
  <ul>
${toc.map((h) => `    <li class="toc-${h.depth}"><a href="#${h.id}">${esc(h.text)}</a></li>`).join("\n")}
  </ul>
</aside>`
    : ""
}
</div>
<script src="${base}assets/app.js" defer></script>
</body>
</html>
`;
}

const FEATURES = [
  ["All metadata is encrypted", "Names, usernames and URLs are invisible in the file, not only the values.", '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>'],
  ["Tampering is detected", "Changed, swapped, removed or older data is refused, with documented limits.", '<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/>'],
  ["Limits come from encryption", "A service's file holds only its own secrets, so there is nothing else to leak.", '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 17.5h7M17.5 14v7"/>'],
  ["Off the command line", "Secrets are never read from arguments or environment variables, so they stay out of history.", '<path d="m5 8 4 4-4 4M12 16h7"/>'],
  ["Audit by default", "A read fails if it can't be logged, and the log holds no names or values.", '<path d="M8 3h8l4 4v14H4V3z"/><path d="M8 11h8M8 15h8M8 7h4"/>'],
  ["Few dependencies", "Only Go's standard library and golang.org/x modules, with a published file format.", '<path d="M12 2 3 7v10l9 5 9-5V7z"/><path d="m3 7 9 5 9-5M12 12v10"/>'],
];

export function home({ site, nav, descriptions }) {
  return `${head({ site, title: "goraz: encrypted secrets, API tokens and passwords for Go", description: site.tagline, path: "", base: "" })}
<body class="home">
<a class="skip" href="#content">Skip to content</a>
${topbar({ site, base: "", withMenu: false })}
<main id="content">
  <section class="hero">
    <div class="hero-text">
      <p class="eyebrow"><span class="spark" aria-hidden="true">✦</span> Go + <span lang="fa">راز</span> (secret)</p>
      <h1>Secrets that stay encrypted. <em>No server required.</em></h1>
      <p class="lead">goraz is a Go library and command-line tool that keeps API tokens, secrets and passwords in an encrypted file. Each production service gets its own file holding only what it needs.</p>
      <div class="cta">
        <a class="btn btn-primary" href="guides/getting-started.html">Get started</a>
        <a class="btn btn-ghost" href="${site.repo}">${ICON.github}View on GitHub</a>
      </div>
    </div>
    <div class="hero-demo" aria-hidden="true">
      <div class="window">
        <div class="window-bar"><i></i><i></i><i></i><span>Terminal</span></div>
        <pre><code><span class="t-dim">$</span> <span class="t-tag">goraz</span> init
<span class="t-dim">$</span> <span class="t-tag">goraz</span> put <span class="t-str">prod/db/password</span>
<span class="t-dim">$</span> <span class="t-tag">goraz</span> run <span class="t-attr">--env</span> DB_PASSWORD=<span class="t-str">goraz://prod/db/password</span> \\
    -- ./my-app</code></pre>
      </div>
      <div class="chat vault-card">
        <div class="chat-head">${ICON.lock} vault.goraz</div>
        <div class="vault-rows">
          <span style="width:72%"></span><span style="width:54%"></span><span style="width:86%"></span><span style="width:40%"></span>
        </div>
        <div class="chat-buttons"><span>XChaCha20-Poly1305</span><span>Argon2id</span></div>
      </div>
    </div>
  </section>

  <aside class="notice" role="note">
    <strong>Early release.</strong> goraz 0.1 has not had an independent security audit. Read <a href="threat-model.html#4-what-goraz-does-not-defend-against">what it does not defend against</a> before relying on it.
  </aside>

  <section class="flow" aria-label="How it works">
    <div class="flow-step"><span class="num">1</span><h3>Store</h3><p>Put secrets in an encrypted vault from a hidden prompt or a pipe, never from arguments.</p></div>
    <div class="flow-arrow" aria-hidden="true"></div>
    <div class="flow-step"><span class="num">2</span><h3>Split</h3><p>Give each service its own file with only its items, and its key separately.</p></div>
    <div class="flow-arrow" aria-hidden="true"></div>
    <div class="flow-step"><span class="num">3</span><h3>Read</h3><p>Open the file from Go, or let <code>goraz run</code> pass values to any program.</p></div>
  </section>

  <section class="features" aria-label="What's different">
${FEATURES.map(([t, d, icon]) => `    <div class="feature"><svg viewBox="0 0 24 24" aria-hidden="true">${icon}</svg><h3>${esc(t)}</h3><p>${esc(d)}</p></div>`).join("\n")}
  </section>

  <section class="doc-map" aria-labelledby="docs-title">
    <h2 id="docs-title">Documentation</h2>
    <div class="doc-grid">
${nav
  .map(
    (g) => `      <div class="doc-card">
        <h3>${esc(g.group)}</h3>
        <p class="doc-card-intro">${esc(g.intro ?? "")}</p>
        <ul>
${g.items
  .filter(([s]) => s !== "index")
  .map(([s, label]) => `          <li><a href="${s}.html"><strong>${esc(label)}</strong><span>${esc(descriptions[s] ?? "")}</span></a></li>`)
  .join("\n")}
        </ul>
      </div>`,
  )
  .join("\n")}
    </div>
  </section>
  ${footer({ site })}
</main>
<script src="assets/app.js" defer></script>
</body>
</html>
`;
}
