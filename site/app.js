// goraz documentation: theme toggle, mobile navigation, copy buttons and the "On this page" highlight.
(() => {
  const root = document.documentElement;
  const store = (value) => {
    try {
      localStorage.setItem("goraz-theme", value);
    } catch {}
  };

  document.querySelector(".theme-btn")?.addEventListener("click", () => {
    const current = root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = current === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    store(next);
  });

  const menu = document.querySelector(".menu-btn");
  const scrim = document.querySelector(".scrim");
  const setNav = (open) => {
    document.body.classList.toggle("nav-open", open);
    menu?.setAttribute("aria-expanded", String(open));
    if (scrim) scrim.hidden = !open;
  };
  menu?.addEventListener("click", () => setNav(!document.body.classList.contains("nav-open")));
  scrim?.addEventListener("click", () => setNav(false));
  document.addEventListener("keydown", (e) => e.key === "Escape" && setNav(false));

  for (const button of document.querySelectorAll(".copy")) {
    button.addEventListener("click", async () => {
      const code = button.parentElement.querySelector("pre")?.innerText ?? "";
      try {
        await navigator.clipboard.writeText(code.replace(/\n$/, ""));
        button.textContent = "Copied";
        button.classList.add("done");
        setTimeout(() => {
          button.textContent = "Copy";
          button.classList.remove("done");
        }, 1600);
      } catch {
        button.textContent = "Press ⌘C";
      }
    });
  }

  const links = [...document.querySelectorAll(".toc a")];
  if (links.length && "IntersectionObserver" in window) {
    const byId = new Map(links.map((a) => [decodeURIComponent(a.hash.slice(1)), a]));
    const headings = [...byId.keys()].map((id) => document.getElementById(id)).filter(Boolean);
    const visible = new Set();
    const update = () => {
      const first = headings.find((h) => visible.has(h)) ?? headings.filter((h) => h.getBoundingClientRect().top < 120).at(-1);
      links.forEach((a) => a.classList.toggle("active", first && byId.get(first.id) === a));
    };
    const observer = new IntersectionObserver(
      (entries) => {
        for (const e of entries) e.isIntersecting ? visible.add(e.target) : visible.delete(e.target);
        update();
      },
      { rootMargin: "-70px 0px -65% 0px" },
    );
    headings.forEach((h) => observer.observe(h));
  }
})();
