// shell/mfe/visage-playground.js — the <visage-playground> custom element.
//
// Defines a custom element that encapsulates the WASM + CodeMirror alias
// resolver demo. The element builds its editor DOM on connectedCallback and
// loads the required scripts (visage.js emscripten module, CodeMirror,
// codemirror-simple.js, dhall-mode.js, then app.js) in order.
//
// The interactive demo is NOT Elm-ified: the surrounding page (nav / hero /
// sections / footer) is rendered in Elm via the shared Fixpoint.* package, and
// only the WASM editor is hosted by this element. app.js is copied VERBATIM
// from docs/ (it is a pre-existing, unchanged artifact).
//
// DOM contract (must be satisfied for app.js to find its elements):
//   #addr       — text input for the alias@domain to resolve
//   #source     — textarea (converted to CodeMirror via fromTextArea)
//   #summary    — div showing the parsed-config summary
//   #result     — div showing the resolution result
//   #status     — status line
//   #runBtn     — the Run button
//   #editor-wrap — position:relative wrapper for the textarea/CodeMirror
//
// app.js is an IIFE that getElementById's these at load time and calls global
// createVisage() (emscripten MODULARIZE, EXPORT_NAME=createVisage from
// docs/visage.js). It must therefore load only AFTER the element has built this
// light-DOM and been connected to the document.
//
// The element uses light DOM (NOT shadow DOM) because app.js uses
// document.getElementById to find these elements.

const BASE = '/visage';

// Once-per-element boot guard.
const BOOTED = Symbol('booted');

// Reusable script loading (cached per URL).
const scriptCache = new Map();

function loadScript(src) {
  if (scriptCache.has(src)) {
    return scriptCache.get(src);
  }
  const promise = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.async = false; // preserve ordering
    s.onload = () => { s.remove(); resolve(); };
    s.onerror = () => { s.remove(); reject(new Error(`visage-playground: failed to load ${src}`)); };
    (document.head || document.documentElement).appendChild(s);
  });
  scriptCache.set(src, promise);
  return promise;
}

function loadFactories() {
  // visage.js (defines global createVisage) must load before app.js, and the
  // CodeMirror vendor scripts before app.js too. Order matters:
  //   visage.js → codemirror.min.js → codemirror-simple.js → dhall-mode.js
  // app.js is loaded last (see bootPlayground).
  return Promise.all([
    loadScript(`${BASE}/visage.js`),
    loadScript(`${BASE}/vendor/codemirror.min.js`),
    loadScript(`${BASE}/vendor/codemirror-simple.js`),
    loadScript(`${BASE}/vendor/dhall-mode.js`),
  ]);
}

// Minimal DOM builder helper.
function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'html') node.innerHTML = v;
      else node.setAttribute(k, v);
    }
  }
  for (const c of children || []) {
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

// Consolidated playground CSS: the fixpoint palette + the demo/editor rules
// from docs/style.css (query-bar, panes, summary/result rows, CodeMirror,
// status). The <visage-playground> element gets this because it is NOT Elm
// (and so receives none of Fixpoint.Style's stylesheet).
const PLAYGROUND_CSS = `
:root{--bg:#0b0e11;--bg2:#10141a;--fg:#d8dee6;--dim:#7d8794;--accent:#6ad6a1;--accent2:#8ab4f8;--line:#1e2730;--mono:"SFMono-Regular","Cascadia Code","JetBrains Mono","Fira Code",Menlo,Consolas,monospace;--sans:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
* {box-sizing:border-box;margin:0;padding:0}
body {background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap {max-width:780px;margin:0 auto;padding:0 24px}
.site {position:sticky;top:0;z-index:50;background:rgba(11,14,17,0.88);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.site .wrap {display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;column-gap:16px;row-gap:6px;min-height:52px;padding:10px 24px}
.site .brand {font-family:var(--mono);font-weight:700;color:var(--fg);text-decoration:none;font-size:15px;margin-right:8px}
.site .brand .fx {color:var(--accent)}
.site nav {display:flex;flex-wrap:wrap;gap:4px 14px}
.site nav a {color:var(--dim);text-decoration:none;font-family:var(--mono);font-size:13px}
.site nav a:hover {color:var(--fg)}
.site nav a.ext {color:var(--accent);font-weight:600;margin-left:6px}
.site nav a.nav-cta {color:var(--bg);background:var(--accent);border-radius:14px;padding:2px 12px;font-weight:600}
.site nav a.nav-cta:hover {background:var(--accent2)}
h1 {font-size:clamp(26px,4.5vw,38px);font-weight:750;letter-spacing:-0.02em;margin:0.6em 0 0.3em}
h2 {font-size:1.35em;font-weight:650;margin:1.8em 0 0.4em;letter-spacing:-0.01em;border-bottom:1px solid var(--line);padding-bottom:0.25em}
p {margin:0.6em 0;color:#c3ccd6}
a {color:var(--accent2);text-decoration:none}
a:hover {text-decoration:underline}
code,.code {font-family:var(--mono);font-size:0.9em}
p code,li code,td code,h2 code,h3 code {background:var(--bg2);border:1px solid var(--line);border-radius:5px;padding:1px 6px;color:var(--accent)}
pre.code {background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:16px 18px;overflow-x:auto;margin:0.8em 0;line-height:1.5;white-space:pre;color:#c3ccd6}
pre.code code {background:none;padding:0;font-size:0.9em}
.note {background:#1a2e24;border-left:4px solid var(--accent);padding:10px 14px;border-radius:6px;margin:1em 0;color:#d8dee6}
.warn {background:#2e1a1e;border-left:4px solid #ff7b72;padding:10px 14px;border-radius:6px;margin:1em 0;color:#ffd7d5}
ul {list-style:none;padding-left:0}
ul li {color:#c3ccd6;margin-bottom:6px}
/* --- demo / editor (mirrors docs/style.css) --- */
.demo {background:#0d1713;border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:1em 0}
.window-bar {display:flex;align-items:center;gap:8px;padding:10px 14px;background:rgba(255,255,255,0.02);border-bottom:1px solid var(--line);font-family:var(--mono);font-size:0.8rem;color:var(--dim)}
.window-bar .dot {width:10px;height:10px;border-radius:50%;display:inline-block}
.dot-r{background:#f87171}.dot-y{background:#fbbf24}.dot-g{background:#34d399}
.window-title{flex:1;text-align:center}
.window-badge{color:var(--accent);border:1px solid var(--accent);border-radius:10px;padding:0 8px;font-size:0.72rem}
.query-bar{display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.query-bar label{font-weight:600;font-size:0.95em}
.query-bar input[type="text"]{font-family:var(--mono);font-size:0.95em;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg2);color:var(--fg);flex:1;min-width:180px}
.query-bar button{font-size:0.95em;font-weight:600;padding:7px 18px;border:none;border-radius:6px;background:var(--accent);color:var(--bg);cursor:pointer}
.query-bar button:hover{background:var(--accent2)}
.panes{display:grid;grid-template-columns:1fr 1fr;gap:0}
@media(max-width:720px){.panes{grid-template-columns:1fr}}
.pane{padding:14px}
.pane+.pane{border-left:1px solid var(--line)}
.pane label{display:block;font-size:0.8rem;color:var(--dim);font-family:var(--mono);margin-bottom:8px}
.summary,.result{background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:4px;min-height:60px;overflow:auto}
.sum-line{padding:8px 12px;border-bottom:1px solid var(--border-soft, var(--line));color:#c3ccd6;font-family:var(--mono);font-size:0.84rem}
.sum-line:last-child{border-bottom:none}
.alias-row{display:flex;justify-content:space-between;gap:10px;padding:8px 12px;border-bottom:1px solid var(--border-soft, var(--line))}
.alias-row:hover{background:rgba(255,255,255,0.02)}
.alias-name{color:var(--fg);font-weight:600;font-family:var(--mono);font-size:0.84rem}
.alias-dests{color:var(--accent);word-break:break-all;font-family:var(--mono);font-size:0.84rem}
.ans-empty{padding:14px 16px;color:var(--dim);font-family:var(--mono);font-size:0.88rem}
.decide{display:inline-block;padding:3px 12px;border-radius:8px;font-weight:700;font-family:var(--mono);font-size:0.9rem;margin:8px 12px 0}
.decide.accept{color:#0b2418;background:#34d399}
.decide.reject{color:#2a0d0d;background:#f87171}
.route{padding:2px 14px 8px;font-family:var(--mono);font-size:0.84rem;color:var(--dim)}
.dest-row{padding:8px 14px;font-family:var(--mono);font-size:0.84rem;color:#c3ccd6}
.dest-row::before{content:"→ ";color:var(--accent);font-weight:700}
.result .ans-empty{border-top:1px solid var(--border-soft, var(--line))}
.demo-foot{padding:8px 14px;border-top:1px solid var(--line);font-family:var(--mono);font-size:0.84rem;color:var(--dim)}
#status{color:var(--dim);font-size:0.84rem;font-family:var(--mono)}
#status.error{color:#f87171}
#editor-wrap{position:relative;overflow:hidden;background:#0d1713;border:1px solid var(--line);border-radius:9px}
#editor-wrap textarea{display:none}
#editor-wrap .CodeMirror{height:300px;background:#0d1713;color:var(--fg)}
#editor-wrap .CodeMirror-gutters{background:#0d1713;border-right:1px solid var(--line)}
#editor-wrap .CodeMirror-linenumber{color:#2f4d3e;padding:0 8px 0 12px}
#editor-wrap .CodeMirror-cursor{border-left:2px solid var(--accent)}
#editor-wrap .CodeMirror-selected{background:rgba(45,212,167,0.14)}
#editor-wrap .CodeMirror-focused .CodeMirror-selected{background:rgba(45,212,167,0.2)}
#editor-wrap .CodeMirror-activeline-background{background:rgba(255,255,255,0.03)}
#editor-wrap .CodeMirror{color:var(--fg)}
#editor-wrap .cm-s-dhall .cm-keyword{color:#2dd4a7;font-weight:600}
#editor-wrap .cm-s-dhall .cm-type{color:#fbbf24;font-weight:600}
#editor-wrap .cm-s-dhall .cm-atom{color:#38bdf8}
#editor-wrap .cm-s-dhall .cm-builtin{color:#38bdf8}
#editor-wrap .cm-s-dhall .cm-string{color:#4ade80}
#editor-wrap .cm-s-dhall .cm-number{color:#fca5a5}
#editor-wrap .cm-s-dhall .cm-comment{color:#4f6b5e;font-style:italic}
#editor-wrap .cm-s-dhall .cm-operator{color:#94a3b8}
#editor-wrap .cm-s-dhall .cm-variable{color:var(--fg)}
.CodeMirror{font-size:13px;line-height:1.5}
footer.site-foot{margin-top:3em;padding:1.4em 0 2em;border-top:1px solid var(--line);color:var(--dim);font-family:var(--mono);font-size:13px;text-align:center}
`;

/**
 * Wait until `element` is attached to the live document.
 */
function waitConnected(element) {
  if (element.isConnected) return Promise.resolve();
  return new Promise((resolve) => {
    const check = () => {
      if (element.isConnected) resolve();
      else requestAnimationFrame(check);
    };
    requestAnimationFrame(check);
  });
}

/**
 * Boot the playground: load factories then app.js against the element's DOM.
 * app.js must load AFTER the DOM is built and connected (it getElementById's
 * the editor/status elements at load time).
 */
async function bootPlayground(element) {
  await waitConnected(element);
  await loadFactories();
  await loadScript(`${BASE}/app.js`);
}

/**
 * The <visage-playground> custom element.
 */
class VisagePlayground extends HTMLElement {
  constructor() {
    super();
    this[BOOTED] = false;
    this._styleEl = null;
    this._linkEl = null;
  }

  connectedCallback() {
    if (this[BOOTED]) return;
    this[BOOTED] = true;

    // Build the demo DOM inside the element (light DOM), matching the
    // docs/index.html #demo structure so app.js finds its elements.
    const windowBar = el('div', { class: 'window-bar' }, [
      el('span', { class: 'dot dot-r' }),
      el('span', { class: 'dot dot-y' }),
      el('span', { class: 'dot dot-g' }),
      el('span', { class: 'window-title' }, ['visage — in your browser']),
      el('span', { class: 'window-badge' }, ['wasm']),
    ]);
    const queryBar = el('div', { class: 'query-bar' }, [
      el('label', { for: 'addr' }, ['Alias']),
      el('input', { id: 'addr', type: 'text', placeholder: 'shopping@example.com', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off' }),
      el('button', { id: 'runBtn', class: 'btn btn-primary run', type: 'button' }, ['Run']),
    ]);
    const leftPane = el('div', { class: 'pane' }, [
      el('label', { for: 'source' }, ['Dhall config']),
      el('div', { id: 'editor-wrap' }, [
        el('textarea', { id: 'source', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off' }),
      ]),
    ]);
    const rightPane = el('div', { class: 'pane' }, [
      el('label', {}, ['Parsed config']),
      el('div', { id: 'summary', class: 'summary' }, [el('div', { class: 'ans-empty' }, ['loading wasm…'])]),
      el('label', { style: 'margin-top:14px;display:block' }, ['Resolution result']),
      el('div', { id: 'result', class: 'result' }, [el('div', { class: 'ans-empty' }, ['—'])]),
    ]);
    const demoFoot = el('div', { class: 'demo-foot' }, [
      el('span', { id: 'status', class: 'status' }, ['loading wasm…']),
    ]);
    const demo = el('div', { class: 'demo' }, [windowBar, queryBar, el('div', { class: 'panes' }, [leftPane, rightPane]), demoFoot]);

    // Clear any existing content and append the demo DOM.
    this.textContent = '';
    this.appendChild(demo);

    // Inject CSS: codemirror.css link + inline PLAYGROUND_CSS.
    this._linkEl = document.createElement('link');
    this._linkEl.rel = 'stylesheet';
    this._linkEl.href = `${BASE}/vendor/codemirror.css`;
    document.head.appendChild(this._linkEl);

    this._styleEl = document.createElement('style');
    this._styleEl.textContent = PLAYGROUND_CSS;
    document.head.appendChild(this._styleEl);

    // Boot the playground scripts non-blocking.
    void bootPlayground(this);
  }

  disconnectedCallback() {
    // Clean up injected styles if this element is removed.
    if (this._styleEl) {
      this._styleEl.remove();
      this._styleEl = null;
    }
    if (this._linkEl) {
      this._linkEl.remove();
      this._linkEl = null;
    }
  }
}

// Register the custom element.
customElements.define('visage-playground', VisagePlayground);
