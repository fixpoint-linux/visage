#!/usr/bin/env node
/**
 * tests/playground-smoke.mjs — happy-dom smoke test for the <visage-playground>
 * custom element.
 *
 * Imports shell/mfe/visage-playground.js in a happy-dom Window (the module
 * self-registers <visage-playground>), mounts the element, and asserts that
 * connectedCallback builds the exact DOM contract docs/app.js needs:
 *   #addr, #source (textarea), #summary, #result, #status, #runBtn, #editor-wrap
 * and that the demo scripts load in the correct order (visage.js first, app.js
 * LAST, after the DOM is built). Network loads are stubbed via a fake
 * document.head + fake <script> so nothing is fetched — we verify the
 * newly-reconstructed DOM-building boot path, not the wasm/CodeMirror fetch.
 *
 * Run from repo root:  node tests/playground-smoke.mjs
 */
import { Window } from 'happy-dom';

const window = new Window();
// Install the browser globals the element module touches at import/mount time.
const globals = [
  'window', 'document', 'customElements', 'HTMLElement', 'requestAnimationFrame',
  'performance', 'Node', 'Element', 'DocumentFragment', 'Text', 'Map', 'Symbol',
];
for (const name of globals) {
  const v = window[name];
  if (v === undefined) continue;
  Object.defineProperty(globalThis, name, { value: v, configurable: true, writable: true });
}

// The module's loadScript() does `(document.head || document.documentElement)
// .appendChild(s)`. Replace document.head with a fake recorder so appending a
// <script> records its src (in order) and fires onload async, never touching
// happy-dom's real script loader (which would try a network fetch).
const loadedScripts = [];
const fakeHead = {
  appendChild(node) {
    loadedScripts.push(String(node.src || ''));
    setTimeout(() => node.onload && node.onload(), 0);
    return node;
  },
  removeChild() {},
};
Object.defineProperty(globalThis.document, 'head', { value: fakeHead, configurable: true, writable: true });
globalThis.document.documentElement.appendChild = fakeHead.appendChild;

// Fake <script> elements: plain objects with src + onload, so happy-dom's
// HTMLScriptElement private-field loader is never constructed.
const realCreateElement = globalThis.document.createElement.bind(globalThis.document);
globalThis.document.createElement = (tag, opts) => {
  if (tag === 'script') {
    return { src: '', onload: null, onerror: null, remove() {} };
  }
  return realCreateElement(tag, opts);
};

// Import the module — this defines <visage-playground>.
await import('../shell/mfe/visage-playground.js');

if (!globalThis.customElements.get('visage-playground')) {
  console.error('FAIL: visage-playground custom element was not registered');
  process.exit(1);
}

// Mount it.
const host = globalThis.document.createElement('div');
globalThis.document.body.appendChild(host);
host.innerHTML = '<visage-playground></visage-playground>';
const el = host.querySelector('visage-playground');
if (!el) { console.error('FAIL: element not found in DOM'); process.exit(1); }

// Allow connectedCallback + boot to run.
await new Promise((r) => setTimeout(r, 80));

const missing = [];
for (const id of ['addr', 'source', 'summary', 'result', 'status', 'runBtn', 'editor-wrap']) {
  if (!globalThis.document.getElementById(id)) missing.push(id);
}
if (missing.length) {
  console.error(`FAIL: missing DOM elements: ${missing.join(', ')}`);
  process.exit(1);
}
const ta = globalThis.document.getElementById('source');
if (ta.tagName !== 'TEXTAREA') {
  console.error(`FAIL: #source should be a TEXTAREA, got ${ta.tagName}`);
  process.exit(1);
}
// Order: visage.js + CodeMirror vendor first, app.js LAST (after DOM built).
const appIdx = loadedScripts.findIndex((s) => s.endsWith('/app.js'));
const visIdx = loadedScripts.findIndex((s) => s.endsWith('/visage.js'));
const cmIdx = loadedScripts.findIndex((s) => s.includes('/vendor/codemirror.min.js'));
if (appIdx === -1 || appIdx <= visIdx || cmIdx === -1 || appIdx <= cmIdx || appIdx !== loadedScripts.length - 1) {
  console.error(`FAIL: bad script order. got=${JSON.stringify(loadedScripts)}`);
  process.exit(1);
}

console.log(`PASS: <visage-playground> builds the full app.js DOM contract.`);
console.log(`  script load order: ${loadedScripts.join(' → ')}`);
process.exit(0);
