// shell/pages.js — canonical page definitions for visage MFE site.
//
// Single source of truth for all routes, templates, slots, and output paths.
// Imported by both shell/shell.js (browser ESM) and scripts/ssg.mjs (Node ESM).
//
// CANONICAL ROUTE TABLE (6 visage pages):
//   '/visage'                → template 'visage-landing'
//   '/visage/compactness'    → template 'visage-compactness'
//   '/visage/security'       → template 'visage-security'
//   '/visage/config'         → template 'visage-config'
//   '/visage/cli'            → template 'visage-cli'
//   '/visage/playground'     → template 'visage-playground'
//
// SLOT NAME == TEMPLATE NAME for all visage pages.
// The landing page's `dir` is '' so its output is dist/index.html.
// All other content pages have dir == slug, output to dist/<slug>/index.html.
// The playground IS Elm-rendered (its hero/sections) with the interactive
// WASM+CodeMirror alias resolver hosted by the <visage-playground> custom
// element, so it is type 'content' like the other pages (it IS pre-rendered).
// The cross-nav home route '/' → 'fixpoint' is handled separately (main site owns
// /shell/templates/fixpoint.html and the importmap key 'fixpoint-landing').

export const PAGES = [
  {
    slug: 'visage',
    path: '/visage',
    slot: 'visage-landing',
    template: 'visage-landing',
    dir: '',
    title: 'visage — a compact email alias & forwarding server in C',
    type: 'content',
  },
  {
    slug: 'compactness',
    path: '/visage/compactness',
    slot: 'visage-compactness',
    template: 'visage-compactness',
    dir: 'compactness',
    title: 'Compactness — visage',
    type: 'content',
  },
  {
    slug: 'security',
    path: '/visage/security',
    slot: 'visage-security',
    template: 'visage-security',
    dir: 'security',
    title: 'Security — visage',
    type: 'content',
  },
  {
    slug: 'config',
    path: '/visage/config',
    slot: 'visage-config',
    template: 'visage-config',
    dir: 'config',
    title: 'Config — visage',
    type: 'content',
  },
  {
    slug: 'cli',
    path: '/visage/cli',
    slot: 'visage-cli',
    template: 'visage-cli',
    dir: 'cli',
    title: 'CLI — visage',
    type: 'content',
  },
  {
    slug: 'playground',
    path: '/visage/playground',
    slot: 'visage-playground',
    template: 'visage-playground',
    dir: 'playground',
    title: 'Playground — visage',
    type: 'content',
  },
];

// All content pages (Elm-rendered) — all of visage's pages, since the
// playground is Elm-rendered chrome + a custom element for the editor.
export const CONTENT_PAGES = PAGES.filter((p) => p.type === 'content');

// Just the visage pages (all of them)
export const VISAGE_PAGES = PAGES;
