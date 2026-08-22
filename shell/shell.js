// shell/shell.js — @mfe/framework thin-shell entry for the visage MFE site.
//
// Boots the visage docs app with 7 routes:
//   '/'                 → template 'fixpoint'         (cross-nav home, main site)
//   '/visage'           → template 'visage-landing'
//   '/visage/compactness' → template 'visage-compactness'
//   '/visage/security'  → template 'visage-security'
//   '/visage/config'    → template 'visage-config'
//   '/visage/cli'       → template 'visage-cli'
//   '/visage/playground' → template 'visage-playground'
//
// Matching the main site means a data-mfe-route like '/visage' or '/'
// resolves the same way on either page, so cross-site MFE nav links agree.
//
// The pages ship statically pre-rendered (see scripts/ssg.mjs): the #app root
// carries an `ssr` attribute, so createApp rehydrates the existing DOM in
// place instead of wiping it and re-fetching the template on first paint.
//
// Rehydrate only when the current pathname (trailing-slash-stripped) matches
// a pre-rendered visage page (i.e. starts with /visage — ALL six pages are
// pre-rendered, including the playground, whose chrome is Elm while the
// <visage-playground> custom element boots client-side).

import { createApp } from '@mfe/framework';

const app = await createApp({
  root: document.getElementById('app'),
  routes: [
    { path: '/', template: 'fixpoint', name: 'home' },
    { path: '/visage', template: 'visage-landing', name: 'visage-landing' },
    { path: '/visage/compactness', template: 'visage-compactness', name: 'visage-compactness' },
    { path: '/visage/security', template: 'visage-security', name: 'visage-security' },
    { path: '/visage/config', template: 'visage-config', name: 'visage-config' },
    { path: '/visage/cli', template: 'visage-cli', name: 'visage-cli' },
    { path: '/visage/playground', template: 'visage-playground', name: 'visage-playground' },
  ],
  basePath: '/',
  // visage's templates are served from /visage/shell/templates
  // (the main site owns /shell/templates). Pin the baseURL here so both route
  // templates resolve under this site's shell regardless of the deep-link subpath.
  baseURL: '/visage/shell/templates',
  // The SSG output pre-renders all six content pages (incl. the playground's
  // Elm chrome). Rehydrate whenever the current pathname is a /visage route.
  ssr: (() => {
    const path = (window.location.pathname.replace(/\/+$/, '') || '/');
    return path.startsWith('/visage');
  })(),
});

// Expose the app handle so the shell/host can inspect or drive it later.
window.__visageApp = app;
