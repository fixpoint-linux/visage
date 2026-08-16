/* dhall-mode.js — a CodeMirror 5 mode for the Dhall subset, using the
 * defineSimpleMode helper (vendored from addon/mode/simple.js). Token classes
 * map to standard CodeMirror styles (cm-keyword / cm-string / cm-number /
 * cm-comment / cm-atom / cm-builtin / cm-operator / cm-variable), which the
 * site's theme (cm-s-dhall in style.css) colours to match the page palette. */
(function () {
  'use strict';
  if (typeof CodeMirror === 'undefined' || !CodeMirror.defineSimpleMode) return;

  CodeMirror.defineSimpleMode('dhall', {
    // The token stream is processed per-line; `--` line comments, block
    // comments are multi-line via the `comment` state, strings/numbers carry
    // their own states. Token classes keep the names CodeMirror's default
    // theme understands.
    start: [
      { regex: /"(?:[^"\\]|\\.)*"/, token: 'string' },
      { regex: /--.*$/, token: 'comment' },
      { regex: /\{-/, token: 'comment', next: 'comment' },

      // keywords / control
      { regex: /\b(let|in|if|then|else|merge|assert|as|with|using|missing|forall)\b/, token: 'keyword' },
      // builtin function names like List/map, List/length, Natural/build
      // (must precede the builtin-type rule so List/map wins over List)
      { regex: /\b[A-Za-z_][A-Za-z0-9_]*\/[A-Za-z_][A-Za-z0-9_]*\b/, token: 'builtin' },
      // builtin types
      { regex: /\b(Natural|Integer|Double|Text|Bool|List|Optional|Type|Kind)\b/, token: 'type' },
      // booleans
      { regex: /\b(True|False)\b/, token: 'atom' },
      // numbers (natural, integer, double, hex)
      { regex: /-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)/, token: 'number' },
      // identifiers
      { regex: /[A-Za-z_][A-Za-z0-9_]*/, token: 'variable' },
      // operators (ASCII + Unicode), longest first
      { regex: /(?:\-\>|\/\=|\/\/|\=\=|!\=|<\=|>\=|&&|\|\|)/, token: 'operator' },
      { regex: /[\u2192\u2200\u2227\u2228\u2261\u2afd\u2a3e\u03bb]/, token: 'operator' },
      { regex: /[+\-*\/=:<>,.?!]/, token: 'operator' }
    ],
    comment: [
      { regex: /.*?-\}/, token: 'comment', next: 'start' },
      { regex: /.*/, token: 'comment' }
    ],
    meta: {
      lineComment: '--',
      blockCommentStart: '{-',
      blockCommentEnd: '-}'
    }
  });

  CodeMirror.defineMIME('text/x-dhall', 'dhall');
})();
