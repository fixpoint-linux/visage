/* wasm-smoke.js — headless smoke test for the visage alias wasm module.
 * Run from the repo root via `node tests/wasm-smoke.js` (after `make wasm`).
 */
const fs = require('fs');
const path = require('path');
const createVisage = require(path.join(__dirname, '..', 'docs', 'visage.js'));

const config = fs.readFileSync(path.join(__dirname, '..', 'config.example.dhall'), 'utf8');

function alloc(M, s) {
  const b = M.lengthBytesUTF8(s);
  const p = M._malloc(b + 1);
  M.stringToUTF8(s, p, b + 1);
  return p;
}

createVisage().then((M) => {
  const p = alloc(M, config);
  const rc = M._visage_load(p);
  M._free(p);
  if (rc !== 0) {
    console.error('CONFIG ERROR:', M.UTF8ToString(M._visage_err()));
    process.exit(1);
  }
  const summary = JSON.parse(M.UTF8ToString(M._visage_json(), M._visage_json_len()));
  if (summary.hostname !== 'mx.example.com') throw new Error('hostname ' + summary.hostname);
  if (summary.naliases !== 2) throw new Error('expected 2 aliases, got ' + summary.naliases);
  console.log('loaded config:', summary.hostname, '| domains', summary.domains.join(','), '| aliases', summary.naliases);

  function resolve(addr) {
    const a = alloc(M, addr);
    const r = M._visage_resolve(a);
    M._free(a);
    if (r !== 0) throw new Error('resolve error: ' + M.UTF8ToString(M._visage_err()));
    return JSON.parse(M.UTF8ToString(M._visage_json(), M._visage_json_len()));
  }

  function expect(label, addr, decision, route, dests) {
    const j = resolve(addr);
    if (j.decision !== decision) throw new Error(label + ': decision ' + j.decision + ' != ' + decision);
    if (j.route !== route) throw new Error(label + ': route ' + j.route + ' != ' + route);
    if (JSON.stringify(j.destinations) !== JSON.stringify(dests))
      throw new Error(label + ': dests ' + JSON.stringify(j.destinations) + ' != ' + JSON.stringify(dests));
    console.log('  ok', label, '->', decision, 'via', route, '=>', j.destinations.join(', '));
  }

  expect('single dest', 'jane@example.com', 'accept', 'alias', ['jane@realmail.example']);
  expect('multi dest', 'shopping@example.com', 'accept', 'alias', ['jane@realmail.example', 'bob@realmail.example']);
  expect('case-insensitive', 'JANE@EXAMPLE.COM', 'accept', 'alias', ['jane@realmail.example']);
  expect('unknown alias (catch_all empty)', 'unknown@example.com', 'reject', '', []);
  expect('bad domain', 'jane@other.com', 'reject', '', []);
  expect('malformed', 'not-an-address', 'reject', '', []);

  // Edit the config: enable catch_all, then unknown@example.com resolves to it.
  const edited = config.replace('catch_all = ""', 'catch_all = "jane@realmail.example"');
  const p2 = alloc(M, edited);
  if (M._visage_load(p2) !== 0) throw new Error('reload error: ' + M.UTF8ToString(M._visage_err()));
  M._free(p2);
  expect('catch-all (edited)', 'unknown@example.com', 'accept', 'catch_all', ['jane@realmail.example']);

  console.log('SMOKE OK');
});
