/* app.js — wires the emscripten WASM module (window.createVisage from visage.js)
 * to the live demo. Mirrors compendium's docs/app.js structure.
 */
(function () {
  'use strict';

  var Module = null;

  var statusEl = document.getElementById('status');
  var runBtn = document.getElementById('runBtn');
  var addrEl = document.getElementById('addr');
  var summaryEl = document.getElementById('summary');
  var resultEl = document.getElementById('result');

  var editor = CodeMirror.fromTextArea(document.getElementById('source'), {
    mode: 'dhall',
    theme: 'dhall',
    lineNumbers: true,
    indentUnit: 2,
    tabSize: 2,
    lineWrapping: true
  });

  var DEFAULT_SRC =
    'let Auth = { enabled : Bool, username : Text, password : Text }\n' +
    'in  let Config =\n' +
    '      { hostname : Text\n' +
    '      , domains : List Text\n' +
    '      , listen : { address : Text, port : Natural }\n' +
    '      , limits : { message : Natural, line : Natural, rcpts : Natural\n' +
    '                 , cmd_timeout : Natural, data_timeout : Natural }\n' +
    '      , relay : { host : Text, port : Natural, auth : Auth, retries : Natural\n' +
    '                , tls : Text, tls_ca : Text, max_attempts : Natural }\n' +
    '      , storage : { path : Text, spool : Text }\n' +
    '      , reply : { prefix : Text, separator : Text }\n' +
    '      , catch_all : Text\n' +
    '      , aliases : List { alias : Text, destinations : List Text }\n' +
    '      , http : { address : Text, port : Natural }\n' +
    '      , admin : { token : Text }\n' +
    '      , dkim : List { domain : Text, selector : Text, private_key : Text }\n' +
    '      }\n' +
    'in  { hostname = "mx.example.com"\n' +
    '   , domains = [ "example.com" ]\n' +
    '   , listen = { address = "0.0.0.0", port = 2525 }\n' +
    '   , limits = { message = 26214400, line = 1000, rcpts = 100\n' +
    '              , cmd_timeout = 300, data_timeout = 600 }\n' +
    '   , relay = { host = "127.0.0.1", port = 2526\n' +
    '             , auth = { enabled = False, username = "", password = "" }\n' +
    '             , retries = 3, tls = "none", tls_ca = "", max_attempts = 100 }\n' +
    '   , storage = { path = "./var/db", spool = "./var/spool" }\n' +
    '   , reply = { prefix = "reply", separator = "+" }\n' +
    '   , catch_all = ""\n' +
    '   , aliases = [ { alias = "jane@example.com", destinations = [ "jane@realmail.example" ] }\n' +
    '               , { alias = "shopping@example.com", destinations = [ "jane@realmail.example", "bob@realmail.example" ] }\n' +
    '               ]\n' +
    '   , http = { address = "127.0.0.1", port = 8080 }\n' +
    '   , admin = { token = "change-me" }\n' +
    '   , dkim = [] : List { domain : Text, selector : Text, private_key : Text }\n' +
    '   } : Config';

  function setStatus(text, isError) {
    statusEl.textContent = text;
    statusEl.classList.toggle('error', !!isError);
  }

  function allocUTF8(s) {
    var bytes = Module.lengthBytesUTF8(s);
    var p = Module._malloc(bytes + 1);
    Module.stringToUTF8(s, p, bytes + 1);
    return p;
  }

  function loadConfig() {
    var src = editor.getValue();
    var p = allocUTF8(src);
    var rc = Module._visage_load(p);
    Module._free(p);
    if (rc !== 0) {
      setStatus('config error: ' + Module.UTF8ToString(Module._visage_err()), true);
      summaryEl.innerHTML = '<div class="ans-empty">config did not load</div>';
      return false;
    }
    var summary = JSON.parse(Module.UTF8ToString(Module._visage_json(), Module._visage_json_len()));
    renderSummary(summary);
    setStatus('loaded: ' + summary.hostname + ' · ' + summary.domains.length + ' domain(s) · ' + summary.naliases + ' alias(es)');
    return true;
  }

  function renderSummary(s) {
    summaryEl.innerHTML = '';
    var line = function (text) {
      var d = document.createElement('div');
      d.className = 'sum-line';
      d.textContent = text;
      summaryEl.appendChild(d);
    };
    line('hostname: ' + s.hostname + ' · listen ' + s.listen);
    line('domains: ' + s.domains.join(', '));
    line('catch_all: ' + (s.catch_all ? s.catch_all : '(disabled)'));
    s.aliases.forEach(function (a) {
      var row = document.createElement('div');
      row.className = 'alias-row';
      var n = document.createElement('span'); n.className = 'alias-name'; n.textContent = a.alias;
      var d = document.createElement('span'); d.className = 'alias-dests'; d.textContent = '→ ' + a.destinations.join(', ');
      row.appendChild(n); row.appendChild(d);
      summaryEl.appendChild(row);
    });
  }

  function renderResult(j) {
    resultEl.innerHTML = '';
    var badge = document.createElement('div');
    badge.className = 'decide ' + (j.decision === 'accept' ? 'accept' : 'reject');
    badge.textContent = j.decision === 'accept' ? 'ACCEPT' : 'REJECT';
    resultEl.appendChild(badge);
    var route = document.createElement('div');
    route.className = 'route';
    route.textContent = j.route ? ('via ' + j.route) : (j.reason || '');
    resultEl.appendChild(route);
    j.destinations.forEach(function (dst) {
      var row = document.createElement('div');
      row.className = 'dest-row';
      row.textContent = dst;
      resultEl.appendChild(row);
    });
    if (!j.destinations.length) {
      var empty = document.createElement('div');
      empty.className = 'ans-empty';
      empty.textContent = 'no destinations';
      resultEl.appendChild(empty);
    }
  }

  function doResolve() {
    if (!Module) { setStatus('WASM still loading…', true); return; }
    if (!loadConfig()) return;
    var addr = addrEl.value.trim();
    if (!addr) { setStatus('type an alias@domain to resolve', true); return; }
    var p = allocUTF8(addr);
    var rc = Module._visage_resolve(p);
    Module._free(p);
    if (rc !== 0) { setStatus(Module.UTF8ToString(Module._visage_err()), true); return; }
    var json = JSON.parse(Module.UTF8ToString(Module._visage_json(), Module._visage_json_len()));
    renderResult(json);
    setStatus(json.decision === 'accept' ? ('✓ accepted via ' + json.route) : ('✕ rejected: ' + (json.reason || 'unknown')));
  }

  runBtn.addEventListener('click', doResolve);
  addrEl.addEventListener('keydown', function (e) { if (e.key === 'Enter') doResolve(); });
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); doResolve(); }
  });

  editor.setValue(DEFAULT_SRC);
  setStatus('loading WASM…');
  createVisage()
    .then(function (M) {
      Module = M;
      setStatus('WASM ready');
      doResolve();
    })
    .catch(function (e) {
      setStatus('WASM failed to load: ' + e.message, true);
    });
})();
