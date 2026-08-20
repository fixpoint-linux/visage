/* visage admin — vanilla JS, no framework, no CDN.
 *
 * The admin token is entered once on the login gate, stored client-side
 * (sessionStorage), and sent as `Authorization: Bearer` on every API call.
 * Every data route below requires that token; the static shell (this page)
 * is served without auth because it contains no data.
 *
 * All data rendered into the DOM is escaped (esc()) to prevent stored XSS —
 * aliases and log lines may contain arbitrary user-supplied strings.
 */
(function () {
  'use strict';

  var TOKEN_KEY = 'visage_admin_token';

  var $ = function (id) { return document.getElementById(id); };
  var loginEl = $('login'), appEl = $('app');

  /* --- helpers -------------------------------------------------------- */

  // Escape a value for safe insertion into HTML (never trust the data).
  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function token() { return sessionStorage.getItem(TOKEN_KEY) || ''; }

  function setError(el, msg) {
    el.textContent = msg || '';
    el.hidden = !msg;
  }

  function setOk(el, msg) {
    el.textContent = msg || '';
    el.hidden = !msg;
  }

  /* api(path, opts): fetch with the bearer token; resolves to the parsed
     JSON body on 2xx, else rejects with an Error carrying the status + a
     server-provided {"error": ...} message when present. */
  function api(path, opts) {
    opts = opts || {};
    var headers = opts.headers || {};
    var t = token();
    if (t) headers['Authorization'] = 'Bearer ' + t;
    var init = { method: opts.method || 'GET', headers: headers };
    if (opts.body != null) init.body = JSON.stringify(opts.body);
    return fetch(path, init).then(function (resp) {
      return resp.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { /* non-JSON */ }
        if (!resp.ok) {
          var detail = (data && data.error) ? data.error : ('HTTP ' + resp.status);
          var err = new Error(detail);
          err.status = resp.status;
          throw err;
        }
        return data;
      });
    });
  }

  /* --- auth ----------------------------------------------------------- */

  function showApp() {
    loginEl.hidden = true;
    appEl.hidden = false;
    loadDashboard();
  }

  function showLogin(msg) {
    appEl.hidden = true;
    loginEl.hidden = false;
    if (msg) setError($('login-error'), msg);
  }

  function login() {
    var t = $('token').value.trim();
    if (!t) { setError($('login-error'), 'Enter the admin token.'); return; }
    setError($('login-error'), '');
    // Verify the token with a light authed probe before unlocking the app.
    api('/status').then(function (st) {
      sessionStorage.setItem(TOKEN_KEY, t);
      $('status-host').textContent = (st && st.hostname) ? st.hostname : '';
      showApp();
    }).catch(function (err) {
      setError($('login-error'), 'Invalid token: ' + err.message);
    });
  }

  function logout() {
    sessionStorage.removeItem(TOKEN_KEY);
    $('token').value = '';
    showLogin(null);
  }

  /* --- dashboard ------------------------------------------------------ */

  function renderStatus(st) {
    var q = st.queue || {};
    $('st-host').textContent = esc(st.hostname);
    $('st-domains').textContent = esc((st.domains || []).join(', '));
    $('st-listen').textContent = esc((st.listen && st.listen.address) || '') +
      ':' + esc(st.listen ? st.listen.port : '');
    $('st-http').textContent = esc((st.http && st.http.address) || '') +
      ':' + esc(st.http ? st.http.port : '');
    $('st-relay').textContent = esc((st.relay && st.relay.host) || '') +
      ':' + esc(st.relay ? st.relay.port : '') +
      ((st.relay && st.relay.tls) ? ' (' + esc(st.relay.tls) + ')' : '');
    $('st-aliases').textContent = esc(st.alias_count);

    var html = '';
    var entries = [
      ['queued', q.queued], ['delivering', q.delivering],
      ['delivered', q.delivered], ['permfail', q.permfail]
    ];
    entries.forEach(function (e, i) {
      html += '<div class="card"><div class="label">' + esc(e[0]) +
        '</div><div class="value">' + esc(e[1]) + '</div></div>';
    });
    $('st-queue').innerHTML = html;
  }

  function loadDashboard() {
    setError($('dash-error'), '');
    api('/status').then(function (st) {
      $('status-host').textContent = st.hostname ? esc(st.hostname) : '';
      renderStatus(st);
    }).catch(function (err) {
      if (err.status === 401) { showLogin('Session expired — re-enter the token.'); }
      else setError($('dash-error'), 'Failed to load status: ' + err.message);
    });
  }

  /* --- aliases -------------------------------------------------------- */

  function renderAliases(list) {
    var host = $('aliases');
    host.innerHTML = '';
    if (!list || !list.length) {
      var none = document.createElement('p');
      none.className = 'muted';
      none.textContent = 'No aliases yet.';
      host.appendChild(none);
      return;
    }
    // Group destinations by alias, preserving first-seen order.
    var groups = {};
    var order = [];
    list.forEach(function (pair) {
      if (!(pair.alias in groups)) { groups[pair.alias] = []; order.push(pair.alias); }
      groups[pair.alias].push(pair.destination);
    });
    order.forEach(function (alias) {
      var block = document.createElement('div');
      block.className = 'alias-block';

      var head = document.createElement('div');
      head.className = 'alias-head';
      var name = document.createElement('span');
      name.className = 'alias-name';
      name.textContent = alias;                    // textContent: safe
      head.appendChild(name);
      block.appendChild(head);

      groups[alias].forEach(function (dest) {
        var row = document.createElement('div');
        row.className = 'alias-row';

        var addr = document.createElement('span');
        addr.textContent = dest;                   // textContent: safe
        row.appendChild(addr);

        var del = document.createElement('button');
        del.type = 'button';
        del.className = 'link danger';
        del.textContent = 'delete';
        del.addEventListener('click', function () { deleteAlias(alias, dest); });
        row.appendChild(del);

        block.appendChild(row);
      });

      host.appendChild(block);
    });
  }

  function loadAliases() {
    setError($('alias-error'), '');
    setOk($('alias-msg'), '');
    api('/aliases').then(function (data) {
      renderAliases(data ? data.aliases : []);
    }).catch(function (err) {
      if (err.status === 401) { showLogin('Session expired — re-enter the token.'); }
      else setError($('alias-error'), 'Failed to load aliases: ' + err.message);
    });
  }

  function addAlias(alias, dest) {
    setError($('alias-error'), '');
    setOk($('alias-msg'), '');
    return api('/alias', { method: 'POST', body: { alias: alias, destination: dest } })
      .then(function () { loadAliases(); })
      .catch(function (err) {
        if (err.status === 401) { showLogin('Session expired — re-enter the token.'); }
        else setError($('alias-error'), 'Add failed: ' + err.message);
      });
  }

  function deleteAlias(alias, dest) {
    setError($('alias-error'), '');
    setOk($('alias-msg'), '');
    api('/alias', { method: 'DELETE', body: { alias: alias, destination: dest } })
      .then(function () { loadAliases(); })
      .catch(function (err) {
        if (err.status === 401) { showLogin('Session expired — re-enter the token.'); }
        else setError($('alias-error'), 'Delete failed: ' + err.message);
      });
  }

  /* --- log ------------------------------------------------------------ */

  function loadLog(n) {
    setError($('log-error'), '');
    var tbody = $('log-table').querySelector('tbody');
    tbody.innerHTML = '';
    api('/log?n=' + encodeURIComponent(n)).then(function (entries) {
      $('log-empty').hidden = !(entries && entries.length);
      $('log-table').style.display = (entries && entries.length) ? '' : 'none';
      (entries || []).forEach(function (e) {
        var tr = document.createElement('tr');
        [e.msgid, e.ts, e.dir, e.local, e.remote, e.status].forEach(function (v) {
          var td = document.createElement('td');
          td.textContent = v == null ? '' : v;     // textContent: safe
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
    }).catch(function (err) {
      if (err.status === 401) { showLogin('Session expired — re-enter the token.'); }
      else setError($('log-error'), 'Failed to load log: ' + err.message);
    });
  }

  /* --- replay --------------------------------------------------------- */

  function replay(msgid) {
    setError($('replay-error'), '');
    setOk($('replay-msg'), '');
    api('/replay', { method: 'POST', body: { msgid: msgid } })
      .then(function (data) {
        var k = (data && data.replayed != null) ? data.replayed : '?';
        setOk($('replay-msg'), 'Replayed ' + k + ' delivery(ies) for msgid ' + msgid + '.');
      })
      .catch(function (err) {
        if (err.status === 401) { showLogin('Session expired — re-enter the token.'); }
        else setError($('replay-error'), 'Replay failed: ' + err.message);
      });
  }

  /* --- tab switching -------------------------------------------------- */

  function activateTab(name) {
    var tabs = document.querySelectorAll('.tabs button');
    for (var i = 0; i < tabs.length; i++) {
      var t = tabs[i];
      var active = t.getAttribute('data-tab') === name;
      t.classList.toggle('active', active);
    }
    var sections = document.querySelectorAll('.tab');
    for (var j = 0; j < sections.length; j++) {
      sections[j].classList.toggle('active', sections[j].id === 'tab-' + name);
    }
    if (name === 'aliases') loadAliases();
    if (name === 'log') loadLog(parseInt($('log-n').value, 10) || 100);
  }

  /* --- wire up -------------------------------------------------------- */

  document.addEventListener('DOMContentLoaded', function () {
    $('login-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      login();
    });
    $('logout').addEventListener('click', logout);

    document.querySelectorAll('.tabs button').forEach(function (btn) {
      btn.addEventListener('click', function () { activateTab(btn.getAttribute('data-tab')); });
    });

    $('alias-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      addAlias($('alias-input').value.trim(), $('dest-input').value.trim());
      ev.target.reset();
    });

    $('log-refresh').addEventListener('click', function () {
      loadLog(parseInt($('log-n').value, 10) || 100);
    });

    $('replay-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      replay(parseInt($('replay-msgid').value, 10));
      ev.target.reset();
    });

    // Auto-unlock if a token is already stored.
    if (token()) {
      api('/status').then(showApp).catch(function () {
        sessionStorage.removeItem(TOKEN_KEY);
        showLogin(null);
      });
    } else {
      showLogin(null);
    }
  });
})();
