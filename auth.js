/* Account layer for PYQ Predictor: username+email+password sign-up, sign-in by username or email,
   forgot-password via email OTP. Works with the local Python server (config.js: apiBase)
   or Supabase (config.js: supabaseUrl + supabaseAnonKey). With empty config it does nothing
   and the app runs in guest mode. */
(function () {
  var cfg = window.PYQ_CONFIG || {};
  var useLocal = !!cfg.apiBase, useSb = !!(cfg.supabaseUrl && cfg.supabaseAnonKey);
  if (!useLocal && !useSb) return;

  var style = document.createElement('style');
  style.textContent =
    '.ag{position:fixed;inset:0;z-index:50;display:flex;align-items:center;justify-content:center;padding:16px;overflow:auto;background:radial-gradient(70% 40% at 15% 0,#ffffff,transparent 70%),linear-gradient(170deg,#f6fbf9,#cfe6dd)}' +
    '@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .ag{background:radial-gradient(70% 40% at 15% 0,#0f3a31,transparent 70%),linear-gradient(170deg,#0b1f1b,#050c0a)}}' +
    '.ag form{width:100%;max-width:420px;display:flex;flex-direction:column;gap:14px;padding:24px;border:1px solid var(--line);border-radius:18px;background:linear-gradient(45deg,rgba(196,226,216,.6),rgba(244,251,248,.8));box-shadow:0 8px 24px rgba(10,60,48,.16);-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px)}' +
    '@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .ag form{background:linear-gradient(45deg,rgba(255,255,255,.05),rgba(255,255,255,.12))}}' +
    '.ag h1{font-size:1.45rem;margin:0}.ag p{margin:0}' +
    '.ag .lbl{display:flex;flex-direction:column;gap:4px;font-size:.85rem;font-weight:600;color:var(--muted)}' +
    '.ag .hint{font-size:.78rem;color:var(--muted);margin-top:-4px;font-weight:400}' +
    '.ag input{font:inherit;font-size:1rem;min-height:46px;padding:9px 12px;color:var(--fg);width:100%}' +
    '.ag .otp{letter-spacing:.35em;text-align:center;font-family:var(--mono);font-size:1.3rem}' +
    '.ag .err{color:var(--bad,#a82c16);font-size:.9rem;min-height:1.2em}.ag .ok{color:var(--good,#17703f);font-size:.9rem}' +
    '.ag .lnk{background:none;border:0;padding:6px 0;color:var(--accent);font:inherit;font-weight:600;text-align:left;cursor:pointer;text-decoration:underline;min-height:36px}' +
    '.ag .row2{display:flex;gap:12px;flex-wrap:wrap;justify-content:space-between}' +
    '.acct{font-size:.75rem;padding:4px 10px;min-height:30px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;position:absolute;left:max(8px,env(safe-area-inset-left,0px));top:50%;transform:translateY(-50%);z-index:20}';
  document.head.appendChild(style);

  function el(tag, attrs) {
    var e = document.createElement(tag);
    for (var k in (attrs || {})) { if (k === 'text') e.textContent = attrs[k]; else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), attrs[k]); else e.setAttribute(k, attrs[k]); }
    for (var i = 2; i < arguments.length; i++) { var c = arguments[i]; if (c) e.append(c.nodeType ? c : document.createTextNode(c)); }
    return e;
  }

  var session = null, gate = null, acct = null, pending = [], api = null;

  /* -------- backends -------- */
  function fail(e) { return { error: e }; }

  function makeLocal(base) {
    function call(method, path, body) {
      return fetch(base + path, { method: method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-PYQ': '1' }, body: body ? JSON.stringify(body) : undefined })
        .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { if (!r.ok) j.error = j.error || { message: 'Request failed', status: r.status }; else delete j.error; if (!r.ok && typeof j.error === 'string') j.error = { message: j.error, status: r.status }; return j; }); })
        .catch(function () { return fail({ message: 'network failed' }); });
    }
    return {
      init:        function ()             { return call('GET',    '/me').then(function (j) { return j.error ? null : j.user; }); },
      register:    function (un, em, pw)   { return call('POST',   '/register',  { username: un, email: em, password: pw }); },
      sendCode:    function (email)        { return call('POST',   '/otp/send',  { email: email }); },
      verify:      function (email, code)  { return call('POST',   '/otp/verify',{ email: email, code: code }); },
      setPassword: function (pw)           { return call('POST',   '/password',  { password: pw }); },
      signIn:      function (login, pw)    { return call('POST',   '/signin',    { login: login, password: pw }); },
      signOut:     function ()             { return call('POST',   '/signout'); },
      list:        function ()             { return call('GET',    '/attempts').then(function (j) { return j.error ? null : j.rows; }); },
      save:        function (rows)         { return call('POST',   '/attempts',  { rows: rows }); },
      clear:       function ()             { return call('DELETE', '/attempts'); },
      onSignedOut: function () {}
    };
  }

  function makeSb(url, key, ready) {
    var sb, uid = null, cb = function () {};
    function wrap(p) { return p.then(function (r) { return r.error ? fail(r.error) : r; }); }
    function user(sess) { return sess && sess.user ? { id: sess.user.id, email: sess.user.email, username: sess.user.user_metadata && (sess.user.user_metadata.username || ''), name: sess.user.user_metadata && (sess.user.user_metadata.username || sess.user.user_metadata.display_name || '') } : null; }
    return {
      init: function () {
        return ready.then(function () {
          sb = window.supabase.createClient(url, key, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true } });
          sb.auth.onAuthStateChange(function (ev) { if (ev === 'SIGNED_OUT') cb(); });
          return sb.auth.getSession().then(function (r) {
            if (r.data && r.data.session && (location.hash.includes('type=recovery') || location.hash.includes('type=signup'))) {
              session = user(r.data.session); S.screen = 'password'; uid = r.data.session.user.id;
            }
            var u = user(r.data && r.data.session); uid = u && u.id; return u;
          });
        });
      },
      register: function (username, email, password) {
        return wrap(sb.auth.signUp({ email: email, password: password, options: { data: { username: username, display_name: username } } }))
          .then(function (r) {
            if (r.error) return r;
            if (!r.data.session) return { needsConfirm: true, email: email };
            uid = r.data.session.user.id;
            return { user: user(r.data.session) };
          });
      },
      sendCode: function (email) { return wrap(sb.auth.resetPasswordForEmail(email, { redirectTo: location.href })); },
      verify: function () { return Promise.resolve(fail({ message: 'Click the link in your email to reset your password.' })); },
      setPassword: function (pw) {
        return wrap(sb.auth.updateUser({ password: pw })).then(function (r) {
          if (r.error) return r; uid = r.data.user.id; return { user: user({ user: r.data.user }) };
        });
      },
      signIn: function (login, pw) {
        if (login.indexOf('@') < 0) return Promise.resolve(fail({ message: 'Please enter your email address to sign in (username login is only available on the local server).' }));
        return wrap(sb.auth.signInWithPassword({ email: login, password: pw })).then(function (r) {
          if (r.error) return r; uid = r.data.session.user.id; return { user: user(r.data.session) };
        });
      },
      signOut:     function ()     { return sb.auth.signOut(); },
      list:        function ()     { return sb.from('attempts').select('qid,tp,u,sel,ok,ts').order('ts', { ascending: true }).limit(10000).then(function (r) { return r.error ? null : r.data; }); },
      save:        function (rows) { return sb.from('attempts').upsert(rows, { onConflict: 'user_id,qid,ts', ignoreDuplicates: true }).then(function (r) { return r.error ? fail(r.error) : {}; }); },
      clear:       function ()     { return sb.from('attempts').delete().eq('user_id', uid).then(function () { return {}; }); },
      onSignedOut: function (f)    { cb = f; }
    };
  }

  function msg(err) {
    var m = (err && (err.message || err.error_description)) || '';
    if (/invalid login|invalid credentials/i.test(m) || err && err.status === 400 && /signin|password/i.test(m)) return 'Username/email or password is incorrect.';
    if (/rate limit|too many|wait/i.test(m) || (err && err.status === 429)) return 'Too many tries. Please wait a minute and try again.';
    if (/username.*taken|taken.*username/i.test(m)) return 'That username is already taken. Please choose another.';
    if (/email.*exist|already.*register|already.*account/i.test(m)) return 'An account with that email already exists. Sign in instead.';
    if (/token|otp|expired|invalid/i.test(m)) return 'That code is wrong or has expired. Check it or ask for a new one.';
    if (/no account found/i.test(m)) return 'No account found for that email address.';
    if (/network|fetch|failed/i.test(m)) return 'No connection. Check your internet and try again.';
    return m || 'Something went wrong. Please try again.';
  }

  /* -------- screens -------- */
  var S = { screen: 'signin', email: '', username: '', cool: 0, note: '' };
  var timer;

  function field(label, input, hint) {
    var l = el('label', { 'class': 'lbl' }, label, input);
    if (hint) l.appendChild(el('span', { 'class': 'hint', text: hint }));
    return l;
  }
  function inp(type, name, extra) { return el('input', Object.assign({ type: type, name: name, required: '' }, extra || {})); }
  function pwField(label, name, auto) {
    var i = inp('password', name, { minlength: '8', autocomplete: auto });
    var show = el('button', { type: 'button', 'class': 'lnk', text: 'Show password', onclick: function () { var on = i.type === 'password'; i.type = on ? 'text' : 'password'; show.textContent = on ? 'Hide password' : 'Show password'; } });
    return [field(label, i), show, i];
  }

  function draw() {
    if (!gate) { gate = el('div', { 'class': 'ag', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Sign in' }); document.body.appendChild(gate); }
    var f = el('form', { novalidate: '' }), err = el('p', { 'class': 'err', role: 'alert' }), busy = false;
    var btn = el('button', { 'class': 'btn', type: 'submit' });
    function submit(fn) {
      f.addEventListener('submit', function (e) {
        e.preventDefault(); if (busy) return;
        if (!f.checkValidity()) { f.reportValidity(); return; }
        busy = true; err.textContent = ''; btn.disabled = true;
        new Promise(function (res) { res(fn()); }).catch(function (x) { err.textContent = msg(x); }).then(function () { busy = false; btn.disabled = false; });
      });
    }
    var go = function (screen, extra) { return function () { Object.assign(S, { screen: screen, note: '' }, extra || {}); draw(); }; };
    var kids;

    /* ── Sign in ── */
    if (S.screen === 'signin') {
      var loginInp = inp('text', 'login', { autocomplete: 'username email', placeholder: 'e.g. student42 or you@email.com' });
      loginInp.value = S.username || S.email;
      var pw = pwField('Password', 'password', 'current-password');
      btn.textContent = 'Sign in';
      kids = [
        el('h1', { text: 'Sign in' }),
        el('p', { 'class': 'muted', text: 'Enter your username or email address.' }),
        field('Username or Email', loginInp),
        pw[0], pw[1],
        el('div', { 'class': 'row2' },
          el('button', { type: 'button', 'class': 'lnk', text: 'Forgot password?', onclick: go('forgot') }),
          el('button', { type: 'button', 'class': 'lnk', text: 'Create an account', onclick: go('signup') })
        ),
        S.note ? el('p', { 'class': 'ok', text: S.note }) : null,
        err, btn
      ];
      submit(function () {
        var login = loginInp.value.trim();
        if (login.indexOf('@') >= 0) S.email = login.toLowerCase(); else S.username = login;
        return api.signIn(login, pw[2].value).then(function (r) { if (r.error) throw r.error; session = r.user; enter(); });
      });

    /* ── Sign up ── */
    } else if (S.screen === 'signup') {
      var unInp = inp('text', 'username', { autocomplete: 'username', minlength: '3', maxlength: '20', pattern: '[A-Za-z0-9]+', title: 'Letters and numbers only, 3–20 characters' });
      unInp.value = S.username;
      var emInp = inp('email', 'email', { autocomplete: 'email', inputmode: 'email' });
      emInp.value = S.email;
      var p1 = pwField('Create password (min. 8 characters)', 'password', 'new-password');
      var p2i = inp('password', 'password2', { minlength: '8', autocomplete: 'new-password' });
      btn.textContent = 'Create account';
      kids = [
        el('h1', { text: 'Create your account' }),
        field('Username', unInp, 'Letters and numbers only, 3–20 characters. This is your login name.'),
        field('Email address', emInp),
        p1[0], p1[1],
        field('Verify password', p2i),
        el('button', { type: 'button', 'class': 'lnk', text: 'Already have an account? Sign in', onclick: go('signin') }),
        err, btn
      ];
      submit(function () {
        var username = unInp.value.trim();
        var email    = emInp.value.trim().toLowerCase();
        if (!/^[A-Za-z0-9]{3,20}$/.test(username)) { err.textContent = 'Username must be 3–20 letters and numbers only (no spaces or symbols).'; return; }
        if (p1[2].value !== p2i.value) { err.textContent = 'The two passwords do not match.'; return; }
        S.username = username; S.email = email;
        return api.register(username, email, p1[2].value).then(function (r) {
          if (r.error) throw r.error;
          if (r.needsConfirm) { S.screen = 'confirm'; S.note = 'We sent a confirmation link to ' + r.email + '. Check your email (and spam) then come back to sign in.'; draw(); return; }
          session = r.user; enter();
        });
      });

    /* ── Awaiting email confirmation (Supabase only) ── */
    } else if (S.screen === 'confirm') {
      kids = [
        el('h1', { text: 'Check your email' }),
        el('p', { text: S.note }),
        el('button', { type: 'button', 'class': 'btn', text: 'Back to sign in', onclick: go('signin', { note: 'Confirm your email first, then sign in here.' }) })
      ];

    /* ── Forgot password — enter email ── */
    } else if (S.screen === 'forgot') {
      var forgotEm = inp('email', 'email', { autocomplete: 'email', inputmode: 'email' });
      forgotEm.value = S.email;
      btn.textContent = 'Send reset code';
      kids = [
        el('h1', { text: 'Reset your password' }),
        el('p', { 'class': 'muted', text: 'We will email you a 6-digit code to confirm it is you.' }),
        field('Email address', forgotEm),
        el('button', { type: 'button', 'class': 'lnk', text: 'Back to sign in', onclick: go('signin') }),
        err, btn
      ];
      submit(function () {
        S.email = forgotEm.value.trim().toLowerCase();
        return api.sendCode(S.email).then(function (r) { if (r.error) throw r.error; startCool(); S.screen = 'code'; draw(); });
      });

    /* ── Enter OTP code ── */
    } else if (S.screen === 'code') {
      var code = inp('text', 'code', { inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9]{6,8}', maxlength: '8', 'class': 'otp', 'aria-label': 'Code from your email' });
      btn.textContent = 'Verify';
      var resend = el('button', { type: 'button', 'data-resend': '', 'class': 'lnk', text: S.cool > 0 ? 'Resend code in ' + S.cool + 's' : 'Send a new code',
        onclick: function () {
          if (S.cool > 0) return; err.textContent = '';
          api.sendCode(S.email).then(function (r) { if (r.error) err.textContent = msg(r.error); else { startCool(); draw(); } });
        }
      });
      if (S.cool > 0) resend.setAttribute('aria-disabled', 'true');
      kids = [
        el('h1', { text: 'Check your email' }),
        el('p', { 'class': 'muted', text: 'We sent a 6-digit code to ' + S.email + '. It expires in 10 minutes. Check spam too.' }),
        field('Code', code),
        resend,
        el('button', { type: 'button', 'class': 'lnk', text: 'Use a different email', onclick: go('forgot') }),
        err, btn
      ];
      submit(function () {
        return api.verify(S.email, code.value.trim()).then(function (r) { if (r.error) throw r.error; session = r.user; S.screen = 'password'; draw(); });
      });

    /* ── Choose new password ── */
    } else if (S.screen === 'password') {
      var np1 = pwField('New password (min. 8 characters)', 'newpw', 'new-password');
      var np2i = inp('password', 'newpw2', { minlength: '8', autocomplete: 'new-password' });
      btn.textContent = 'Save password';
      kids = [
        el('h1', { text: 'Choose a new password' }),
        el('p', { 'class': 'muted', text: 'You will use it with your username or email next time.' }),
        np1[0], np1[1],
        field('Verify new password', np2i),
        err, btn
      ];
      submit(function () {
        if (np1[2].value !== np2i.value) throw { message: 'The two passwords do not match.' };
        return api.setPassword(np1[2].value).then(function (r) {
          if (r.error) throw r.error; session = r.user || session;
          S.screen = 'signin'; S.note = 'Password updated. Sign in with your new password.'; draw();
        });
      });
    }

    f.replaceChildren.apply(f, kids.filter(Boolean).concat([]));
    gate.replaceChildren(f);
    var first = f.querySelector('input'); if (first && S.screen !== 'signin') first.focus();
  }

  function startCool() {
    S.cool = 30; clearInterval(timer);
    timer = setInterval(function () {
      S.cool--; if (S.cool <= 0) clearInterval(timer);
      var b = gate && gate.querySelector('[data-resend]'); if (!b) return;
      b.textContent = S.cool > 0 ? 'Resend code in ' + S.cool + 's' : 'Send a new code';
      if (S.cool > 0) b.setAttribute('aria-disabled', 'true'); else b.removeAttribute('aria-disabled');
    }, 1000);
  }

  function hideGate() { if (gate) { gate.remove(); gate = null; } }
  function showAccount() {
    if (acct) acct.remove();
    var label = session && (session.username || session.name || session.email) || 'Account';
    acct = el('button', { 'class': 'btn ghost small acct', type: 'button', title: 'Sign out as ' + label,
      onclick: function () { if (confirm('Sign out of ' + label + '?')) api.signOut().then(function () { leave('You are signed out.'); }); }
    }, label + ' · Sign out');
    var nav = document.querySelector('nav.tabs');
    if (nav) { nav.style.position = 'relative'; nav.appendChild(acct); }
    else document.body.appendChild(acct);
  }

  /* -------- answer sync -------- */
  function row(a) { return { qid: a.id, tp: a.tp, u: a.u, sel: a.sel, ok: a.ok, ts: a.ts }; }
  function sync() {
    var app = window.PYQ_APP; if (!app || !session) return Promise.resolve();
    return api.list().then(function (data) {
      if (!data) return;
      var have = {}, merged = [];
      data.forEach(function (x) { have[x.qid + '|' + x.ts] = 1; merged.push({ id: x.qid, tp: x.tp, u: x.u, sel: x.sel, ok: x.ok, ts: Number(x.ts) }); });
      var up = [];
      app.get().forEach(function (a) { if (a.sample) return; var k = a.id + '|' + a.ts; if (!have[k]) { merged.push(a); up.push(row(a)); } });
      merged.sort(function (a, b) { return a.ts - b.ts; });
      app.set(merged);
      if (up.length) return api.save(up);
    });
  }
  window.PYQ_HOOK = {
    attempt: function (a) { if (!a || a.sample || !session) return; api.save([row(a)]).then(function (r) { if (r && r.error) pending.push(a); }); },
    reset:   function ()  { if (session) api.clear(); }
  };
  window.addEventListener('online', function () { if (pending.length && session) api.save(pending.splice(0).map(row)); });

  /* -------- start -------- */
  function enter() { hideGate(); showAccount(); sync(); }
  function leave(note) {
    session = null; if (acct) { acct.remove(); acct = null; }
    var app = window.PYQ_APP; if (app) app.set([]);
    S.screen = 'signin'; S.note = note || ''; draw();
  }
  function boot(a) {
    api = a;
    api.onSignedOut(function () { leave('You are signed out.'); });
    api.init().then(function (u) {
      session = u;
      if (u && S.screen === 'password') { draw(); }   // recovery redirect
      else if (u) { enter(); }
      else { leave(''); }
    });
  }
  /* keep the app behind the gate until auth state is known */
  gate = el('div', { 'class': 'ag', 'aria-busy': 'true' }, el('p', { 'class': 'muted', text: 'Loading…' }));
  document.body.appendChild(gate);
  if (useLocal) boot(makeLocal(cfg.apiBase));
  else {
    var ready = new Promise(function (res, rej) {
      var sc = document.createElement('script'); sc.src = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2'; sc.onload = res;
      sc.onerror = function () { gate.replaceChildren(el('p', { text: 'Could not load sign-in. Check your internet and reload.' })); rej(); };
      document.head.appendChild(sc);
    });
    boot(makeSb(cfg.supabaseUrl, cfg.supabaseAnonKey, ready));
  }
})();
