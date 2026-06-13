/* ════════════════════════════════════════════════════════════
   firebase.js — connessione condivisa + login (REST, niente SDK)
   Incluso da profili.html, index.html, piano_settimanale.html e login.html.
   Le pagine protette, se non sei loggato, rimandano a login.html.
════════════════════════════════════════════════════════════ */
var firebaseConfig = {
  apiKey: "AIzaSyBrPK0iixlBVnKNstrzbhsAREzhW2OfoAQ",
  authDomain: "pianosettimanaledb.firebaseapp.com",
  databaseURL: "https://pianosettimanaledb-default-rtdb.europe-west1.firebasedatabase.app",
  projectId: "pianosettimanaledb",
  storageBucket: "pianosettimanaledb.firebasestorage.app",
  messagingSenderId: "479375847867",
  appId: "1:479375847867:web:4178c4657379b17343d49e"
};

var API_KEY = firebaseConfig.apiKey;
var DB_URL  = (firebaseConfig.databaseURL || '').replace(/\/+$/, '');
var db      = (DB_URL && DB_URL.indexOf('il-tuo-progetto') === -1) ? DB_URL : null;

/* ─── Sessione (salvata nel browser) ─────────────────────── */
function _ls(k)        { try { return localStorage.getItem(k); } catch (e) { return null; } }
function _lsSet(k, v)  { try { localStorage.setItem(k, v); } catch (e) {} }
function _lsDel(k)     { try { localStorage.removeItem(k); } catch (e) {} }

function fbHasSession() { return !!_ls('fb_refreshToken'); }
function fbEmail()      { return _ls('fb_email') || ''; }

function _saveAuth(idToken, refreshToken, expiresIn) {
  _lsSet('fb_idToken', idToken);
  _lsSet('fb_refreshToken', refreshToken);
  _lsSet('fb_tokenExp', String(Date.now() + ((parseInt(expiresIn, 10) || 3600) * 1000) - 60000));
}
function fbClearSession() {
  _lsDel('fb_idToken'); _lsDel('fb_refreshToken'); _lsDel('fb_tokenExp');
}
function fbSignOut() { fbClearSession(); location.replace('login.html'); }

/* ─── Login / rinnovo token ──────────────────────────────── */
function fbSignIn(email, password) {
  return fetch('https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=' + API_KEY, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email, password: password, returnSecureToken: true })
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.error) throw new Error(d.error.message || 'LOGIN_FALLITO');
    _lsSet('fb_email', email);
    _saveAuth(d.idToken, d.refreshToken, d.expiresIn);
    return d;
  });
}

function _refreshToken() {
  var rt = _ls('fb_refreshToken');
  if (!rt) return Promise.reject(new Error('NO_SESSION'));
  return fetch('https://securetoken.googleapis.com/v1/token?key=' + API_KEY, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=refresh_token&refresh_token=' + encodeURIComponent(rt)
  }).then(function (r) { return r.json(); }).then(function (d) {
    if (d.error || !d.id_token) throw new Error('REFRESH_FALLITO');
    _saveAuth(d.id_token, d.refresh_token, d.expires_in);
    return d.id_token;
  });
}

/* token valido (rinnovato se scaduto) */
function _validToken() {
  var tok = _ls('fb_idToken'), exp = +(_ls('fb_tokenExp') || 0);
  if (tok && Date.now() < exp) return Promise.resolve(tok);
  return _refreshToken();
}

function _redirectLogin() {
  if (window.FB_LOGIN_PAGE) return;              // non rimbalzare la pagina di login
  var here = location.pathname.split('/').pop() + location.search;
  location.replace('login.html?next=' + encodeURIComponent(here || 'profili.html'));
}

/* ─── Helper DB con autenticazione ───────────────────────── */
function _authedFetch(path, opts, _retried) {
  return _validToken().then(function (tok) {
    var url = DB_URL + '/' + path + '.json?auth=' + tok;
    return fetch(url, opts || {}).then(function (res) {
      if (res.status === 401 && !_retried) {
        // token forse scaduto: rinnova e riprova UNA sola volta
        return _refreshToken().then(
          function () { return _authedFetch(path, opts, true); },
          function () { _redirectLogin(); throw new Error('Sessione scaduta'); }
        );
      }
      if (res.status === 401 || res.status === 403) {
        // sei loggato ma le REGOLE negano l'accesso: non tornare al login (eviti il loop)
        throw new Error('Permesso negato dalle Regole del database (HTTP ' + res.status +
          '). Controlla che le Regole del Realtime Database consentano questo account.');
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res;
    });
  }, function () {
    // nessun token o rinnovo fallito → davvero non autenticato
    _redirectLogin();
    throw new Error('Non autenticato');
  });
}

function dbGet(path) {
  return _authedFetch(path, {}).then(function (res) { return res.json(); });
}
function dbSet(path, value) {
  return _authedFetch(path, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value)
  }).then(function (res) { return res.json(); });
}
function dbDelete(path) {
  return _authedFetch(path, { method: 'DELETE' }).then(function () { return true; });
}

/* ─── Gate: le pagine protette richiedono il login ───────── */
if (!window.FB_LOGIN_PAGE && !fbHasSession()) {
  _redirectLogin();
}
