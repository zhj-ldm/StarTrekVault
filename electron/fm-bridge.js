'use strict';
/* ============================================================================
   STAR TREK VAULT - fm-bridge.js

   Main-world shim injected into renderer/fm.html. That page is the user's own
   LCARSDE file manager and is kept byte-for-byte: it talks to a PHP endpoint
   through XMLHttpRequest (`?action=...`) and gates access with a demo password.

   This shim leaves the page's HTML/CSS/JS untouched and only re-points it:

     XMLHttpRequest  ->  window.stvault.invoke  ->  backend JSON-RPC
     <a download>    ->  IPC export-file        (save dialog + vfs.export)
     demo password   ->  voiceprint unlock      (vault.unlock)
     img/video/audio ->  stvault://media?...    (decrypted stream)

   Injected by electron/preload.js via webFrame.executeJavaScript, so it sees the
   same global object as the page's own scripts.
   ============================================================================ */

(function () {
  var API = window.stvault;
  if (!API || window.__stvaultFmBridge) return;
  window.__stvaultFmBridge = true;

  var I18N = window.STV_I18N;
  var unlocked = false;
  var autoLockTimer = null;
  var autoLockMs = 0;

  var DENY = 'AUTHORIZATION DENIED';
  var LOCKED_OUT = 'LOCKED OUT - AUTHORIZATION SUSPENDED FOR 5 MINUTES';
  var DENY_ONE = 'VOICEPRINT MISMATCH - AUTHORIZATION DENIED - 1 ATTEMPT REMAINING';
  var DENY_N = 'VOICEPRINT MISMATCH - AUTHORIZATION DENIED - {n} ATTEMPTS REMAINING';
  var MIC_DENIED = 'MICROPHONE AUTHORIZATION DENIED - ALLOW ACCESS AND RETRY';

  function t(text, vars) { return I18N && I18N.t ? I18N.t(text, vars) : text; }
  function box(id) { return document.getElementById(id); }
  function strip(p) { return String(p == null ? '' : p).replace(/^\/+/, ''); }
  function many(v) {
    if (v === undefined || v === null || v === '') return [];
    return Object.prototype.toString.call(v) === '[object Array]' ? v : [v];
  }
  function delay(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function play(kind) {
    if (typeof window.playSound === 'function') {
      try { window.playSound(kind); } catch (e) { /* audio unavailable */ }
    }
  }

  function parseQuery(qs) {
    var out = {};
    var parts = String(qs || '').replace(/^\?/, '').split('&');
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      var eq = parts[i].indexOf('=');
      var k = eq < 0 ? parts[i] : parts[i].slice(0, eq);
      var v = eq < 0 ? '' : parts[i].slice(eq + 1);
      try {
        k = decodeURIComponent(k);
        v = decodeURIComponent(v.replace(/\+/g, ' '));
      } catch (e) { /* keep raw */ }
      if (out[k] === undefined) out[k] = v;
      else if (Object.prototype.toString.call(out[k]) === '[object Array]') out[k].push(v);
      else out[k] = [out[k], v];
    }
    return out;
  }

  function mediaUrl(path, file) {
    return 'stvault://media?path=' + encodeURIComponent(path) +
      '&file=' + encodeURIComponent(file);
  }

  /* ------------------------------------------------------------------ routes */

  var ROUTES = {
    list: function (q) {
      if (!unlocked) return { files: [] };
      return API.invoke('vfs.list', { path: strip(q.path) });
    },
    search: function (q) {
      return API.invoke('vfs.search', { path: strip(q.path), q: q.q || '' });
    },
    read: function (q) {
      var path = strip(q.path);
      return API.invoke('vfs.read', { path: path, file: q.file }).then(function (res) {
        if (res && res.url) res.url = mediaUrl(path, q.file);
        return res;
      });
    },
    mkdir: function (q) {
      return API.invoke('vfs.mkdir', { path: strip(q.path), name: q.name || '' });
    },
    delete: function (q) {
      return API.invoke('vfs.delete', {
        path: strip(q.path),
        names: many(q['names[]'] !== undefined ? q['names[]'] : q.names)
      });
    },
    rename: function (q) {
      return API.invoke('vfs.rename', {
        path: strip(q.path),
        old_name: q.old_name || '',
        new_name: q.new_name || ''
      });
    },
    move: function (q) {
      return API.invoke('vfs.move', {
        src_path: strip(q.src_path),
        src_name: q.src_name || '',
        dest_path: strip(q.dest_path)
      });
    },
    paste: function (q) {
      return API.invoke('vfs.paste', {
        dest: strip(q.dest),
        src: strip(q.src),
        action_type: q.action_type || 'copy',
        names: many(q['names[]'] !== undefined ? q['names[]'] : q.names)
      });
    },
    upload: function (q, files) {
      if (!files.length) return { imported: 0 };
      return API.invoke('vfs.import', { path: strip(q.path), sources: files });
    }
  };

  function bodyParams(body) {
    if (body === undefined || body === null) return {};
    if (typeof body === 'string') return parseQuery(body);
    if (window.FormData && body instanceof FormData) {
      var out = {};
      try {
        body.forEach(function (value, key) {
          if (typeof value === 'string') out[key] = value;
        });
      } catch (e) { /* not iterable */ }
      return out;
    }
    return {};
  }

  function bodyFiles(body) {
    var paths = [];
    if (window.FormData && body && body instanceof FormData) {
      try {
        body.forEach(function (value) {
          // Electron <= 31 exposes the real path of dropped/picked files.
          if (value && typeof value === 'object' && typeof value.path === 'string') {
            paths.push(value.path);
          }
        });
      } catch (e) { /* not iterable */ }
    }
    return paths;
  }

  /* -------------------------------------------------------------- XHR bridge */

  var OrigXHR = window.XMLHttpRequest;

  function BridgeXHR() {
    this.readyState = 0;
    this.status = 0;
    this.responseText = '';
    this.onload = null;
    this.onerror = null;
    this._method = 'GET';
    this._url = '';
  }

  BridgeXHR.prototype.open = function (method, url) {
    this._method = String(method || 'GET').toUpperCase();
    this._url = String(url || '');
    this.readyState = 1;
  };
  BridgeXHR.prototype.setRequestHeader = function () { /* handled by the bridge */ };
  BridgeXHR.prototype.overrideMimeType = function () { /* no-op */ };
  BridgeXHR.prototype.abort = function () { /* no-op */ };

  BridgeXHR.prototype.send = function (body) {
    var self = this;
    var url = this._url;
    var qi = url.indexOf('?');

    if (qi < 0) { finish(self, 0); return; }

    var params = parseQuery(url.slice(qi + 1));
    var form = bodyParams(body);
    for (var key in form) if (Object.prototype.hasOwnProperty.call(form, key)) params[key] = form[key];

    var action = params.action;
    var route = ROUTES[action];
    if (!route) { finish(self, 404, { error: 'UNSUPPORTED ACTION' }); return; }

    var result;
    try {
      result = route(params, bodyFiles(body));
    } catch (err) {
      finish(self, 500, { error: err && err.message ? err.message : 'LCARS LINK FAILURE' });
      return;
    }

    Promise.resolve(result).then(function (res) {
      finish(self, 200, res === undefined || res === null ? {} : res);
    }, function (err) {
      finish(self, 500, { error: err && err.message ? err.message : 'LCARS LINK FAILURE' });
    });
  };

  function finish(xhr, status, payload) {
    xhr.readyState = 4;
    xhr.status = status;
    xhr.responseText = payload === 0 ? '' : JSON.stringify(payload);
    setTimeout(function () {
      if (typeof xhr.onload === 'function') xhr.onload();
    }, 0);
  }

  window.XMLHttpRequest = BridgeXHR;

  // Keep the real thing reachable for anything that still wants it.
  window.__StvaultRealXHR = OrigXHR;

  /* ----------------------------------------------------------- download sink */

  if (window.HTMLAnchorElement && HTMLAnchorElement.prototype.click) {
    var origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      var href = this.getAttribute('href') || '';
      var i = href.indexOf('?action=download');
      if (i >= 0) {
        var q = parseQuery(href.slice(i + 1));
        play('chirp');
        API.exportFile({ path: strip(q.path), file: q.file }).catch(function () { play('error'); });
        return;
      }
      return origClick.apply(this, arguments);
    };
  }

  /* ------------------------------------------------------- voiceprint unlock */

  // Lock-screen state machine:
  //   idle      -> primary button reads "RECORD"
  //   recording -> mic is open (voice.listen_begin), primary reads "END & VERIFY"
  //   busy      -> capture closed, vault.unlock in flight, primary disabled
  var lockState = 'idle';

  function lockError(message) {
    var el = box('lock-error');
    if (el) el.textContent = message || '';
  }

  function lockStatus(message) {
    var el = box('lock-status');
    if (el) el.textContent = message || '';
  }

  function showLock(show) {
    var el = box('lock-overlay');
    if (!el) return;
    el.style.display = show ? 'flex' : 'none';
  }

  function primaryBtn() { return box('lock-btn'); }
  function backBtn() { return box('lock-back'); }

  function setPrimary(label, recording, disabled) {
    var btn = primaryBtn();
    if (!btn) return;
    btn.textContent = label;
    btn.disabled = !!disabled;
    if (recording) btn.classList.add('is-recording');
    else btn.classList.remove('is-recording');
  }

  function deniedMessage(res) {
    if (res && res.locked_until) return t(LOCKED_OUT);
    var remaining = res && typeof res.remaining === 'number' ? res.remaining : 0;
    if (remaining <= 1) return t(DENY_ONE);
    return t(DENY_N, { n: remaining });
  }

  function beginRecording() {
    lockError('');
    setPrimary(t('LISTENING...'), false, true);
    lockStatus(t('REQUESTING MICROPHONE...'));

    API.micAuthorize()
      .then(function (granted) {
        if (!granted) throw new Error(t(MIC_DENIED));
        return API.invoke('voice.playback', { active: true });
      })
      .then(function () { play('beep'); return delay(900); })
      .then(function () { return API.invoke('voice.playback', { active: false }); })
      .then(function () {
        return API.invoke('voice.listen_begin', { max_secs: 30, ignore_playback: true });
      })
      .then(function () {
        lockState = 'recording';
        setPrimary('END & VERIFY', true, false);
        lockStatus(t('LISTENING - SPEAK THE AUTHORIZATION CODE...'));
      })
      .catch(function (err) {
        lockState = 'idle';
        setPrimary('RECORD', false, false);
        lockStatus('STANDBY');
        lockError(err && err.message ? err.message : DENY);
        play('error');
      });
  }

  function endAndVerify() {
    if (lockState !== 'recording') return;
    lockState = 'busy';
    setPrimary(t('VERIFYING AUTHORIZATION...'), false, true);
    lockStatus(t('VERIFYING AUTHORIZATION...'));

    API.invoke('voice.listen_end', {})
      .then(function (capture) {
        var embedding = capture && capture.embedding;
        if (!embedding || !embedding.length) throw new Error(t('NO SPEECH RECOGNIZED'));
        return API.invoke('vault.unlock', {
          passphrase_norm: (capture && capture.text_norm) || '',
          embedding: embedding
        });
      })
      .then(function (res) {
        if (res && res.ok) {
          unlocked = true;
          lockState = 'idle';
          play('verify');
          lockError('');
          lockStatus('STANDBY');
          showLock(false);
          setPrimary('RECORD', false, false);
          if (typeof window.refreshFiles === 'function') window.refreshFiles();
          return;
        }
        throw new Error(deniedMessage(res));
      })
      .catch(function (err) {
        lockState = 'idle';
        setPrimary('RECORD', false, false);
        lockStatus('STANDBY');
        lockError(err && err.message ? err.message : DENY);
        play('error');
      });
  }

  // Primary button: RECORD -> begin; END & VERIFY -> finish + unlock.
  function lockPrimary() {
    if (unlocked) return;
    if (lockState === 'idle') beginRecording();
    else if (lockState === 'recording') endAndVerify();
    // busy: ignore further clicks until the verify chain settles.
  }

  // Back button: cancel any in-flight capture and return to the vault list.
  function lockBack() {
    if (lockState === 'recording') {
      lockState = 'busy';
      API.invoke('voice.listen_cancel', {})
        .catch(function () { /* already finished */ })
        .then(function () {
          lockState = 'idle';
          API.invoke('vault.lock', {}).catch(function () { /* already locked */ });
          API.go('app.html');
        });
      return;
    }
    if (lockState === 'busy') return; // verify in flight; let it finish
    API.invoke('vault.lock', {}).catch(function () { /* already locked */ });
    API.go('app.html');
  }

  window.stvaultLockPrimary = lockPrimary;
  window.stvaultLockBack = lockBack;
  // Legacy entry point kept so any stale onclick still resolves somewhere sane.
  window.verifyCode = lockPrimary;

  /* ------------------------------------------------------- idle auto-lock */

  // When enabled in settings, lock the vault and return to the main page after
  // N minutes with no user activity. Any interaction resets the countdown.
  function resetAutoLock() {
    if (autoLockTimer) { clearTimeout(autoLockTimer); autoLockTimer = null; }
    if (!autoLockMs || !unlocked) return;
    autoLockTimer = setTimeout(autoLockNow, autoLockMs);
  }

  function autoLockNow() {
    autoLockTimer = null;
    if (!unlocked) return;
    API.invoke('vault.lock', {}).catch(function () { /* already locked */ });
    API.go('app.html');
  }

  function onAutoLockActivity() {
    if (autoLockMs && unlocked) resetAutoLock();
  }

  function armAutoLock() {
    API.invoke('settings.get', {}).then(function (s) {
      if (!s || !s.autolock_enabled) { autoLockMs = 0; return; }
      var mins = Number(s.autolock_minutes || 0);
      autoLockMs = mins > 0 ? mins * 60000 : 0;
      resetAutoLock();
    }, function () { autoLockMs = 0; });
  }

  /* -------------------------------------------------------------------- boot */

  function reload() {
    if (typeof window.refreshFiles === 'function') window.refreshFiles();
    else if (typeof window.loadFiles === 'function') window.loadFiles('');
  }

  function boot() {
    window.verifyCode = lockPrimary;

    // Reset the idle countdown on any interaction (capture phase so scrolling and
    // clicks inside the file list also count).
    ['mousemove', 'mousedown', 'keydown', 'wheel', 'scroll', 'touchstart', 'click'].forEach(function (ev) {
      window.addEventListener(ev, onAutoLockActivity, true);
    });

    var query = parseQuery(location.search);
    var selected = strip(query.path);

    var ready = selected
      ? API.invoke('vault.select', { path: selected }).catch(function () { /* keep backend default */ })
      : Promise.resolve();

    ready
      .then(function () { return API.invoke('status', {}); })
      .then(function (state) {
        if (state && state.vault_open) {
          unlocked = true;
          showLock(false);
          reload();
          armAutoLock();
          return;
        }
        showLock(true);
      }, function () {
        showLock(true);
      })
      .then(function () {
        var btn = primaryBtn();
        if (btn) { try { btn.focus(); } catch (e) { /* not focusable */ } }
      });

    // Language: mirror the backend setting; the page's own strings stay English
    // in the dictionary, so they swap in place when a translation exists.
    if (I18N) {
      if (I18N.apply) { try { I18N.apply(document.body); } catch (e) { /* ignore */ } }
      if (I18N.onChange) I18N.onChange(function () { try { I18N.apply(document.body); } catch (e) { /* ignore */ } });
      API.invoke('settings.get', {}).then(function (s) {
        if (s && s.language && I18N.setLang) I18N.setLang(s.language, { mirror: false });
      }, function () { /* defaults to English */ });
    }

    // Header doubles as the way back to the vault list (their chrome has no nav
    // button for it): lock the container, then return to app.html.
    var header = document.querySelector('.header__link');
    if (header) {
      header.addEventListener('click', function (e) {
        e.preventDefault();
        API.invoke('vault.lock', {}).catch(function () { /* already locked */ });
        API.go('app.html');
      });
    }
  }

  if (document.readyState === 'complete') boot();
  else window.addEventListener('load', boot);
})();
