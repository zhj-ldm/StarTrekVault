'use strict';
/* ============================================================================
   STAR TREK VAULT - app.js
   Single page controller for renderer/app.html.

   All backend access goes through window.stvault (electron/preload.js):
     invoke(method, params) -> Promise<result>
     micAuthorize()         -> Promise<boolean>
     pickVaultPath(name)    -> Promise<string|null>
     go(page)               -> navigate the window
   UI strings are LCARS English / uppercase. Comments are concise English.
   ============================================================================ */
(function () {

  var API = window.stvault || null;
  var I18N = window.STV_I18N || null;

  // Translate a JS-composed string. Falls back to the source text when the
  // i18n module (renderer/i18n.js) is unavailable.
  function t(text, vars) {
    if (I18N) return I18N.t(text, vars);
    return String(text === null || text === undefined ? '' : text);
  }

  /* ------------------------------------------------------------------ state */
  var state = {
    view: 'vaults',
    initialView: 'vaults',
    fromFm: false,
    vaults: [],
    status: {},
    recovery: { path: '', answer: '', master: '', verified: false },
    pollTimer: null
  };

  var createRecorder = null;
  var recoveryRecorder = null;

  var VIEWS = {
    setup: 'view-setup',
    vaults: 'view-vaults',
    create: 'view-create',
    settings: 'view-settings',
    recovery: 'view-recovery',
    audit: 'view-audit'
  };

  var VIEW_ERROR = {
    setup: 'setup-error',
    vaults: 'vaults-error',
    create: 'create-error',
    settings: 'settings-error',
    recovery: 'recovery-error',
    audit: 'audit-error'
  };

  /* ---------------------------------------------------------------- helpers */
  function $(id) {
    return document.getElementById(id);
  }

  function esc(value) {
    return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function showError(errorId, message) {
    var el = $(errorId);
    if (!el) return;
    el.textContent = t(String(message || 'UNKNOWN FAILURE')).toUpperCase();
    el.hidden = false;
  }

  function clearError(errorId) {
    var el = $(errorId);
    if (!el) return;
    el.hidden = true;
    el.textContent = '';
  }

  function clearAllErrors() {
    Object.keys(VIEW_ERROR).forEach(function (k) { clearError(VIEW_ERROR[k]); });
  }

  // Disable a button and swap in a working label, remembering the old state.
  function setBusy(btn, label) {
    btn.dataset.prevDisabled = btn.disabled ? '1' : '0';
    btn.dataset.idleLabel = btn.textContent;
    btn.textContent = label;
    btn.disabled = true;
  }

  function clearBusy(btn) {
    if (btn.dataset.idleLabel !== undefined) btn.textContent = btn.dataset.idleLabel;
    btn.disabled = btn.dataset.prevDisabled === '1';
  }

  function restoreLabel(btn) {
    if (btn.dataset.idleLabel !== undefined) btn.textContent = btn.dataset.idleLabel;
  }

  // JSON-RPC bridge. Rejects with Error(message) on backend failure.
  function invoke(method, params) {
    if (!API || typeof API.invoke !== 'function') {
      return Promise.reject(new Error('LCARS LINK OFFLINE'));
    }
    return API.invoke(method, params || {});
  }

  function go(page) {
    if (API && typeof API.go === 'function') API.go(page);
    else showError(VIEW_ERROR[state.view], 'LCARS LINK OFFLINE');
  }

  // Enter the file manager only when the backend knows which container to unlock.
  // With exactly one container we select it and jump straight in; otherwise the
  // user must pick one from the vault list first.
  function enterVault() {
    invoke('vault.list', {}).then(function (res) {
      var list = (res && res.vaults) || [];
      if (list.length === 1) {
        var path = list[0].path;
        invoke('vault.select', { path: path }).then(function () {
          go('fm.html?path=' + encodeURIComponent(path));
        }, function (err) {
          showError('vaults-error', err && err.message ? err.message : String(err));
        });
      } else {
        showView('vaults');
      }
    }, function () { showView('vaults'); });
  }

  // Unix seconds/ms -> seconds; 0 when absent.
  function toSeconds(ts) {
    var n = Number(ts || 0);
    if (!n) return 0;
    return n > 1e12 ? Math.floor(n / 1000) : n;
  }

  function pad2(n) {
    return (n < 10 ? '0' : '') + n;
  }

  function formatTime(ts) {
    var secs = toSeconds(ts);
    if (!secs) return t('UNKNOWN');
    var d = new Date(secs * 1000);
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
      ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
  }

  function formatSize(bytes) {
    var n = Number(bytes || 0);
    if (n <= 0) return '0 B';
    var k = 1024;
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(k)));
    return (n / Math.pow(k, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  }

  function normalizeText(s) {
    return String(s || '').toUpperCase().replace(/\s+/g, ' ').trim();
  }

  /* --------------------------------------------------------- header / status */
  function setStateItem(id, label, value, ok) {
    var el = $(id);
    if (!el) return;
    el.textContent = label + ': ' + value;
    el.classList.toggle('is-ok', !!ok);
    el.classList.toggle('is-down', !ok);
  }

  function updateHeader(s) {
    s = s || {};
    state.status = s;
    var micOk = !!(s.mic_alive && s.cap_ok);
    var voiceOk = !!(s.asr_ready && s.spk_ready && s.vad_ready);
    var vaultOpen = !!s.vault_open;
    setStateItem('hdr-mic', t('MIC'), micOk ? t('OK') : t('DOWN'), micOk);
    setStateItem('hdr-voice', t('VOICE'), voiceOk ? t('READY') : t('DOWN'), voiceOk);
    setStateItem('hdr-vault', t('VAULT'), vaultOpen ? t('OPEN') : t('LOCKED'), vaultOpen);
  }

  function pollStatus(initial) {
    if (!API) return;
    var p = invoke('status', {});
    p.then(function (s) {
      updateHeader(s);
      if (initial) {
        if (!s || !s.global_configured) showView('setup');
        else showView(state.initialView);
      }
    }, function (err) {
      if (initial) {
        showView(state.initialView);
        showError(VIEW_ERROR[state.view], err && err.message ? err.message : String(err));
      }
    });
  }

  /* ---------------------------------------------------------- view switching */
  function updateNavActive(name) {
    var map = { vaults: 'nav-vaults', create: 'nav-create', settings: 'nav-settings', audit: 'nav-audit' };
    Object.keys(map).forEach(function (k) {
      var el = $(map[k]);
      if (el) el.classList.toggle('is-active', k === name);
    });
  }

  function showView(name) {
    if (!VIEWS[name]) name = 'vaults';
    Object.keys(VIEWS).forEach(function (k) {
      var el = $(VIEWS[k]);
      if (el) el.classList.toggle('is-active', k === name);
    });
    state.view = name;
    document.body.classList.toggle('setup-mode', name === 'setup');
    updateNavActive(name);
    clearAllErrors();

    // Leaving a recorder view while the mic is open must release the capture,
    // otherwise the next begin would collide with the in-flight session.
    if (name !== 'create' && createRecorder && createRecorder.cancel) createRecorder.cancel();
    if (name !== 'recovery' && recoveryRecorder && recoveryRecorder.cancel) recoveryRecorder.cancel();

    if (name === 'vaults') refreshVaults();
    if (name === 'settings') loadSettings();
    if (name === 'create') setupCreateFingerprint();
    if (name === 'recovery') $('recovery-path').value = state.recovery.path || '';
  }

  /* --------------------------------------------------------------- vaults */
  function statusCell(v) {
    var until = toSeconds(v.locked_until || 0);
    var now = Math.floor(Date.now() / 1000);
    if (until && until > now) {
      var mins = Math.max(1, Math.ceil((until - now) / 60));
      return '<span class="lcars-lockedout">' + esc(t('LOCKED OUT') + ' - ' + mins + ' ' + t('MIN')) + '</span>';
    }
    if (v.locked) return '<span class="lcars-locked">' + esc(t('LOCKED')) + '</span>';
    return '<span class="lcars-open">' + esc(t('OPEN')) + '</span>';
  }

  function renderVaults() {
    var tbody = $('vault-tbody');
    var empty = $('vaults-empty');
    tbody.innerHTML = '';
    if (!state.vaults.length) {
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    state.vaults.forEach(function (v) {
      var tr = document.createElement('tr');
      tr.dataset.path = v.path || '';
      tr.dataset.name = v.name || '';
      tr.innerHTML =
        '<td class="lcars-table__name">' + esc(v.name || t('(UNNAMED)')) + '</td>' +
        '<td>' + esc(formatSize(v.size)) + '</td>' +
        '<td>' + esc(formatTime(v.created)) + '</td>' +
        '<td>' + statusCell(v) + '</td>' +
        '<td><div class="lcars-table__actions">' +
          '<button class="lcars-btn lcars-btn--sm lcars-btn--blue" type="button" data-act="unlock">' + esc(t('UNLOCK')) + '</button>' +
          '<button class="lcars-btn lcars-btn--sm lcars-btn--violet" type="button" data-act="recovery">' + esc(t('RECOVERY')) + '</button>' +
          '<button class="lcars-btn lcars-btn--sm lcars-btn--red" type="button" data-act="delete">' + esc(t('DELETE')) + '</button>' +
        '</div></td>';
      tbody.appendChild(tr);
    });
  }

  function refreshVaults() {
    clearError('vaults-error');
    var btn = $('btn-refresh-vaults');
    setBusy(btn, t('SCANNING...'));
    return invoke('vault.list', {}).then(function (r) {
      state.vaults = (r && r.vaults) ? r.vaults : [];
      renderVaults();
    }, function (err) {
      showError('vaults-error', err && err.message ? err.message : String(err));
    }).then(function () {
      clearBusy(btn);
    });
  }

  // Import an external .stvault container. The main process shows a native file
  // picker and returns the chosen source path plus the default destination
  // (~/Documents/startrek vault). The backend validates the format and copies it.
  function onImportVault() {
    clearError('vaults-error');
    if (!API || typeof API.pickStvaultFile !== 'function') {
      showError('vaults-error', 'LCARS LINK OFFLINE');
      return;
    }
    var btn = $('btn-import-vault');
    setBusy(btn, t('IMPORTING...'));
    API.pickStvaultFile().then(function (res) {
      if (!res || res.canceled || !res.path) return null;
      return invoke('vault.import', { src: res.path, dest_dir: res.dest_dir }).then(function () {
        return refreshVaults();
      });
    }, function (err) {
      showError('vaults-error', err && err.message ? err.message : String(err));
    }).catch(function (err) {
      showError('vaults-error', err && err.message ? err.message : String(err));
    }).then(function () {
      clearBusy(btn);
    });
  }

  function onVaultRowClick(e) {
    var btn = e.target.closest('button[data-act]');
    if (!btn) return;
    var tr = btn.closest('tr');
    var path = tr ? tr.dataset.path : '';
    var name = tr ? tr.dataset.name : '';
    var act = btn.dataset.act;

    if (act === 'unlock') {
      // The fm.html lock overlay performs the voice unlock. The backend must know
      // which container is being unlocked, so select it first.
      invoke('vault.select', { path: path }).then(function () {
        go('fm.html');
      }, function (err) {
        showError('vaults-error', err && err.message ? err.message : String(err));
      });
    } else if (act === 'recovery') {
      state.recovery.path = path;
      state.recovery.answer = '';
      state.recovery.master = '';
      state.recovery.verified = false;
      $('recovery-path').value = path;
      $('recovery-answer').value = '';
      $('recovery-master').value = '';
      $('recovery-question').textContent = t('SECURITY QUESTION: NOT VERIFIED');
      $('recovery-voiceprint').hidden = true;
      if (recoveryRecorder) recoveryRecorder.reset();
      showView('recovery');
    } else if (act === 'delete') {
      confirmVaultDelete(path, name, btn);
    }
  }

  /* --------------------------------------------------------------- modal */
  function openConfirm(title, message, confirmLabel, danger, onConfirm) {
    $('lcars-modal-title').textContent = title;
    $('lcars-modal-body').textContent = message;
    var footer = $('lcars-modal-footer');
    footer.innerHTML = '';

    var cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'lcars-btn lcars-btn--ghost';
    cancel.textContent = t('CANCEL');
    cancel.addEventListener('click', closeModal);

    var ok = document.createElement('button');
    ok.type = 'button';
    ok.className = 'lcars-btn ' + (danger ? 'lcars-btn--red' : 'lcars-btn--blue');
    ok.textContent = confirmLabel;
    ok.addEventListener('click', function () {
      closeModal();
      onConfirm();
    });

    footer.appendChild(cancel);
    footer.appendChild(ok);
    $('lcars-modal').classList.add('is-open');
  }

  function closeModal() {
    $('lcars-modal').classList.remove('is-open');
  }

  // Deleting a vault is irreversible (three-pass overwrite + removal), so it
  // requires FOUR sequential confirmations. Each dialog reports the step number
  // and how many confirmations still remain, to defeat accidental clicks.
  function confirmVaultDelete(path, name, btn) {
    var TOTAL = 4;
    var display = name || path;
    function step(n) {
      var left = TOTAL - n;
      var isFinal = (n === TOTAL);
      openConfirm(
        t('DELETE VAULT - CONFIRMATION {n} OF {m}', { n: n, m: TOTAL }),
        isFinal
          ? t('FINAL CONFIRMATION. THE CONTAINER "{name}" WILL NOW BE OVERWRITTEN THREE TIMES AND PERMANENTLY REMOVED. THIS CANNOT BE UNDONE. PROCEED?', { name: display })
          : t('CONFIRMATION {n} OF {m}. THE CONTAINER "{name}" WILL BE OVERWRITTEN THREE TIMES AND PERMANENTLY REMOVED. THIS CANNOT BE UNDONE. {left} MORE CONFIRMATION(S) STILL REQUIRED AFTER THIS.', { n: n, m: TOTAL, left: left, name: display }),
        isFinal ? t('DELETE VAULT') : t('CONFIRM {n}/{m}', { n: n, m: TOTAL }),
        true,
        function () {
          if (!isFinal) { step(n + 1); return; }
          var del = btn;
          setBusy(del, t('ERASING...'));
          invoke('vault.delete', { path: path }).then(function () {
            refreshVaults();
          }, function (err) {
            showError('vaults-error', err && err.message ? err.message : String(err));
          }).then(function () {
            clearBusy(del);
          });
        });
    }
    step(1);
  }

  /* ------------------------------------------------------------ recorder */
  // Shared voiceprint recorder used by both CREATE and RECOVERY views.
  // Manual flow: click RECORD to open the mic (voice.listen_begin), the button
  // flips to END, click again to close the capture (voice.listen_end) and land
  // the take in the pending review state. Switching views cancels any take in
  // flight via cancel().
  function makeRecorder(cfg) {
    var MIN_TAKES = 2;
    var MAX_TAKES = 3;
    var accepted = [];
    var pending = null;
    var recording = false;
    var labelRecord = cfg.btnRecord.textContent || 'RECORD';

    function render() {
      var next = Math.min(accepted.length + 1, MAX_TAKES);
      cfg.counter.textContent = t('TAKE {n} / {m} · ACCEPTED {k}', { n: next, m: MAX_TAKES, k: accepted.length });
      cfg.btnRecord.disabled = (!recording && pending !== null) || accepted.length >= MAX_TAKES;
      cfg.btnRecord.textContent = recording ? t('END') : labelRecord;
      cfg.btnAgain.disabled = recording || pending === null || accepted.length >= MAX_TAKES;
      cfg.btnAccept.disabled = recording || pending === null;
      if (cfg.onChange) cfg.onChange(accepted.length);
    }

    function renderTakes() {
      cfg.takes.innerHTML = accepted.map(function (take, i) {
        return '<li>' + esc(t('TAKE {n}: {text}', { n: i + 1, text: take.text || t('(UNRECOGNIZED)') })) + '</li>';
      }).join('');
    }

    function fail(message) {
      cfg.onError(String(t(message) || t('VOICEPRINT CAPTURE FAILED')).toUpperCase());
    }

    function begin() {
      if (!API || typeof API.micAuthorize !== 'function') { fail('LCARS LINK OFFLINE'); return; }
      cfg.status.textContent = t('REQUESTING MICROPHONE...');
      API.micAuthorize().then(function (granted) {
        if (!granted) throw new Error(t('MICROPHONE AUTHORIZATION DENIED'));
        return invoke('voice.listen_begin', { max_secs: 30, ignore_playback: true });
      }).then(function () {
        recording = true;
        cfg.status.textContent = t('LISTENING...');
        render();
      }, function (err) {
        fail(err && err.message ? err.message : err);
        cfg.status.textContent = t('RECORDING FAILED');
      });
    }

    function end() {
      cfg.status.textContent = t('VERIFYING AUTHORIZATION...');
      invoke('voice.listen_end', {}).then(function (r) {
        pending = {
          text: (r && r.text) ? String(r.text) : '',
          text_norm: (r && r.text_norm) ? String(r.text_norm) : '',
          embedding: (r && r.embedding) ? r.embedding : []
        };
        cfg.asr.textContent = pending.text ? pending.text.toUpperCase() : t('NO SPEECH RECOGNIZED');
        cfg.status.textContent = t('TAKE CAPTURED - REVIEW AND ACCEPT');
      }, function (err) {
        pending = null;
        fail(err && err.message ? err.message : err);
        cfg.status.textContent = t('RECORDING FAILED');
      }).then(function () {
        recording = false;
        render();
      });
    }

    function record() {
      if (recording) end();
      else if (pending === null) begin();
    }

    function accept() {
      if (!pending) return;
      accepted.push(pending);
      cfg.asr.textContent = t('ACCEPTED:') + ' ' + (pending.text ? pending.text.toUpperCase() : t('(UNRECOGNIZED)'));
      pending = null;
      renderTakes();
      render();
      cfg.status.textContent = accepted.length >= MAX_TAKES
        ? t('ENROLMENT COMPLETE')
        : t('TAKE ACCEPTED - RECORD NEXT TAKE');
    }

    function cancel() {
      if (!recording) return;
      invoke('voice.listen_cancel', {}).catch(function () { /* already finished */ });
      recording = false;
      cfg.status.textContent = t('STANDBY');
      render();
    }

    function reset() {
      cancel();
      accepted = [];
      pending = null;
      cfg.asr.textContent = t('NO TAKE RECORDED');
      cfg.status.textContent = t('STANDBY');
      renderTakes();
      render();
    }

    cfg.btnRecord.addEventListener('click', record);
    cfg.btnAgain.addEventListener('click', function () { pending = null; begin(); });
    cfg.btnAccept.addEventListener('click', accept);

    render();

    return {
      reset: reset,
      cancel: cancel,
      sync: render,
      isRecording: function () { return recording; },
      canCommit: function () { return accepted.length >= MIN_TAKES; },
      getTakes: function () { return accepted.slice(); },
      getEmbeddings: function () { return accepted.map(function (t) { return t.embedding || []; }); },
      getPassphraseNorm: function () {
        if (!accepted.length) return '';
        return accepted[0].text_norm || normalizeText(accepted[0].text);
      }
    };
  }

  function buildRecorders() {
    createRecorder = makeRecorder({
      status: $('create-record-status'),
      asr: $('create-asr-text'),
      counter: $('create-take-counter'),
      takes: $('create-takes'),
      btnRecord: $('btn-create-record'),
      btnAgain: $('btn-create-again'),
      btnAccept: $('btn-create-accept'),
      onError: function (m) { showError('create-error', m); },
      onChange: function (n) { $('btn-create-vault').disabled = n < 2; }
    });

    recoveryRecorder = makeRecorder({
      status: $('rec-record-status'),
      asr: $('rec-asr-text'),
      counter: $('rec-take-counter'),
      takes: $('rec-takes'),
      btnRecord: $('btn-rec-record'),
      btnAgain: $('btn-rec-again'),
      btnAccept: $('btn-rec-accept'),
      onError: function (m) { showError('recovery-error', m); },
      onChange: function (n) { $('btn-commit-voiceprint').disabled = n < 2; }
    });
  }

  /* ---------------------------------------------------------------- setup */
  function resetSetupFields() {
    ['setup-question', 'setup-answer', 'setup-master', 'setup-master2'].forEach(function (id) {
      $(id).value = '';
    });
    clearError('setup-error');
  }

  function onSubmitSetup() {
    clearError('setup-error');
    var question = $('setup-question').value.trim();
    var answer = $('setup-answer').value.trim();
    var master = $('setup-master').value;
    var confirm = $('setup-master2').value;

    if (!question || !answer || !master) { showError('setup-error', 'ALL FIELDS ARE REQUIRED'); return; }
    if (master !== confirm) { showError('setup-error', 'MASTER PASSWORDS DO NOT MATCH'); return; }

    var btn = $('btn-setup');
    setBusy(btn, t('DERIVING KEYS...'));
    invoke('global.init', { question: question, answer: answer, master: master }).then(function () {
      // Carry the freshly defined credentials into the CREATE form so the next
      // step can seal a container without retyping them.
      $('create-answer').value = answer;
      $('create-master').value = master;
      resetSetupFields();
      showView('vaults');
    }, function (err) {
      showError('setup-error', err && err.message ? err.message : String(err));
    }).then(function () {
      clearBusy(btn);
    });
  }

  /* --------------------------------------------------------------- create */
  function onChooseLocation() {
    clearError('create-error');
    if (!API || typeof API.pickVaultPath !== 'function') {
      showError('create-error', 'LCARS LINK OFFLINE');
      return;
    }
    var name = $('create-name').value.trim() || 'VAULT';
    API.pickVaultPath(name + '.stvault').then(function (path) {
      if (path) {
        $('create-path').value = path;
        clearError('create-error');
      }
    }, function (err) {
      showError('create-error', err && err.message ? err.message : String(err));
    });
  }

  // Touch ID availability for the create form. Called every time the view opens
  // so it reflects the current machine (sensor present / enrolled).
  function setupCreateFingerprint() {
    var cb = $('create-fingerprint');
    var label = $('create-fingerprint-text');
    if (!cb) return;
    cb.checked = false;
    cb.disabled = true;
    if (label) label.textContent = t('REQUIRE TOUCH ID');
    if (!API || typeof API.touchIDAvailable !== 'function') {
      if (label) label.textContent = t('TOUCH ID NOT AVAILABLE ON THIS DEVICE');
      return;
    }
    API.touchIDAvailable().then(function (ok) {
      if (ok) {
        cb.disabled = false;
      } else if (label) {
        label.textContent = t('TOUCH ID NOT AVAILABLE ON THIS DEVICE');
      }
    }, function () {
      if (label) label.textContent = t('TOUCH ID NOT AVAILABLE ON THIS DEVICE');
    });
  }

  function onCreateVault() {
    clearError('create-error');
    var name = $('create-name').value.trim();
    var path = $('create-path').value.trim();
    var answer = $('create-answer').value.trim();
    var master = $('create-master').value;

    if (!name) { showError('create-error', 'VAULT NAME IS REQUIRED'); return; }
    if (!path) { showError('create-error', 'CONTAINER PATH IS REQUIRED - USE CHOOSE LOCATION'); return; }
    if (!answer || !master) {
      showError('create-error', 'PATH, SECURITY ANSWER AND MASTER PASSWORD ARE REQUIRED');
      return;
    }
    if (!createRecorder || !createRecorder.canCommit()) {
      showError('create-error', 'TWO OR THREE ACCEPTED TAKES ARE REQUIRED');
      return;
    }

    var btn = $('btn-create-vault');
    setBusy(btn, t('DERIVING KEYS...'));
    // answer + master re-seal the recovery wrap; passing them keeps creation
    // working after a relaunch when the backend cache is cold.
    invoke('vault.create', {
      path: path,
      name: name,
      answer: answer,
      master: master,
      passphrase_norm: createRecorder.getPassphraseNorm(),
      embeddings: createRecorder.getEmbeddings(),
      fingerprint: !!($('create-fingerprint') && $('create-fingerprint').checked)
    }).then(function () {
      createRecorder.reset();
      $('create-name').value = '';
      $('create-path').value = '';
      $('create-master').value = '';
      if ($('create-fingerprint')) $('create-fingerprint').checked = false;
      showView('vaults');
      restoreLabel(btn);
      createRecorder.sync();
    }, function (err) {
      showError('create-error', err && err.message ? err.message : String(err));
      clearBusy(btn);
    });
  }

  /* ------------------------------------------------------------- settings */
  function loadSettings() {
    clearError('settings-error');
    invoke('settings.get', {}).then(function (s) {
      if (s && typeof s.similarity_threshold === 'number') {
        var v = Number(s.similarity_threshold);
        $('settings-threshold').value = String(v);
        $('settings-threshold-value').textContent = v.toFixed(2);
      }
      if (s && s.language) applyLanguage(s.language, true);
      if (s) {
        $('settings-autolock-enabled').checked = !!s.autolock_enabled;
        var mins = Number(s.autolock_minutes);
        if (mins > 0) $('settings-autolock-minutes').value = String(mins);
      }
    }, function (err) {
      showError('settings-error', err && err.message ? err.message : String(err));
    });
  }

  function onApplySettings() {
    clearError('settings-error');
    var value = Math.max(0.4, Math.min(0.9, Number($('settings-threshold').value)));
    var autoEnabled = !!$('settings-autolock-enabled').checked;
    var autoMins = Math.max(1, Math.min(240, Math.round(Number($('settings-autolock-minutes').value) || 5)));
    var btn = $('btn-apply-settings');
    setBusy(btn, t('APPLYING...'));
    invoke('settings.set', {
      similarity_threshold: value,
      autolock_enabled: autoEnabled,
      autolock_minutes: autoMins
    }).then(function () {
      $('settings-threshold-value').textContent = value.toFixed(2);
      $('settings-autolock-minutes').value = String(autoMins);
    }, function (err) {
      showError('settings-error', err && err.message ? err.message : String(err));
    }).then(function () {
      clearBusy(btn);
    });
  }

  // Switch interface language. `mirrorOnly` skips persisting to the backend
  // (used when the backend itself just told us the current language).
  function applyLanguage(language, mirrorOnly) {
    var next = I18N ? I18N.normalizeLang(language) : (String(language).toLowerCase() === 'zh' ? 'zh' : 'en');
    if (I18N && next !== I18N.getLang()) I18N.setLang(next);
    syncLangButtons(next);
    updateHeader(state.status);
    if (state.view === 'vaults') renderVaults();
    if (createRecorder) createRecorder.sync();
    if (recoveryRecorder) recoveryRecorder.sync();
    if (!mirrorOnly) {
      invoke('settings.set', { language: next }).then(null, function () {});
    }
  }

  function syncLangButtons(language) {
    var lang = language || (I18N ? I18N.getLang() : 'en');
    var en = $('btn-lang-en');
    var zh = $('btn-lang-zh');
    if (en) en.classList.toggle('lcars-btn--blue', lang !== 'zh');
    if (zh) zh.classList.toggle('lcars-btn--blue', lang === 'zh');
  }

  function onSystemWipe() {
    openConfirm(t('SYSTEM WIPE'),
      t('SYSTEM WIPE IRREVERSIBLY DESTROYS EVERY VAULT CONTAINER, THE GLOBAL CONFIGURATION AND THE AUDIT LOG. THREE PASS OVERWRITE RUNS FIRST. THIS CANNOT BE UNDONE. PROCEED?'),
      t('EXECUTE WIPE'), true, function () {
        clearError('settings-error');
        var btn = $('btn-system-wipe');
        setBusy(btn, t('WIPING...'));
        invoke('wipe.execute', { confirm: true }).then(function () {
          resetSetupFields();
          showView('setup');
        }, function (err) {
          showError('settings-error', err && err.message ? err.message : String(err));
        }).then(function () {
          clearBusy(btn);
        });
      });
  }

  /* ------------------------------------------------------------- recovery */
  function unlockRecoveryFields() {
    $('recovery-path').readOnly = false;
    $('recovery-answer').readOnly = false;
    $('recovery-master').readOnly = false;
  }

  function onVerifyCredentials() {
    clearError('recovery-error');
    var path = $('recovery-path').value.trim();
    var answer = $('recovery-answer').value.trim();
    var master = $('recovery-master').value;

    if (!path || !answer || !master) {
      showError('recovery-error', 'PATH, SECURITY ANSWER AND MASTER PASSWORD ARE REQUIRED');
      return;
    }

    var btn = $('btn-verify-credentials');
    setBusy(btn, t('DERIVING KEYS...'));
    invoke('recovery.begin', { path: path, answer: answer, master: master }).then(function (r) {
      state.recovery.path = path;
      state.recovery.answer = answer;
      state.recovery.master = master;
      state.recovery.verified = true;
      $('recovery-question').textContent = t('SECURITY QUESTION:') + ' ' +
        (r && r.question ? String(r.question).toUpperCase() : t('UNAVAILABLE'));
      $('recovery-path').readOnly = true;
      $('recovery-answer').readOnly = true;
      $('recovery-master').readOnly = true;
      $('recovery-voiceprint').hidden = false;
      if (recoveryRecorder) recoveryRecorder.reset();
    }, function (err) {
      showError('recovery-error', err && err.message ? err.message : String(err));
    }).then(function () {
      clearBusy(btn);
    });
  }

  function onCommitVoiceprint() {
    clearError('recovery-error');
    if (!state.recovery.verified) { showError('recovery-error', 'VERIFY CREDENTIALS FIRST'); return; }
    if (!recoveryRecorder || !recoveryRecorder.canCommit()) {
      showError('recovery-error', 'TWO OR THREE ACCEPTED TAKES ARE REQUIRED');
      return;
    }

    var btn = $('btn-commit-voiceprint');
    setBusy(btn, t('DERIVING KEYS...'));
    invoke('recovery.set_voiceprint', {
      path: state.recovery.path,
      answer: state.recovery.answer,
      master: state.recovery.master,
      passphrase_norm: recoveryRecorder.getPassphraseNorm(),
      embeddings: recoveryRecorder.getEmbeddings()
    }).then(function () {
      recoveryRecorder.reset();
      state.recovery.verified = false;
      state.recovery.answer = '';
      state.recovery.master = '';
      $('recovery-voiceprint').hidden = true;
      $('recovery-answer').value = '';
      $('recovery-master').value = '';
      unlockRecoveryFields();
      $('recovery-question').textContent = t('VOICEPRINT RE-ENROLLED - FILE DATA PRESERVED');
      showView('vaults');
      restoreLabel(btn);
      recoveryRecorder.sync();
    }, function (err) {
      showError('recovery-error', err && err.message ? err.message : String(err));
      clearBusy(btn);
    });
  }

  /* ---------------------------------------------------------------- audit */
  function renderAudit(entries) {
    var tbody = $('audit-tbody');
    var empty = $('audit-empty');
    tbody.innerHTML = '';
    if (!entries.length) {
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    entries.forEach(function (e) {
      var tr = document.createElement('tr');
      var hash = String(e.hash || '');
      var shortHash = hash.length > 24 ? hash.slice(0, 24) + '...' : hash;
      tr.innerHTML =
        '<td>' + esc(formatTime(e.at)) + '</td>' +
        '<td>' + esc((e.event || '').toUpperCase()) + '</td>' +
        '<td>' + esc(e.detail || '') + '</td>' +
        '<td class="lcars-table__mono" title="' + esc(hash) + '">' + esc(shortHash) + '</td>';
      tbody.appendChild(tr);
    });
  }

  function onDecryptLog() {
    clearError('audit-error');
    var master = $('audit-master').value;
    if (!master) { showError('audit-error', 'MASTER PASSWORD IS REQUIRED'); return; }
    var btn = $('btn-decrypt-log');
    setBusy(btn, t('DERIVING KEYS...'));
    invoke('audit.list', { master: master }).then(function (r) {
      renderAudit((r && r.entries) ? r.entries : []);
    }, function (err) {
      showError('audit-error', err && err.message ? err.message : String(err));
    }).then(function () {
      clearBusy(btn);
    });
  }

  /* --------------------------------------------------------------- wiring */
  function wireEvents() {
    $('nav-vaults').addEventListener('click', function () { showView('vaults'); });
    $('nav-create').addEventListener('click', function () {
      createRecorder.reset();
      showView('create');
    });
    $('nav-settings').addEventListener('click', function () { showView('settings'); });
    $('nav-audit').addEventListener('click', function () { showView('audit'); });
    $('nav-fm').addEventListener('click', function () { enterVault(); });

    $('btn-setup').addEventListener('click', onSubmitSetup);

    $('vault-tbody').addEventListener('click', onVaultRowClick);
    $('btn-refresh-vaults').addEventListener('click', refreshVaults);
    $('btn-new-vault').addEventListener('click', function () {
      createRecorder.reset();
      showView('create');
    });
    $('btn-import-vault').addEventListener('click', onImportVault);

    $('btn-create-cancel').addEventListener('click', function () { showView('vaults'); });
    $('btn-choose-location').addEventListener('click', onChooseLocation);
    $('btn-create-vault').addEventListener('click', onCreateVault);

    $('settings-threshold').addEventListener('input', function () {
      $('settings-threshold-value').textContent = Number($('settings-threshold').value).toFixed(2);
    });
    $('btn-apply-settings').addEventListener('click', onApplySettings);
    $('btn-settings-recovery').addEventListener('click', function () {
      if (recoveryRecorder) recoveryRecorder.reset();
      $('recovery-voiceprint').hidden = true;
      $('recovery-question').textContent = t('SECURITY QUESTION: NOT VERIFIED');
      unlockRecoveryFields();
      $('recovery-answer').value = '';
      $('recovery-master').value = '';
      showView('recovery');
    });
    $('btn-lang-en').addEventListener('click', function () { applyLanguage('en'); });
    $('btn-lang-zh').addEventListener('click', function () { applyLanguage('zh'); });
    $('btn-system-wipe').addEventListener('click', onSystemWipe);
    $('btn-settings-fm').addEventListener('click', function () { go('fm.html'); });

    $('btn-verify-credentials').addEventListener('click', onVerifyCredentials);
    $('btn-commit-voiceprint').addEventListener('click', onCommitVoiceprint);

    $('btn-decrypt-log').addEventListener('click', onDecryptLog);

    $('lcars-modal-close').addEventListener('click', closeModal);
    $('lcars-modal').addEventListener('click', function (e) {
      if (e.target === $('lcars-modal')) closeModal();
    });
  }

  /* ------------------------------------------------------------ bootstrap */
  function parseQuery() {
    var q = new URLSearchParams(window.location.search);
    var view = q.get('view');
    if (VIEWS[view]) state.initialView = view;
    state.fromFm = q.get('from') === 'fm';
    var path = q.get('path');
    if (path) state.recovery.path = path;
  }

  function showOffline() {
    document.body.classList.add('setup-mode');
    $('lcars-offline').classList.add('is-open');
    if (I18N) I18N.apply(document.body);
  }

  function init() {
    if (I18N) I18N.apply(document.body);

    if (!API) {
      showOffline();
      return;
    }

    parseQuery();
    $('btn-settings-fm').hidden = !state.fromFm;

    buildRecorders();
    wireEvents();
    syncLangButtons();

    // Mirror the backend language (source of truth) onto the interface. The
    // i18n module already restored the last language from localStorage for a
    // correct first paint; this reconciles it with the persisted setting.
    invoke('settings.get', {}).then(function (s) {
      if (s && s.language) applyLanguage(s.language, true);
    }, function () { /* keep the mirrored language */ });

    pollStatus(true);

    state.pollTimer = setInterval(function () { pollStatus(false); }, 3000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
