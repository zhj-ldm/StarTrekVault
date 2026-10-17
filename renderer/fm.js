'use strict';
/* ============================================================================
   STAR TREK VAULT - fm.js
   Controller for renderer/fm.html (the LCARS file manager).

   Everything goes through window.stvault (electron/preload.js):
     invoke(method, params)   -> Promise<result>   backend JSON-RPC
     micAuthorize()           -> Promise<boolean>
     pickFiles({path})        -> Promise<{ok,imported}>
     exportFile({path,file})  -> Promise<{ok}>
     dragBegin({path,file})   -> Promise<{ok,temp_path}>
     go(page)                 -> void

   The file table is deliberately not a shim: this page owns its own DOM and
   calls the vault VFS methods directly.
   ============================================================================ */
(function () {

  var API = window.stvault || null;
  var I18N = window.STV_I18N || null;

  function t(text, vars) {
    if (I18N) return I18N.t(text, vars);
    return String(text === null || text === undefined ? '' : text);
  }

  function $(id) { return document.getElementById(id); }

  function esc(value) {
    return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  /* ------------------------------------------------------------------ state */
  var state = {
    vaultPath: '',
    path: '',
    files: [],
    selected: [],
    sortBy: 'name',
    sortOrder: 'asc',
    clipboard: null,
    query: '',
    unlocked: false,
    busy: false
  };

  var SOUNDS = {
    chirp: 'snd-chirp', beep: 'snd-beep', warning: 'snd-warning',
    error: 'snd-error', verify: 'snd-verify'
  };

  function play(kind) {
    try {
      var el = $(SOUNDS[kind]);
      if (el) { el.currentTime = 0; el.play(); }
    } catch (e) { /* sound is cosmetic */ }
  }

  function invoke(method, params) {
    if (!API || typeof API.invoke !== 'function') {
      return Promise.reject(new Error('LCARS LINK OFFLINE'));
    }
    return API.invoke(method, params || {});
  }

  function fail(err) {
    showError((err && err.message) ? String(err.message) : 'LCARS LINK FAILURE');
    play('error');
  }

  function showError(message) {
    var el = $('fm-error');
    if (!el) return;
    el.textContent = String(message).toUpperCase();
    el.hidden = false;
  }

  function clearError() {
    var el = $('fm-error');
    if (!el) return;
    el.hidden = true;
    el.textContent = '';
  }

  /* ----------------------------------------------------------------- header */
  function baseName(p) {
    if (!p) return '--';
    var parts = String(p).split('/');
    return parts[parts.length - 1] || p;
  }

  function updateHeader() {
    $('hdr-vault').textContent = t('VAULT') + ': ' + baseName(state.vaultPath);
    $('hdr-items').textContent = t('ITEMS') + ': ' + state.files.length;
    $('hdr-selected').textContent = t('SELECTED') + ': ' + state.selected.length;
  }

  /* -------------------------------------------------------------- breadcrumb */
  function renderPathbar() {
    var html = '<button class="fm-crumb" data-path="" type="button">' + esc(t('VAULT')) + '</button>';
    var parts = state.path.replace(/\/$/, '').split('/');
    var acc = '';
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      acc += (acc ? '/' : '') + parts[i];
      html += '<span class="fm-sep">/</span>' +
        '<button class="fm-crumb" data-path="' + esc(acc + '/') + '" type="button">' + esc(parts[i]) + '</button>';
    }
    if (state.query) {
      html += '<span class="fm-sep">|</span><span>' + esc(t('SEARCH') + ': ' + state.query) + '</span>';
    }
    $('fm-pathbar').innerHTML = html;
  }

  function renderStatus() {
    var dirs = 0, files = 0;
    for (var i = 0; i < state.files.length; i++) {
      if (state.files[i].is_dir) dirs++; else files++;
    }
    var text = t('ITEMS') + ': ' + state.files.length +
      '  -  ' + t('DIR') + ': ' + dirs +
      '  -  ' + t('FILES') + ': ' + files +
      '  -  ' + t('SELECTED') + ': ' + state.selected.length;
    $('fm-status').textContent = text;
  }

  /* ------------------------------------------------------------------- table */
  function sortFiles() {
    var order = state.sortOrder === 'asc' ? 1 : -1;
    state.files.sort(function (a, b) {
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
      if (state.sortBy === 'size') return order * ((a.size || 0) - (b.size || 0));
      if (state.sortBy === 'type') {
        var ta = a.is_dir ? 'dir' : String(a.kind || '');
        var tb = b.is_dir ? 'dir' : String(b.kind || '');
        return order * ta.localeCompare(tb);
      }
      if (state.sortBy === 'modified') return order * String(a.modified || '').localeCompare(String(b.modified || ''));
      return order * String(a.name).localeCompare(String(b.name));
    });
  }

  function renderTable() {
    sortFiles();
    var tbody = $('fm-tbody');
    var heads = document.querySelectorAll('#fm-table thead th');
    for (var h = 0; h < heads.length; h++) {
      var base = t(heads[h].getAttribute('data-sort').toUpperCase());
      if (heads[h].getAttribute('data-sort') === state.sortBy) {
        base += ' ' + (state.sortOrder === 'asc' ? '\u25B2' : '\u25BC');
      }
      heads[h].textContent = base;
    }

    if (!state.files.length) {
      tbody.innerHTML = '';
      $('fm-empty').textContent = t('EMPTY DIRECTORY');
      $('fm-empty').hidden = false;
      updateHeader();
      renderStatus();
      return;
    }
    $('fm-empty').hidden = true;

    var html = '';
    for (var i = 0; i < state.files.length; i++) {
      var f = state.files[i];
      var sel = state.selected.indexOf(f.name) >= 0 ? ' is-selected' : '';
      html += '<tr class="' + sel + '" data-name="' + esc(f.name) + '" data-isdir="' + (f.is_dir ? 'true' : 'false') + '" draggable="true">' +
        '<td><span class="fm-row-name lcars-table__name">' + esc(f.name) + '</span></td>' +
        '<td class="lcars-table__mono">' + (f.is_dir ? '--' : formatSize(f.size)) + '</td>' +
        '<td>' + (f.is_dir ? t('DIR') : esc(String(f.kind || '').toUpperCase())) + '</td>' +
        '<td class="lcars-table__mono">' + esc(f.modified || '') + '</td>' +
        '</tr>';
    }
    tbody.innerHTML = html;
    updateHeader();
    renderStatus();
  }

  function formatSize(bytes) {
    var n = Number(bytes || 0);
    if (n <= 0) return '0 B';
    var k = 1024;
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(n) / Math.log(k));
    if (i >= units.length) i = units.length - 1;
    return parseFloat((n / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
  }

  /* ----------------------------------------------------------------- loading */
  function refresh() {
    state.query = '';
    return load(state.path);
  }

  function load(path) {
    state.busy = true;
    return invoke('vfs.list', { path: path }).then(function (res) {
      state.busy = false;
      state.path = path;
      state.files = (res && res.files) || [];
      state.selected = [];
      clearError();
      renderPathbar();
      renderTable();
    }, function (err) {
      state.busy = false;
      fail(err);
    });
  }

  function search(q) {
    return invoke('vfs.search', { path: state.path, q: q }).then(function (res) {
      state.files = (res && res.files) || [];
      state.selected = [];
      state.query = q;
      clearError();
      renderPathbar();
      renderTable();
      play('chirp');
    }, fail);
  }

  function navigate(path) {
    return load(path).then(function () { play('chirp'); });
  }

  function navigateUp() {
    if (!state.path) return;
    var parts = state.path.replace(/\/$/, '').split('/');
    parts.pop();
    var up = parts.join('/');
    if (up) up += '/';
    navigate(up);
  }

  function openRow(name) {
    var f = findByName(name);
    if (!f) return;
    if (f.is_dir) {
      navigate(state.path ? (state.path.replace(/\/$/, '') + '/' + f.name + '/') : (f.name + '/'));
    } else {
      preview(f.name);
    }
  }

  function findByName(name) {
    for (var i = 0; i < state.files.length; i++) {
      if (state.files[i].name === name) return state.files[i];
    }
    return null;
  }

  function selectRow(name, event) {
    var pos = state.selected.indexOf(name);
    if (event && (event.metaKey || event.ctrlKey)) {
      if (pos >= 0) state.selected.splice(pos, 1);
      else state.selected.push(name);
    } else if (pos >= 0 && state.selected.length === 1) {
      state.selected = [];
    } else {
      state.selected = [name];
    }
    renderTable();
    play('chirp');
  }

  function selectedEntries() {
    var out = [];
    for (var i = 0; i < state.selected.length; i++) {
      var f = findByName(state.selected[i]);
      if (f) out.push(f);
    }
    return out;
  }

  /* ------------------------------------------------------------------ export */
  function download(name) {
    if (!name || typeof API.exportFile !== 'function') { play('error'); return; }
    API.exportFile({ path: state.path, file: name }).then(function (r) {
      if (r && r.ok) play('chirp');
      else if (!r || !r.canceled) play('error');
    }, fail);
  }

  function downloadSelected() {
    var sel = selectedEntries();
    if (!sel.length) { play('error'); return; }
    for (var i = 0; i < sel.length; i++) {
      if (!sel[i].is_dir) download(sel[i].name);
    }
  }

  /* ------------------------------------------------------------------ upload */
  function upload() {
    if (typeof API.pickFiles !== 'function') { play('error'); return; }
    API.pickFiles({ path: state.path }).then(function (r) {
      if (!r || !r.ok) { if (!r || !r.canceled) play('error'); return; }
      play('chirp');
      refresh();
    }, fail);
  }

  /* -------------------------------------------------------------------- CRUD */
  function createDir() {
    openModal(t('NEW DIRECTORY'),
      '<input class="lcars-input" id="fm-modal-input" type="text" autocomplete="off" placeholder="' + esc(t('ENTER DIRECTORY NAME...')) + '">',
      [
        { label: t('CANCEL'), cls: 'lcars-btn--ghost', action: closeModal },
        { label: t('CREATE'), cls: '', action: function () {
          var name = ($('fm-modal-input').value || '').trim();
          closeModal();
          if (!name) return;
          invoke('vfs.mkdir', { path: state.path, name: name }).then(function () {
            play('chirp');
            refresh();
          }, fail);
        } }
      ]);
    play('chirp');
  }

  function rename() {
    var sel = selectedEntries();
    if (sel.length !== 1) { play('error'); alert(t('SELECT EXACTLY ONE ITEM TO RENAME.')); return; }
    var oldName = sel[0].name;
    openModal(t('RENAME'),
      '<input class="lcars-input" id="fm-modal-input" type="text" autocomplete="off" value="' + esc(oldName) + '">',
      [
        { label: t('CANCEL'), cls: 'lcars-btn--ghost', action: closeModal },
        { label: t('RENAME'), cls: '', action: function () {
          var newName = ($('fm-modal-input').value || '').trim();
          closeModal();
          if (!newName || newName === oldName) return;
          invoke('vfs.rename', { path: state.path, old_name: oldName, new_name: newName }).then(function () {
            play('chirp');
            refresh();
          }, fail);
        } }
      ]);
    play('warning');
  }

  function remove() {
    var sel = selectedEntries();
    if (!sel.length) { play('error'); alert(t('NO FILES SELECTED.')); return; }
    var names = [];
    var listHtml = '';
    for (var i = 0; i < sel.length; i++) {
      names.push(sel[i].name);
      listHtml += '<div class="lcars-table__mono">' + esc(sel[i].name) + '</div>';
    }
    openModal(t('CONFIRM DELETE'),
      listHtml + '<p class="lcars-p">' + esc(t('DELETE THESE {n} ITEM(S)?', { n: sel.length })) + '</p>',
      [
        { label: t('CANCEL'), cls: 'lcars-btn--ghost', action: closeModal },
        { label: t('DELETE'), cls: 'lcars-btn--red', action: function () {
          closeModal();
          invoke('vfs.delete', { path: state.path, names: names }).then(function () {
            play('chirp');
            refresh();
          }, fail);
        } }
      ]);
    play('warning');
  }

  function copy() {
    var sel = selectedEntries();
    if (!sel.length) { play('error'); return; }
    var names = [];
    for (var i = 0; i < sel.length; i++) names.push(sel[i].name);
    state.clipboard = { src: state.path, names: names };
    play('chirp');
    alert(t('COPIED {n} ITEM(S) TO CLIPBOARD.', { n: names.length }));
  }

  function paste() {
    if (!state.clipboard || !state.clipboard.names.length) { play('error'); alert(t('CLIPBOARD IS EMPTY.')); return; }
    if (state.clipboard.src === state.path) { play('error'); alert(t('CANNOT PASTE TO THE SAME DIRECTORY.')); return; }
    invoke('vfs.paste', {
      dest: state.path, src: state.clipboard.src, action_type: 'copy', names: state.clipboard.names
    }).then(function () {
      play('chirp');
      refresh();
    }, fail);
  }

  function searchPrompt() {
    openModal(t('SEARCH FILES'),
      '<input class="lcars-input" id="fm-modal-input" type="text" autocomplete="off" placeholder="' + esc(t('ENTER SEARCH TERM...')) + '">',
      [
        { label: t('CANCEL'), cls: 'lcars-btn--ghost', action: closeModal },
        { label: t('SEARCH'), cls: '', action: function () {
          var q = ($('fm-modal-input').value || '').trim();
          closeModal();
          if (q) search(q);
        } }
      ]);
    play('chirp');
  }

  function cycleSort() {
    var options = ['name', 'size', 'type', 'modified'];
    var idx = options.indexOf(state.sortBy);
    state.sortBy = options[(idx + 1) % options.length];
    state.sortOrder = 'asc';
    renderTable();
    play('beep');
  }

  function sortByColumn(col) {
    if (state.sortBy === col) state.sortOrder = state.sortOrder === 'asc' ? 'desc' : 'asc';
    else { state.sortBy = col; state.sortOrder = 'asc'; }
    renderTable();
    play('beep');
  }

  /* ----------------------------------------------------------------- preview */
  function preview(name) {
    invoke('vfs.read', { path: state.path, file: name }).then(function (r) {
      if (!r || !r.type) { download(name); return; }
      var title = t('PREVIEW') + ': ' + name;
      var body;
      if (r.type === 'image') {
        body = '<div class="lcars-table__mono"><img src="' + esc(r.url) + '" alt="' + esc(name) + '" style="max-width:100%;max-height:58vh"></div>';
      } else if (r.type === 'video') {
        body = '<div><video controls style="max-width:100%;max-height:58vh"><source src="' + esc(r.url) + '"></video></div>';
      } else if (r.type === 'audio') {
        body = '<div><audio controls style="width:100%"><source src="' + esc(r.url) + '"></audio></div>';
      } else if (r.text !== undefined) {
        body = '<pre class="fm-preview-text">' + esc(r.text) + (r.truncated ? '\n\n--- ' + esc(t('TRUNCATED - SHOWING FIRST 100KB')) + ' ---' : '') + '</pre>';
      } else {
        download(name);
        return;
      }
      openModal(title, body, [
        { label: t('CLOSE'), cls: 'lcars-btn--ghost', action: closeModal },
        { label: t('DOWNLOAD'), cls: '', action: function () { closeModal(); download(name); } }
      ]);
      play('chirp');
    }, function () { download(name); });
  }

  /* ------------------------------------------------------------------- modal */
  function openModal(title, bodyHtml, buttons) {
    $('fm-modal-title').textContent = title;
    $('fm-modal-body').innerHTML = bodyHtml + '<div class="lcars-actions" id="fm-modal-actions"></div>';
    var actions = $('fm-modal-actions');
    var list = buttons || [];
    for (var i = 0; i < list.length; i++) {
      (function (b) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'lcars-btn ' + (b.cls || '');
        btn.textContent = b.label;
        btn.addEventListener('click', function () { if (typeof b.action === 'function') b.action(); });
        actions.appendChild(btn);
      })(list[i]);
    }
    $('fm-modal').classList.add('is-open');
    var input = $('fm-modal-input');
    if (input) setTimeout(function () { input.focus(); if (input.select) input.select(); }, 60);
  }

  function closeModal() {
    $('fm-modal').classList.remove('is-open');
  }

  /* -------------------------------------------------------------------- lock */
  var unlockBusy = false;

  function lockStatus(msg) {
    $('lock-status').textContent = msg;
  }

  function lockError(msg, sound) {
    var el = $('lock-error');
    el.textContent = msg;
    el.hidden = false;
    play(sound || 'error');
  }

  function lockIdle() {
    unlockBusy = false;
    var input = $('lock-code');
    input.disabled = false;
    input.value = '';
    input.focus();
  }

  function denied(res) {
    var remaining = (res && typeof res.remaining === 'number') ? res.remaining : 0;
    var lockedUntil = (res && res.locked_until) ? res.locked_until : 0;
    if (lockedUntil) {
      lockError(t('LOCKED OUT - AUTHORIZATION SUSPENDED FOR 5 MINUTES'), 'error');
    } else if (remaining === 1) {
      lockError(t('VOICEPRINT MISMATCH - AUTHORIZATION DENIED - 1 ATTEMPT REMAINING'), 'warning');
    } else {
      lockError(t('VOICEPRINT MISMATCH - AUTHORIZATION DENIED - {n} ATTEMPTS REMAINING', { n: remaining }), 'error');
    }
    lockIdle();
  }

  function unlock() {
    if (unlockBusy) return;
    unlockBusy = true;
    var input = $('lock-code');
    input.disabled = true;
    $('lock-error').hidden = true;

    if (!API || typeof API.micAuthorize !== 'function') {
      lockError(t('LCARS LINK OFFLINE'), 'error');
      lockIdle();
      return;
    }

    lockStatus(t('REQUESTING MICROPHONE...'));
    API.micAuthorize().then(function (granted) {
      if (!granted) {
        lockError(t('MICROPHONE AUTHORIZATION DENIED - ALLOW ACCESS AND RETRY'), 'error');
        lockIdle();
        return null;
      }
      lockStatus(t('STANDBY - VOICE CODE REQUIRED'));
      // Echo gate: mute the analyser while the LCARS beep plays through speakers.
      return invoke('voice.playback', { active: true }).then(function () {
        play('beep');
        return new Promise(function (resolve) { setTimeout(resolve, 900); });
      }).then(function () {
        return invoke('voice.playback', { active: false });
      }).then(function () {
        lockStatus(t('LISTENING - SPEAK THE AUTHORIZATION CODE...'));
        return invoke('voice.listen_once', { max_secs: 12, silence_secs: 1.5, ignore_playback: true });
      });
    }).then(function (captured) {
      if (!captured) return null;
      var norm = String(captured.text_norm || captured.text || '').trim();
      var embedding = (captured.embedding && captured.embedding.length) ? captured.embedding : null;
      if (!norm || !embedding) {
        lockError(t('VOICE CODE NOT RECOGNIZED - SPEAK CLEARLY AND RETRY'), 'error');
        lockIdle();
        return null;
      }
      lockStatus(t('VERIFYING AUTHORIZATION...'));
      return invoke('vault.unlock', { passphrase_norm: norm, embedding: embedding }).then(function (res) {
        if (res && res.ok) {
          play('verify');
          state.unlocked = true;
          $('lock-overlay').hidden = true;
          lockIdle();
          refresh();
          return;
        }
        denied(res);
      });
    }).then(null, function (err) {
      lockError(String((err && err.message) ? err.message : t('AUTHORIZATION DENIED')).toUpperCase(), 'error');
      lockIdle();
    });
  }

  /* ---------------------------------------------------------------- drag out */
  function dragStart(e) {
    var tr = e.target && e.target.closest ? e.target.closest('tr') : null;
    if (!tr) return;
    var name = tr.getAttribute('data-name');
    if (!name) return;
    if (e.altKey || e.metaKey) {
      // Native drag to Finder: the main process decrypts to drag-tmp and calls
      // webContents.startDrag, then owns the lifetime of that plaintext.
      if (tr.getAttribute('data-isdir') === 'true') { e.preventDefault(); return; }
      e.preventDefault();
      e.stopPropagation();
      if (typeof API.dragBegin !== 'function') return;
      API.dragBegin({ path: state.path, file: name }).then(null, function () { play('error'); });
      return;
    }
    // Plain drag: move the row into a directory of the same container.
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', name);
    state.dragName = name;
  }

  function dragOver(e) {
    if (hasFiles(e.dataTransfer)) {
      e.preventDefault();
      try { e.dataTransfer.dropEffect = 'copy'; } catch (x) { /* ignore */ }
      var tr = e.target && e.target.closest ? e.target.closest('tr') : null;
      clearDropMarks();
      if (tr && tr.getAttribute('data-isdir') === 'true') tr.classList.add('is-drop');
      return;
    }
    if (!state.dragName) return;
    var row = e.target && e.target.closest ? e.target.closest('tr') : null;
    if (!row || row.getAttribute('data-isdir') !== 'true' || row.getAttribute('data-name') === state.dragName) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    clearDropMarks();
    row.classList.add('is-drop');
  }

  function clearDropMarks() {
    var rows = document.querySelectorAll('#fm-tbody tr.is-drop');
    for (var i = 0; i < rows.length; i++) rows[i].classList.remove('is-drop');
  }

  function hasFiles(dt) {
    if (!dt) return false;
    var types = dt.types;
    if (!types) return dt.files && dt.files.length > 0;
    for (var i = 0; i < types.length; i++) {
      if (types[i] === 'Files') return true;
    }
    return false;
  }

  function drop(e) {
    clearDropMarks();

    if (hasFiles(e.dataTransfer)) {
      e.preventDefault();
      e.stopPropagation();
      var sources = [];
      var dtFiles = e.dataTransfer.files;
      for (var i = 0; i < dtFiles.length; i++) {
        var f = dtFiles[i];
        if (f && f.path) sources.push(String(f.path));
      }
      var row = e.target && e.target.closest ? e.target.closest('tr') : null;
      var hovered = (row && row.getAttribute('data-isdir') === 'true') ? row.getAttribute('data-name') : null;
      var dest = hovered ? joinDir(state.path, hovered) : state.path;
      if (!sources.length) { play('error'); return; }
      invoke('vfs.import', { path: dest, sources: sources }).then(function () {
        play('chirp');
        refresh();
      }, fail);
      return;
    }

    // in-vault move onto a directory row
    if (!state.dragName) return;
    var target = e.target && e.target.closest ? e.target.closest('tr') : null;
    var srcName = state.dragName;
    state.dragName = null;
    if (!target || target.getAttribute('data-isdir') !== 'true') return;
    var destName = target.getAttribute('data-name');
    if (!destName || destName === srcName) return;
    e.preventDefault();
    invoke('vfs.move', {
      src_path: state.path, src_name: srcName, dest_path: joinDir(state.path, destName)
    }).then(function () {
      play('chirp');
      refresh();
    }, fail);
  }

  function dragEnd() {
    state.dragName = null;
    clearDropMarks();
  }

  function joinDir(base, dir) {
    return (base ? base.replace(/\/+$/, '') + '/' : '') + dir + '/';
  }

  /* ------------------------------------------------------------------- extras */
  function goView(view) {
    if (API && typeof API.go === 'function') API.go('app.html?view=' + view + '&from=fm');
  }

  function lockVault() {
    invoke('vault.lock', {}).then(function () {
      if (API && typeof API.go === 'function') API.go('app.html');
    }, function () {
      if (API && typeof API.go === 'function') API.go('app.html');
    });
  }

  /* -------------------------------------------------------------------- wire */
  function on(id, handler) {
    var el = $(id);
    if (el) el.addEventListener('click', handler);
  }

  function wireEvents() {
    on('nav-upload', upload);
    on('nav-download', downloadSelected);
    on('nav-refresh', function () { refresh(); play('chirp'); });
    on('nav-up', navigateUp);
    on('nav-mkdir', createDir);
    on('nav-delete', remove);
    on('nav-rename', rename);
    on('nav-copy', copy);
    on('nav-paste', paste);
    on('nav-search', searchPrompt);
    on('nav-sort', cycleSort);
    on('nav-settings', function () { goView('settings'); });
    on('nav-recovery', function () { goView('recovery'); });
    on('nav-audit', function () { goView('audit'); });
    on('nav-lock', lockVault);

    document.querySelectorAll('#fm-table thead th').forEach(function (th) {
      th.addEventListener('click', function () { sortByColumn(th.getAttribute('data-sort')); });
    });

    $('fm-tbody').addEventListener('click', function (e) {
      var tr = e.target.closest('tr');
      if (!tr) return;
      var name = tr.getAttribute('data-name');
      if (e.target.classList.contains('fm-row-name')) { openRow(name); play('chirp'); return; }
      selectRow(name, e);
    });
    $('fm-tbody').addEventListener('dblclick', function (e) {
      var tr = e.target.closest('tr');
      if (tr) openRow(tr.getAttribute('data-name'));
    });

    $('fm-pathbar').addEventListener('click', function (e) {
      var crumb = e.target.closest('.fm-crumb');
      if (!crumb) return;
      navigate(crumb.getAttribute('data-path') || '');
    });

    $('fm-modal-close').addEventListener('click', closeModal);
    $('fm-modal').addEventListener('click', function (e) {
      if (e.target === $('fm-modal')) closeModal();
    });

    $('lock-verify').addEventListener('click', unlock);
    $('lock-code').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') unlock();
    });

    $('fm-tbody').addEventListener('dragstart', dragStart);
    $('fm-tbody').addEventListener('dragend', dragEnd);
    $('fm-tbody').addEventListener('dragover', dragOver);
    $('fm-tbody').addEventListener('dragleave', clearDropMarks);
    $('fm-tbody').addEventListener('drop', drop);
    document.addEventListener('dragover', function (e) {
      // Finder drag over empty areas of the page: keep the drop legal.
      if (hasFiles(e.dataTransfer)) { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; }
    });
    document.addEventListener('drop', function (e) {
      if (hasFiles(e.dataTransfer)) drop(e);
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeModal();
    });
    window.addEventListener('dragend', dragEnd);
  }

  /* --------------------------------------------------------------- bootstrap */
  function showOffline() {
    $('lcars-offline').classList.add('is-open');
    $('lock-overlay').hidden = true;
    if (I18N) I18N.apply(document.body);
  }

  function boot() {
    if (I18N) I18N.apply(document.body);

    if (!API) { showOffline(); return; }
    wireEvents();

    var q = new URLSearchParams(window.location.search);
    state.vaultPath = q.get('path') || '';
    if (state.vaultPath) invoke('vault.select', { path: state.vaultPath });

    if (I18N && typeof I18N.onChange === 'function') {
      I18N.onChange(function () { renderPathbar(); renderTable(); });
    }

    invoke('settings.get', {}).then(function (s) {
      if (s && s.language && I18N) I18N.setLang(s.language, { mirror: false });
    }, function () { /* keep mirrored language */ });

    updateHeader();
    renderPathbar();
    renderStatus();
    play('chirp');
    setTimeout(function () { $('lock-code').focus(); }, 80);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})();
