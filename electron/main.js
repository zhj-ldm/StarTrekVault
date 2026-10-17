'use strict';
/* ============================================================================
   STAR TREK VAULT - electron main process

   - spawns the single Rust binary `stvault-backend` (JSON-RPC over stdio)
   - serves decrypted media through the custom `stvault://media?...` protocol
   - owns the plaintext drag-out temp files in <data-dir>/drag-tmp/
   - microphone consent (macOS) and the renderer permission handler
   ============================================================================ */

const { app, BrowserWindow, ipcMain, dialog, protocol, session, nativeImage, systemPreferences } = require('electron');
const { spawn } = require('child_process');
const readline = require('readline');
const path = require('path');
const fs = require('fs');

app.setName('StarTrekVault');

const DEV = !app.isPackaged;
const RES_ROOT = DEV ? path.join(__dirname, '..', 'resources') : process.resourcesPath;
const RENDERER_DIR = path.join(__dirname, '..', 'renderer');
const DRAG_ICON = path.join(RES_ROOT, 'assets', 'drag-icon.png');
const DRAG_HOLD_MS = 90000; // grace before temp plaintext is wiped after blur

const backendCandidates = [
  path.join(RES_ROOT, 'bin', 'stvault-backend'),
  path.join(__dirname, '..', 'backend', 'target', 'release', 'stvault-backend')
];

const MIME = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', bmp: 'image/bmp', svg: 'image/svg+xml', heic: 'image/heic',
  mp4: 'video/mp4', mov: 'video/quicktime', webm: 'video/webm', mkv: 'video/x-matroska',
  mp3: 'audio/mpeg', wav: 'audio/wav', m4a: 'audio/mp4', aac: 'audio/aac', flac: 'audio/flac',
  ogg: 'audio/ogg', pdf: 'application/pdf', txt: 'text/plain'
};

/* ------------------------------------------------------------------- backend */

class Backend {
  constructor() {
    this.proc = null;
    this.seq = 0;
    this.pending = new Map();
    this.dead = false;
  }

  binPath() {
    for (const p of backendCandidates) {
      if (fs.existsSync(p)) return p;
    }
    return null;
  }

  start(dataDir) {
    const bin = this.binPath();
    if (!bin) throw new Error('backend binary not found: run tools/build.sh first');

    this.proc = spawn(bin, ['--root', RES_ROOT, '--data-dir', dataDir], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    const stdout = readline.createInterface({ input: this.proc.stdout });
    stdout.on('line', (line) => this.onLine(line));

    readline.createInterface({ input: this.proc.stderr }).on('line', (line) => {
      console.log('[backend]', line);
    });

    this.proc.on('exit', (code) => {
      console.error('[backend] exited with', code);
      if (this.dead) return;
      this.dead = true;
      for (const [, entry] of this.pending) entry.reject(new Error('LCARS LINK OFFLINE'));
      this.pending.clear();
      if (!app.isQuitting) {
        dialog.showErrorBox('LCARS LINK FAILURE', 'The vault backend stopped unexpectedly. The application will now close.');
        app.quit();
      }
    });
  }

  onLine(line) {
    const text = String(line).trim();
    if (!text) return;
    let msg;
    try {
      msg = JSON.parse(text);
    } catch (err) {
      console.error('[backend] unparsable output:', text.slice(0, 200));
      return;
    }
    const entry = this.pending.get(msg.id);
    if (!entry) return;
    this.pending.delete(msg.id);
    if (msg.error && msg.error.message) entry.reject(new Error(String(msg.error.message)));
    else entry.resolve(msg.result === undefined ? {} : msg.result);
  }

  request(method, params) {
    if (!this.proc || this.dead) return Promise.reject(new Error('LCARS LINK OFFLINE'));
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        this.proc.stdin.write(JSON.stringify({ id, method, params: params || {} }) + '\n');
      } catch (err) {
        this.pending.delete(id);
        reject(new Error('LCARS LINK OFFLINE'));
      }
    });
  }

  stop() {
    this.dead = true;
    if (this.proc) {
      try { this.proc.stdin.end(); } catch (err) { /* already gone */ }
      const victim = this.proc;
      setTimeout(() => { try { victim.kill('SIGKILL'); } catch (err) { /* gone */ } }, 400);
    }
  }
}

const backend = new Backend();

/* ------------------------------------------------------------ drag temp files */

let tempFiles = new Set();
let tempTimer = null;

async function releaseTemps() {
  if (tempTimer) { clearTimeout(tempTimer); tempTimer = null; }
  const list = Array.from(tempFiles);
  tempFiles = new Set();
  for (const t of list) {
    try {
      await backend.request('vfs.release_temp', { temp_path: t });
    } catch (err) {
      /* best effort: the backend purges drag-tmp on start/lock/exit anyway */
    }
  }
}

function holdTemps() {
  // Window lost focus: a drag to Finder may still be in flight, so wipe later.
  if (!tempFiles.size) return;
  if (tempTimer) clearTimeout(tempTimer);
  tempTimer = setTimeout(releaseTemps, DRAG_HOLD_MS);
}

/* ----------------------------------------------------------------- window */

let win = null;
let currentPage = 'app.html';

function pagePath(page) {
  const raw = String(page || 'app.html');
  const [file, query] = raw.split('?');
  const safe = path.basename(file); // never allow directory escapes
  return { file: path.join(RENDERER_DIR, safe), query: query || '' };
}

function loadPage(page) {
  currentPage = String(page || 'app.html');
  const { file, query } = pagePath(currentPage);
  if (!win) return;
  if (query) {
    win.loadFile(file, { query: Object.fromEntries(new URLSearchParams(query)) });
  } else {
    win.loadFile(file);
  }
}

function createWindow() {
  const icon = fs.existsSync(DRAG_ICON) ? nativeImage.createFromPath(DRAG_ICON) : undefined;
  win = new BrowserWindow({
    width: 1180,
    height: 800,
    minWidth: 900,
    minHeight: 620,
    backgroundColor: '#000000',
    title: 'STAR TREK VAULT',
    show: false,
    ...(icon && !icon.isEmpty() ? { icon } : {}),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      spellcheck: false
    }
  });

  win.once('ready-to-show', () => win.show());
  win.on('blur', holdTemps);
  win.on('focus', () => { releaseTemps(); });
  win.on('closed', () => { win = null; });

  // Keep navigation inside the renderer directory (both pages are local).
  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) event.preventDefault();
  });

  loadPage(currentPage);
}

/* ------------------------------------------------------------------ protocol */

protocol.registerSchemesAsPrivileged([
  {
    scheme: 'stvault',
    privileges: { standard: true, secure: true, supportFetchAPI: true, stream: true, bypassCSP: true }
  }
]);

function mimeFor(name) {
  const ext = String(name).split('.').pop().toLowerCase();
  return MIME[ext] || 'application/octet-stream';
}

/* ------------------------------------------------------------------- app flow */

app.whenReady().then(() => {
  const dataDir = app.getPath('userData');
  fs.mkdirSync(path.join(dataDir, 'drag-tmp'), { recursive: true });

  try {
    backend.start(dataDir);
  } catch (err) {
    dialog.showErrorBox('BACKEND UNAVAILABLE', String(err && err.message));
    app.quit();
    return;
  }

  // Decrypted media for <img>/<video>/<audio> previews.
  protocol.handle('stvault', async (request) => {
    try {
      const url = new URL(request.url);
      const dir = url.searchParams.get('path') || '';
      const file = url.searchParams.get('file') || '';
      const res = await backend.request('vfs.media', { path: dir, file });
      const buf = Buffer.from(String(res.b64 || ''), 'base64');
      return new Response(buf, {
        status: 200,
        headers: { 'Content-Type': mimeFor(file), 'Cache-Control': 'no-store' }
      });
    } catch (err) {
      return new Response('', { status: 404 });
    }
  });

  const ses = session.defaultSession;
  ses.setPermissionRequestHandler((wc, permission, callback) => {
    callback(permission === 'media' || permission === 'microphone' || permission === 'audioCapture');
  });
  ses.setPermissionCheckHandler((wc, permission) => (
    permission === 'media' || permission === 'microphone' || permission === 'audioCapture'
  ));

  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => app.quit());

app.on('before-quit', (event) => {
  if (app.isQuitting) return;
  app.isQuitting = true;
  event.preventDefault();
  (async () => {
    await releaseTemps();
    try { await backend.request('vault.lock', {}); } catch (err) { /* locking out */ }
    backend.stop();
    app.quit();
  })();
});

/* ---------------------------------------------------------------------- IPC */

/* Default container store: <Documents>/startrek vault (created on demand). */
function vaultsHome() {
  const dir = path.join(app.getPath('documents'), 'startrek vault');
  try { fs.mkdirSync(dir, { recursive: true }); } catch (e) { /* best effort */ }
  return dir;
}

ipcMain.handle('stvault:rpc', (event, payload) => {
  const method = payload && payload.method ? String(payload.method) : '';
  const params = (payload && payload.params) || {};
  return backend.request(method, params);
});

ipcMain.handle('stvault:mic-authorize', async () => {
  if (process.platform === 'darwin' && systemPreferences.askForMediaAccess) {
    try {
      return await systemPreferences.askForMediaAccess('microphone');
    } catch (err) {
      return false;
    }
  }
  return true;
});

ipcMain.handle('stvault:pick-vault-path', async (event, payload) => {
  const name = (payload && payload.name) ? String(payload.name) : 'VAULT.stvault';
  const result = await dialog.showSaveDialog(win, {
    title: 'CREATE VAULT CONTAINER',
    defaultPath: path.join(vaultsHome(), name),
    filters: [{ name: 'Star Trek Vault', extensions: ['stvault'] }],
    properties: ['createDirectory']
  });
  return result.canceled || !result.filePath ? null : result.filePath;
});

ipcMain.handle('stvault:pick-stvault-file', async () => {
  const result = await dialog.showOpenDialog(win, {
    title: 'IMPORT VAULT CONTAINER',
    defaultPath: vaultsHome(),
    properties: ['openFile'],
    filters: [{ name: 'Star Trek Vault', extensions: ['stvault'] }]
  });
  if (result.canceled || !result.filePaths || !result.filePaths.length) {
    return { canceled: true };
  }
  return { canceled: false, path: result.filePaths[0], dest_dir: vaultsHome() };
});

ipcMain.handle('stvault:pick-files', async (event, payload) => {
  const dir = (payload && payload.path) ? String(payload.path) : '';
  const result = await dialog.showOpenDialog(win, {
    title: 'IMPORT INTO VAULT',
    properties: ['openFile', 'multiSelections']
  });
  if (result.canceled || !result.filePaths || !result.filePaths.length) {
    return { ok: false, canceled: true };
  }
  return backend.request('vfs.import', { path: dir, sources: result.filePaths });
});

ipcMain.handle('stvault:export-file', async (event, payload) => {
  const dir = (payload && payload.path) ? String(payload.path) : '';
  const file = (payload && payload.file) ? String(payload.file) : '';
  if (!file) return { ok: false };
  const result = await dialog.showSaveDialog(win, {
    title: 'EXPORT FROM VAULT',
    defaultPath: path.join(app.getPath('downloads'), path.basename(file)),
    properties: ['createDirectory']
  });
  if (result.canceled || !result.filePath) return { ok: false, canceled: true };
  return backend.request('vfs.export', { path: dir, file, dest: result.filePath });
});

ipcMain.handle('stvault:drag-begin', async (event, payload) => {
  const dir = (payload && payload.path) ? String(payload.path) : '';
  const file = (payload && payload.file) ? String(payload.file) : '';
  if (!file || !win) return { ok: false };
  const res = await backend.request('vfs.prepare_drag', { path: dir, file });
  if (!res || !res.temp_path) return { ok: false };
  const tempPath = String(res.temp_path);
  tempFiles.add(tempPath);

  let icon = nativeImage.createEmpty();
  try {
    if (fs.existsSync(DRAG_ICON)) icon = nativeImage.createFromPath(DRAG_ICON);
  } catch (err) { /* icon is cosmetic */ }

  const dragItem = { file: tempPath };
  if (!icon.isEmpty()) dragItem.icon = icon;
  win.webContents.startDrag(dragItem);
  return { ok: true, temp_path: tempPath };
});

ipcMain.handle('stvault:release-temp', async (event, payload) => {
  const t = (payload && payload.temp_path) ? String(payload.temp_path) : '';
  if (!t) return { ok: false };
  tempFiles.delete(t);
  try {
    return await backend.request('vfs.release_temp', { temp_path: t });
  } catch (err) {
    return { ok: false };
  }
});

ipcMain.on('stvault:go', (event, page) => {
  loadPage(page);
});
