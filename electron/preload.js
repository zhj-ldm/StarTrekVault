'use strict';
/* ============================================================================
   STAR TREK VAULT - preload

   Exposes the minimal renderer API through contextBridge as `window.stvault`.
   renderer/app.html and renderer/fm.html are both first-party LCARS pages and
   call these methods directly; no main-world injection is performed.

   window.stvault:
     invoke(method, params)   -> Promise<result>      backend JSON-RPC
     micAuthorize()           -> Promise<boolean>     macOS microphone consent
     pickVaultPath(name)      -> Promise<string|null> save dialog for .stvault
     pickStvaultFile()        -> Promise<{canceled,path?,dest_dir?}> open dialog to import a .stvault
     pickFiles({path})        -> Promise<{ok,imported}> open dialog + vfs.import
     exportFile({path,file})  -> Promise<{ok}>        save dialog + vfs.export
     dragBegin({path,file})   -> Promise<{temp_path}> decrypt + startDrag
     releaseTemp(temp)        -> Promise<{ok}>        3-pass wipe of drag temp
     go(page)                 -> void                 navigate this window
   ============================================================================ */

const { contextBridge, ipcRenderer, webFrame } = require('electron');
const fs = require('fs');
const path = require('path');

const invoke = (channel, payload) => ipcRenderer.invoke(channel, payload);

contextBridge.exposeInMainWorld('stvault', {
  invoke: (method, params) => invoke('stvault:rpc', { method: String(method || ''), params: params || {} }),
  micAuthorize: () => invoke('stvault:mic-authorize', {}),
  pickVaultPath: (name) => invoke('stvault:pick-vault-path', { name: String(name || '') }),
  pickStvaultFile: () => invoke('stvault:pick-stvault-file', {}),
  pickFiles: (payload) => invoke('stvault:pick-files', payload || {}),
  exportFile: (payload) => invoke('stvault:export-file', payload || {}),
  dragBegin: (payload) => invoke('stvault:drag-begin', payload || {}),
  releaseTemp: (tempPath) => invoke('stvault:release-temp', { temp_path: String(tempPath || '') }),
  go: (page) => ipcRenderer.send('stvault:go', String(page || 'app.html'))
});

/* ---------------------------------------------------------------------------
   renderer/fm.html is the user's own LCARSDE file manager, kept untouched. It
   expects a PHP endpoint behind `?action=...` XHR calls, so inject fm-bridge.js
   into the page's main world where it can re-point that traffic at the vault
   backend. app.html is a first-party page and needs no shim.
--------------------------------------------------------------------------- */

function injectFmBridge() {
  const bridge = path.join(__dirname, 'fm-bridge.js');
  if (!fs.existsSync(bridge)) return;
  webFrame.executeJavaScript(fs.readFileSync(bridge, 'utf8'));
}

if (process.isMainFrame) {
  injectFmBridge();
}

