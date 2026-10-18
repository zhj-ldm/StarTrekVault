/* ============================================================================
   STAR TREK VAULT - i18n.js

   Tiny English->Chinese dictionary shared by renderer/app.html and
   renderer/fm.html.

   Design:
     - English source text is the key. ZH maps English -> Chinese.
     - EN is the auto-built reverse map (Chinese -> English) so a text node can
       always be normalised back to its source language.
     - t(text, vars)   translate a JS-composed string (used by app.js).
     - apply(root)     walk text nodes + placeholder/title attributes of an
                       already-rendered DOM subtree and swap language in place.
     - getLang()/setLang(lang)/onChange(cb)
     - Language is mirrored to localStorage for a correct first paint; the
       backend settings.json remains the source of truth (see app.js).

   Default language is English.
   ============================================================================ */
(function () {
  'use strict';

  if (window.STV_I18N) return;

  var STORAGE_KEY = 'stvault.lang';
  var DEFAULT_LANG = 'en';

  /* --------------------------------------------------------------- dictionary */
  // English source -> Chinese. Keep every Chinese value unique so the reverse
  // map stays unambiguous.
  var ZH = {
    /* header / status */
    'MIC': '麦克风',
    'VOICE': '语音',
    'VAULT': '保险箱',
    'OK': '正常',
    'DOWN': '离线',
    'READY': '就绪',
    'OPEN': '已开启',
    'LOCKED': '已锁定',
    'LOCKED OUT': '锁定中',
    'MIN': '分钟',
    'UNKNOWN': '未知',

    /* nav */
    'VAULT LIST': '保险箱列表',
    'CREATE VAULT': '创建保险箱',
    'SETTINGS': '设置',
    'AUDIT LOG': '审计日志',
    'FILE MANAGER': '文件管理器',
    'RECOVERY': '恢复',
    'AUDIT': '审计',
    'LOCK': '锁定',

    /* setup */
    'SECURITY GRID INITIALIZATION': '安全网格初始化',
    'AUTHORIZATION REQUIRED': '需要授权',
    'FIRST LAUNCH DETECTED. DEFINE THE SECURITY QUESTION, ITS ANSWER AND THE STATIC MASTER PASSWORD. THESE FACTORS SEAL THE GLOBAL CONFIGURATION AND CANNOT BE RECOVERED IF LOST.': '检测到首次启动。请设定安全问题、答案与静态主密码。这些要素将封存全局配置，一旦丢失将无法恢复。',
    'SECURITY QUESTION': '安全问题',
    'ANSWER': '答案',
    'MASTER PASSWORD': '主密码',
    'CONFIRM MASTER PASSWORD': '确认主密码',
    'ENTER SECURITY QUESTION': '输入安全问题',
    'ENTER ANSWER': '输入答案',
    'ENTER MASTER PASSWORD': '输入主密码',
    'RE-ENTER MASTER PASSWORD': '再次输入主密码',
    'INITIALIZE SECURITY GRID': '初始化安全网格',

    /* vault list */
    'CREATE NEW VAULT': '创建新保险箱',
    'IMPORT VAULT': '导入保险箱',
    'IMPORTING...': '导入中...',
    'REFRESH': '刷新',
    'SCANNING...': '扫描中...',
    'NAME': '名称',
    'SIZE': '大小',
    'CREATED': '创建时间',
    'STATUS': '状态',
    'ACTIONS': '操作',
    'NO VAULT CONTAINERS REGISTERED': '未注册任何保险箱容器',
    'UNLOCK': '解锁',
    'DELETE': '删除',
    '(UNNAMED)': '(未命名)',
    'ERASING...': '抹除中...',

    /* create vault */
    'CONTAINER': '容器',
    'VAULT NAME': '保险箱名称',
    'ENTER VAULT NAME': '输入保险箱名称',
    'CONTAINER PATH': '容器路径',
    'NO LOCATION CHOSEN': '未选择位置',
    'CHOOSE LOCATION': '选择位置',
    'VOICEPRINT ENROLMENT': '声纹录入',
    'MASTER CREDENTIALS': '管理员凭证',
    'THE RECOVERY WRAP OF EVERY CONTAINER IS SEALED WITH THE SECURITY ANSWER AND THE STATIC MASTER PASSWORD. SUPPLY THEM TO AUTHORISE CREATION.': '每个容器的恢复包装包都由安全答案与静态主密码封存。请提供它们以授权创建。',
    'ENTER SECURITY ANSWER': '输入安全答案',
    'SPEAK THE SAME AUTHORIZATION CODE TWO OR THREE TIMES. EVERY ACCEPTED TAKE IS COMBINED INTO THE VOICEPRINT TEMPLATE AND ALL TAKES MUST MATCH.': '请将同一授权口令朗读两到三遍。每一段被接受的录音都会参与合成声纹模板，且所有录音必须相互匹配。',
    'TOUCH ID - SECOND FACTOR': '指纹识别 - 第二层验证',
    'WHEN ENABLED, UNLOCKING REQUIRES TOUCH ID AFTER THE VOICEPRINT CHECK. TOUCH ID CANNOT BE USED ALONE - VOICEPRINT IS ALWAYS REQUIRED.': '开启后，解锁时需在声纹校验通过后再通过 Touch ID。不可单独使用 Touch ID，声纹始终必需。',
    'REQUIRE TOUCH ID': '要求指纹识别',
    'TOUCH ID NOT AVAILABLE ON THIS DEVICE': '本设备不支持指纹识别',
    'TOUCH ID UNAVAILABLE - USE RECOVERY ACCESS': '指纹识别不可用 - 请使用恢复访问',
    'TOUCH ID DENIED': '指纹识别被拒绝',
    'TOUCH ID REQUIRED...': '需要指纹识别...',
    'UNLOCK VAULT': '解锁保险箱',

    /* unlock step indicator (fm.html lock screen) */
    'VOICE PASSPHRASE': '语音口令',
    'SPEAK THE DIGITS': '朗读数字',
    'TOUCH ID': '指纹识别',
    'RECORD DIGITS': '录制数字',
    'STEP 2 - READ THE DIGITS ABOVE ALOUD': '第 2 步 - 请朗读上方显示的数字',
    'LISTENING - READ THE DIGITS ALOUD...': '正在聆听 - 请朗读数字...',
    'VERIFYING DIGITS...': '正在验证数字...',
    'VOICEPRINT MISMATCH': '声纹不匹配',
    'DIGITS DID NOT MATCH - READ THE NEW CODE': '数字不匹配 - 请朗读新的数字',
    'STANDBY': '待机',
    'NO TAKE RECORDED': '未录制任何录音',
    'TAKE 1 / 3 · ACCEPTED 0': '第 1 / 3 段 · 已接受 0',
    'RECORD AUTHORIZATION CODE': '录制授权口令',
    'RECORD AGAIN': '重新录制',
    'ACCEPT TAKE': '接受此段',
    'RETURN TO VAULT LIST': '返回保险箱列表',

    /* settings */
    'LANGUAGE': '语言',
    'SELECT INTERFACE LANGUAGE. DEFAULT IS ENGLISH.': '选择界面语言。默认英文。',
    'ENGLISH': '英文',
    'AUTO-LOCK ON IDLE': '空闲自动上锁',
    'WHEN ENABLED, THE VAULT AUTOMATICALLY LOCKS AND RETURNS TO THE MAIN PAGE AFTER THE SET NUMBER OF MINUTES WITHOUT ANY ACTIVITY.': '开启后，无任何操作达到设定分钟数时，保险箱会自动上锁并返回主页面。',
    'ENABLE AUTO-LOCK': '启用自动上锁',
    'IDLE MINUTES (1 - 240)': '空闲分钟数（1 - 240）',
    'VOICEPRINT MATCH THRESHOLD': '声纹匹配阈值',
    'SIMILARITY THRESHOLD USED FOR VOICEPRINT VERIFICATION. VALID RANGE 0.40 TO 0.90.': '用于声纹验证的相似度阈值。有效范围 0.40 至 0.90。',
    'APPLY': '应用',
    'APPLYING...': '应用中...',
    'RECOVERY AND DESTRUCTION': '恢复与销毁',
    'RECOVERY ACCESS CLEARS THE OLD VOICEPRINT TEMPLATE AND RE-ENROLS A NEW ONE, PRESERVING ALL STORED FILE DATA. SYSTEM WIPE IRREVERSIBLY DESTROYS EVERY CONTAINER, THE GLOBAL CONFIGURATION AND THE AUDIT LOG.': '恢复访问会清除旧声纹模板并重新录入一份新模板，同时保留全部已存储的文件数据。系统擦除将不可逆地销毁所有容器、全局配置与审计日志。',
    'RECOVERY ACCESS': '恢复访问',
    'SYSTEM WIPE': '系统擦除',
    'RETURN TO FILE MANAGER': '返回文件管理器',
    'WIPING...': '擦除中...',

    /* recovery */
    'DUAL FACTOR AUTHORIZATION REQUIRED': '需要双因素授权',
    'CREDENTIALS': '凭证',
    'VAULT PATH': '保险箱路径',
    'SECURITY ANSWER': '安全答案',
    'VERIFY CREDENTIALS': '验证凭证',
    'VOICEPRINT RE-ENROLMENT': '声纹重新录入',
    'THE OLD VOICEPRINT TEMPLATE IS CLEARED AND REPLACED. FILE DATA IS PRESERVED. SPEAK THE AUTHORIZATION CODE TWO OR THREE TIMES.': '旧声纹模板将被清除并替换，文件数据予以保留。请将授权口令朗读两到三遍。',
    'COMMIT NEW VOICEPRINT': '提交新声纹',
    'DERIVING KEYS...': '派生密钥中...',
    'SECURITY QUESTION: NOT VERIFIED': '安全问题：未验证',
    'SECURITY QUESTION:': '安全问题：',
    'UNAVAILABLE': '不可用',
    'VOICEPRINT RE-ENROLLED - FILE DATA PRESERVED': '声纹已重新录入 - 文件数据已保留',

    /* audit */
    'THE AUDIT LOG IS SEALED WITH THE MASTER PASSWORD. SUPPLY IT TO DECRYPT AND VERIFY THE HASH CHAIN.': '审计日志由主密码封存。请输入主密码以解密并校验哈希链。',
    'DECRYPT LOG': '解密日志',
    'TIME': '时间',
    'EVENT': '事件',
    'DETAIL': '详情',
    'HASH': '哈希',
    'NO AUDIT ENTRIES': '无审计条目',

    /* footer / modal / offline */
    'STARFLEET VAULT SUBSYSTEM — LCARS INTERFACE': '星际舰队保险箱子系统 — LCARS 界面',
    'CONFIRM': '确认',
    'CANCEL': '取消',
    'LCARS LINK OFFLINE': 'LCARS 链路离线',
    'THE VAULT INTERFACE IS UNAVAILABLE OUTSIDE THE STAR TREK VAULT SHELL.': '保险箱界面仅在星际迷航保险箱外壳内可用。',

    /* recorder */
    'TAKE': '段',
    'TAKE {n} / {m} · ACCEPTED {k}': '第 {n} / {m} 段 · 已接受 {k}',
    'TAKE {n}: {text}': '第 {n} 段：{text}',
    '(UNRECOGNIZED)': '(未识别)',
    'ACCEPTED:': '已接受：',
    'ACCEPTED': '已接受',
    'VOICEPRINT CAPTURE FAILED': '声纹采集失败',
    'REQUESTING MICROPHONE...': '正在请求麦克风...',
    'LISTENING...': '正在聆听...',
    'MICROPHONE AUTHORIZATION DENIED': '麦克风授权被拒绝',
    'NO SPEECH RECOGNIZED': '未识别到语音',
    'TAKE CAPTURED - REVIEW AND ACCEPT': '已录取 - 请审阅并接受',
    'RECORDING FAILED': '录制失败',
    'ENROLMENT COMPLETE': '录入完成',
    'TAKE ACCEPTED - RECORD NEXT TAKE': '已接受此段 - 请录制下一段',

    /* validation / backend errors */
    'UNKNOWN FAILURE': '未知故障',
    'ALL FIELDS ARE REQUIRED': '所有字段均为必填',
    'MASTER PASSWORDS DO NOT MATCH': '两次主密码不一致',
    'VAULT NAME IS REQUIRED': '保险箱名称为必填',
    'CONTAINER PATH IS REQUIRED - USE CHOOSE LOCATION': '容器路径为必填 - 请使用“选择位置”',
    'TWO OR THREE ACCEPTED TAKES ARE REQUIRED': '需要接受两到三段录音',
    'PATH, SECURITY ANSWER AND MASTER PASSWORD ARE REQUIRED': '路径、安全答案与主密码均为必填',
    'VERIFY CREDENTIALS FIRST': '请先验证凭证',
    'MASTER PASSWORD IS REQUIRED': '主密码为必填',
    'AUTHORIZATION DENIED': '授权被拒绝',
    'VAULT NOT UNLOCKED': '保险箱未解锁',
    'MASTER PASSWORD REJECTED': '主密码被拒绝',

    /* confirmation dialogs */
    'DELETE VAULT': '删除保险箱',
    'THE CONTAINER "{name}" WILL BE OVERWRITTEN THREE TIMES AND REMOVED. THIS CANNOT BE UNDONE. PROCEED?': '容器“{name}”将被覆写三次并移除，且无法撤销。是否继续？',
    /* four-step vault deletion confirmation */
    'DELETE VAULT - CONFIRMATION {n} OF {m}': '删除保险箱 - 第 {n} 次确认（共 {m} 次）',
    'CONFIRM {n}/{m}': '确认 {n}/{m}',
    'CONFIRMATION {n} OF {m}. THE CONTAINER "{name}" WILL BE OVERWRITTEN THREE TIMES AND PERMANENTLY REMOVED. THIS CANNOT BE UNDONE. {left} MORE CONFIRMATION(S) STILL REQUIRED AFTER THIS.': '第 {n} 次确认（共 {m} 次）。容器“{name}”将被覆写三次并永久移除，且无法撤销。本次确认后，仍需再确认 {left} 次。',
    'FINAL CONFIRMATION. THE CONTAINER "{name}" WILL NOW BE OVERWRITTEN THREE TIMES AND PERMANENTLY REMOVED. THIS CANNOT BE UNDONE. PROCEED?': '最终确认。容器“{name}”将被覆写三次并永久移除，且无法撤销。是否继续？',
    'EXECUTE WIPE': '执行擦除',
    'SYSTEM WIPE IRREVERSIBLY DESTROYS EVERY VAULT CONTAINER, THE GLOBAL CONFIGURATION AND THE AUDIT LOG. THREE PASS OVERWRITE RUNS FIRST. THIS CANNOT BE UNDONE. PROCEED?': '系统擦除将不可逆地销毁所有保险箱容器、全局配置与审计日志，并先执行三遍覆写。无法撤销。是否继续？',

    /* file manager (renderer/fm.html + renderer/fm.js) */
    'UPLOAD': '上传',
    'DOWNLOAD': '下载',
    'IMPORT': '导入',
    'EXPORT': '导出',
    'UP': '上级',
    'BACK': '返回',
    'NEW DIRECTORY': '新建目录',
    'NEW FOLDER': '新建文件夹',
    'NEW FILE': '新建文件',
    'SAVE': '保存',
    'CUT': '剪切',
    'RENAME': '重命名',
    'COPY': '复制',
    'PASTE': '粘贴',
    'SEARCH': '搜索',
    'SORT': '排序',
    'RECORD': '录制',
    'END': '结束',
    'END & VERIFY': '结束并验证',
    'VERIFYING AUTHORIZATION...': '正在验证授权...',
    'LISTENING - SPEAK THE AUTHORIZATION CODE...': '正在聆听 - 请朗读授权口令...',
    'LOCK VAULT': '锁定保险箱',
    'ITEMS': '项目',
    'SELECTED': '已选',
    'DIR': '目录',
    'FILES': '文件',
    'TYPE': '类型',
    'MODIFIED': '修改时间',
    'EMPTY DIRECTORY': '空目录',
    'CREATE': '创建',
    'CLOSE': '关闭',
    'PREVIEW': '预览',
    'TRUNCATED - SHOWING FIRST 100KB': '已截断 - 仅显示前 100KB',
    'CONFIRM DELETE': '确认删除',
    'SEARCH FILES': '搜索文件',
    'ENTER DIRECTORY NAME...': '输入目录名...',
    'ENTER SEARCH TERM...': '输入搜索词...',
    'DELETE THESE {n} ITEM(S)?': '删除这 {n} 个项目？',
    'COPIED {n} ITEM(S) TO CLIPBOARD.': '已复制 {n} 个项目到剪贴板。',
    'SELECT EXACTLY ONE ITEM TO RENAME.': '请选择恰好一个项目来重命名。',
    'DRAG OUT WITH ALT OR CMD - DRAG IN FROM FINDER': '按 Alt 或 Cmd 拖出 - 从访达拖入',
    'AUTHORIZATION CODE': '授权口令',
    'SPEAK THE AUTHORIZATION CODE - VOICEPRINT AND VOICE CODE.': '朗读授权口令 - 声纹与语音口令。',
    'SPEAK AUTHORIZATION CODE': '朗读授权口令',
    'SPEAK & VERIFY': '朗读并验证',
    'VOICEPRINT AUTHORIZATION REQUIRED': '需要声纹授权',
    'No files selected.': '未选择任何文件。',
    'Clipboard is empty.': '剪贴板为空。',
    'Cannot paste to the same directory.': '无法粘贴到同一目录。',
    'LCARS LINK FAILURE': 'LCARS 链路故障',

    /* voice unlock messages (vault list + file manager) */
    'LOCKED OUT - AUTHORIZATION SUSPENDED FOR 5 MINUTES': '已锁定 - 授权暂停 5 分钟',
    'VOICEPRINT MISMATCH - AUTHORIZATION DENIED - 1 ATTEMPT REMAINING': '声纹不匹配 - 授权被拒绝 - 剩余 1 次尝试',
    'VOICEPRINT MISMATCH - AUTHORIZATION DENIED - {n} ATTEMPTS REMAINING': '声纹不匹配 - 授权被拒绝 - 剩余 {n} 次尝试',
    'MICROPHONE AUTHORIZATION DENIED - ALLOW ACCESS AND RETRY': '麦克风授权被拒绝 - 请允许访问后重试',
    'STANDBY - VOICE CODE REQUIRED': '待机 - 需要语音口令',
    'LISTENING - SPEAK THE AUTHORIZATION CODE...': '正在聆听 - 请朗读授权口令...',
    'VOICE CODE NOT RECOGNIZED - SPEAK CLEARLY AND RETRY': '未识别语音口令 - 请清晰朗读后重试',
    'VERIFYING AUTHORIZATION...': '正在验证授权...',

    /* LCARSDE file manager page (renderer/fm.html, wording kept as authored) */
    'FILE MANAGER - LCARSDE': '文件管理器 - LCARSDE',
    '+DIR': '+目录',
    'Name': '名称',
    'Size': '大小',
    'Type': '类型',
    'Modified': '修改时间',
    'Empty directory': '空目录',
    'SECURITY LEVEL 9 REQUIRED': '需要 9 级安全权限',
    'ACCESS RESTRICTED — AUTHORIZED PERSONNEL ONLY': '限制访问 — 仅限授权人员',
    'ENTER AUTHORIZATION CODE': '输入授权口令',
    'VERIFY': '验证',
    'INVALID AUTHORIZATION CODE — ACCESS DENIED': '授权码无效 — 拒绝访问',
    'New Directory': '新建目录',
    'Confirm Delete': '确认删除',
    'Search Files': '搜索文件',
    'Enter directory name...': '输入目录名...',
    'Enter search term...': '输入搜索词...',
    'Select exactly one file to rename.': '请选择恰好一个文件来重命名。'
  };

  /* --------------------------------------------------------------- utilities */
  function norm(s) {
    return String(s === null || s === undefined ? '' : s).replace(/\s+/g, ' ').trim();
  }

  var EN = {};
  (function () {
    for (var k in ZH) {
      if (!Object.prototype.hasOwnProperty.call(ZH, k)) continue;
      var zh = ZH[k];
      if (EN[zh] === undefined) EN[zh] = k;
    }
  })();

  var lang = DEFAULT_LANG;
  try {
    var saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === 'en' || saved === 'zh') lang = saved;
  } catch (e) { /* storage unavailable */ }

  var listeners = [];

  function normalizeLang(next) {
    return String(next || '').toLowerCase() === 'zh' ? 'zh' : 'en';
  }

  /* t(): translate a whole string; optional {name} interpolation. */
  function t(text, vars) {
    var out = String(text === null || text === undefined ? '' : text);
    if (lang === 'zh') {
      var hit = ZH[norm(out)];
      if (hit !== undefined) out = hit;
    }
    if (vars) {
      out = out.replace(/\{(\w+)\}/g, function (m, k) {
        return (vars[k] === undefined || vars[k] === null) ? m : String(vars[k]);
      });
    }
    return out;
  }

  /* -------------------------------------------------------------- DOM apply */
  var SKIP_TAGS = { SCRIPT: 1, STYLE: 1, TEXTAREA: 1, NOSCRIPT: 1 };

  function swap(raw, key) {
    var want = (lang === 'zh') ? ZH[key] : EN[key];
    if (want === undefined) return raw;
    return raw.replace(key, want);
  }

  function applyTextNode(node) {
    if (!node || node.nodeType !== 3) return;
    var p = node.parentNode;
    if (p && SKIP_TAGS[p.tagName]) return;
    var raw = node.nodeValue;
    if (!raw) return;
    var key = norm(raw);
    if (!key) return;
    var next = swap(raw, key);
    if (next !== raw) node.nodeValue = next;
  }

  function applyAttrs(el) {
    var attrs = ['placeholder', 'title'];
    for (var i = 0; i < attrs.length; i++) {
      var a = attrs[i];
      var cur = el.getAttribute(a);
      if (!cur) continue;
      var key = norm(cur);
      if (!key) continue;
      var next = swap(cur, key);
      if (next !== cur) el.setAttribute(a, next);
    }
  }

  /* Walk an already-rendered subtree and swap the language in place. Safe to
     call repeatedly: nodes already in the target language simply match nothing. */
  function apply(root) {
    root = root || document.body;
    if (!root) return;
    if (root.nodeType === 1 && SKIP_TAGS[root.tagName]) return;

    if (root.nodeType === 3) { applyTextNode(root); return; }
    if (root.nodeType === 1) applyAttrs(root);

    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var nodes = [];
    var n;
    while ((n = walker.nextNode())) nodes.push(n);
    for (var i = 0; i < nodes.length; i++) applyTextNode(nodes[i]);

    if (root.querySelectorAll) {
      var els = root.querySelectorAll('[placeholder],[title]');
      for (var j = 0; j < els.length; j++) applyAttrs(els[j]);
    }
  }

  /* ---------------------------------------------------------------- language */
  function getLang() { return lang; }

  function setLang(next, opts) {
    lang = normalizeLang(next);
    if (!(opts && opts.mirror === false)) {
      try { window.localStorage.setItem(STORAGE_KEY, lang); } catch (e) { /* ignore */ }
    }
    if (document && document.body) apply(document.body);
    for (var i = 0; i < listeners.length; i++) {
      try { listeners[i](lang); } catch (e) { /* isolate listeners */ }
    }
    return lang;
  }

  function onChange(cb) {
    if (typeof cb !== 'function') return function () {};
    listeners.push(cb);
    return function () {
      var i = listeners.indexOf(cb);
      if (i >= 0) listeners.splice(i, 1);
    };
  }

  window.STV_I18N = {
    t: t,
    apply: apply,
    getLang: getLang,
    setLang: setLang,
    onChange: onChange,
    normalizeLang: normalizeLang,
    dict: ZH,
    reverse: EN
  };
})();
