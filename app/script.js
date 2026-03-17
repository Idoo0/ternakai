/* ═══════════════════════════════════════════════════════════
   TERNAKAI v4 — script.js
   Modules: DB | Crypto | Store | IO | QR | App | UI
═══════════════════════════════════════════════════════════ */
'use strict';

/* ════════════════════════════════════════════════════════════
   MODULE: DB — IndexedDB wrapper
   Stores entire app state as a single object under one key.
════════════════════════════════════════════════════════════ */
const DB = (() => {
  const DB_NAME = 'TernakAI';
  const VERSION = 1;
  const STORE   = 'vault';
  const KEY     = 'appdata';
  let _db       = null;

  function init() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, VERSION);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE);
        }
      };
      req.onsuccess = e => { _db = e.target.result; resolve(); };
      req.onerror   = e => reject(new Error('IndexedDB: ' + e.target.error));
    });
  }

  function save(data) {
    return new Promise((resolve, reject) => {
      const tx  = _db.transaction(STORE, 'readwrite');
      const req = tx.objectStore(STORE).put(data, KEY);
      req.onsuccess = () => resolve();
      req.onerror   = e => reject(e.target.error);
    });
  }

  function load() {
    return new Promise((resolve, reject) => {
      const tx  = _db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(KEY);
      req.onsuccess = e => resolve(e.target.result ?? null);
      req.onerror   = e => reject(e.target.error);
    });
  }

  function clear() {
    return new Promise((resolve, reject) => {
      const tx  = _db.transaction(STORE, 'readwrite');
      const req = tx.objectStore(STORE).delete(KEY);
      req.onsuccess = () => resolve();
      req.onerror   = e => reject(e.target.error);
    });
  }

  async function sizeKB() {
    const data = await load();
    if (!data) return 0;
    return (new Blob([JSON.stringify(data)]).size / 1024).toFixed(1);
  }

  return { init, save, load, clear, sizeKB };
})();

/* ════════════════════════════════════════════════════════════
   MODULE: Crypto — AES-256-GCM via Web Crypto API
   Format: salt(16) | iv(12) | ciphertext → Base64 string
════════════════════════════════════════════════════════════ */
const Crypto = (() => {
  async function _deriveKey(password, salt) {
    const enc = new TextEncoder();
    const raw = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name:'PBKDF2', salt, iterations:120_000, hash:'SHA-256' },
      raw,
      { name:'AES-GCM', length:256 },
      false,
      ['encrypt','decrypt']
    );
  }

  async function encrypt(obj, password) {
    const salt     = crypto.getRandomValues(new Uint8Array(16));
    const iv       = crypto.getRandomValues(new Uint8Array(12));
    const key      = await _deriveKey(password, salt);
    const enc      = new TextEncoder();
    const ct       = await crypto.subtle.encrypt(
      { name:'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))
    );
    const packed   = new Uint8Array(16 + 12 + ct.byteLength);
    packed.set(salt, 0); packed.set(iv, 16); packed.set(new Uint8Array(ct), 28);
    return btoa(String.fromCharCode(...packed));
  }

  async function decrypt(b64, password) {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const salt  = bytes.slice(0, 16);
    const iv    = bytes.slice(16, 28);
    const ct    = bytes.slice(28);
    const key   = await _deriveKey(password, salt);
    const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(plain));
  }

  return { encrypt, decrypt };
})();

/* ════════════════════════════════════════════════════════════
   MODULE: Store — in-memory state + DB persistence
════════════════════════════════════════════════════════════ */
const Store = (() => {
  const state = {
    accounts:       [],
    apikeys:        [],
    customFamilies: [],
    prefs:          { theme:'dark', lang:'id' }
  };

  function hydrate(raw) {
    state.accounts       = raw.accounts       ?? [];
    state.apikeys        = raw.apikeys        ?? [];
    state.customFamilies = raw.customFamilies ?? [];
    state.prefs          = { theme:'dark', lang:'id', ...raw.prefs };
  }

  function serialize() {
    return {
      accounts:       state.accounts,
      apikeys:        state.apikeys,
      customFamilies: state.customFamilies,
      prefs:          state.prefs
    };
  }

  /** Add incoming records; skip duplicates by id */
  function mergeWith(incoming) {
    const accIds  = new Set(state.accounts.map(a => a.id));
    const keyIds  = new Set(state.apikeys.map(k => k.id));
    const famNames= new Set(state.customFamilies.map(f => f.name));
    (incoming.accounts       || []).forEach(a => { if (!accIds.has(a.id))    state.accounts.push(a); });
    (incoming.apikeys        || []).forEach(k => { if (!keyIds.has(k.id))    state.apikeys.push(k); });
    (incoming.customFamilies || []).forEach(f => { if (!famNames.has(f.name)) state.customFamilies.push(f); });
  }

  function replaceWith(incoming) {
    state.accounts       = incoming.accounts       ?? [];
    state.apikeys        = incoming.apikeys        ?? [];
    state.customFamilies = incoming.customFamilies ?? [];
  }

  async function persist() { await DB.save(serialize()); }

  // Expose raw arrays for direct mutation (kept intentional for simplicity)
  return { state, hydrate, serialize, mergeWith, replaceWith, persist };
})();

/* ════════════════════════════════════════════════════════════
   MODULE: IO — import / export cred.json
════════════════════════════════════════════════════════════ */
const IO = (() => {
  const MAGIC   = '_ternakai';
  const VERSION = '4.0';

  async function buildPayload(password) {
    const data = {
      accounts:       Store.state.accounts,
      apikeys:        Store.state.apikeys,
      customFamilies: Store.state.customFamilies
    };
    const payload = {
      [MAGIC]:      VERSION,
      _exported_at: new Date().toISOString(),
      _encrypted:   !!password
    };
    if (password) {
      payload.data = await Crypto.encrypt(data, password);
    } else {
      Object.assign(payload, data);
    }
    return payload;
  }

  function download(obj, filename = 'cred.json') {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type:'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href:url, download:filename });
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function validate(obj) {
    if (!obj[MAGIC])                    throw new Error('Not a valid TernakAI backup');
    if (obj._encrypted && !obj.data)    throw new Error('Encrypted file missing data field');
    if (!obj._encrypted && !Array.isArray(obj.accounts))
                                        throw new Error('Missing accounts array');
  }

  async function extract(obj) {
    if (obj._encrypted) {
      const pwd = await promptPassword(
        'Encrypted Vault',
        'This file is password-protected. Enter password to decrypt.'
      );
      try { return await Crypto.decrypt(obj.data, pwd); }
      catch { throw new Error('Decryption failed — wrong password?'); }
    }
    return {
      accounts:       obj.accounts       ?? [],
      apikeys:        obj.apikeys        ?? [],
      customFamilies: obj.customFamilies ?? []
    };
  }

  async function executeExport() {
    try {
      const useEnc = document.getElementById('exportEncryptToggle').checked;
      let   password = null;
      if (useEnc) {
        const p1 = document.getElementById('exportPwd').value;
        const p2 = document.getElementById('exportPwdConfirm').value;
        if (!p1)       { showToast('Password cannot be empty', 'err'); return; }
        if (p1 !== p2) { showToast('Passwords do not match',   'err'); return; }
        password = p1;
      }
      showToast('Preparing…', 'info');
      const payload = await buildPayload(password);
      download(payload, `ternakai_${new Date().toISOString().split('T')[0]}.cred.json`);
      closeModal('exportModal');
      showToast(t('toast_saved'));
    } catch (err) {
      if (err.message !== 'cancelled') showToast('Export failed: ' + err.message, 'err');
    }
  }

  /** Entry point for <input type=file> onChange */
  async function handleFileInput(event, origin) {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    showToast('Reading file…', 'info');
    try {
      const text = await file.text();
      if (!text.trim()) throw new Error('File is empty');
      let obj;
      try { obj = JSON.parse(text); }
      catch { throw new Error('Invalid JSON — file may be corrupted'); }
      validate(obj);
      const data = await extract(obj);
      await _applyImport(data, origin);
    } catch (err) {
      if (err.message !== 'cancelled') showToast('Import error: ' + err.message, 'err');
    }
  }

  /** Apply already-parsed data object (used by QR scanner too) */
  async function applyData(data, origin) {
    await _applyImport(data, origin);
  }

  async function _applyImport(data, origin) {
    const hasExisting = Store.state.accounts.length > 0 || Store.state.apikeys.length > 0;
    let mode = 'replace';
    if (hasExisting && origin === 'app') {
      mode = await promptImportMode(
        `Vault has ${Store.state.accounts.length} account(s) and ${Store.state.apikeys.length} key(s).`
      );
    }
    if (mode === 'merge') Store.mergeWith(data);
    else                  Store.replaceWith(data);
    await Store.persist();
    if (origin === 'onboarding') App.showApp();
    renderAll();
    showToast(
      `${t('toast_imported')} — ${Store.state.accounts.length} accounts, ${Store.state.apikeys.length} keys`,
      'ok'
    );
  }

  return { handleFileInput, executeExport, applyData };
})();

/* ════════════════════════════════════════════════════════════
   MODULE: QR — chunked QR export + camera-based import
   Chunk format: "TK4:{idx}/{total}:{jsonSlice}"
════════════════════════════════════════════════════════════ */
const QR = (() => {
  const CHUNK = 900;   // safe size for QR level M at low DPI
  let _chunks  = [];
  let _current = 0;

  // ── Export ──
  function _chunkStr(str) {
    const total = Math.ceil(str.length / CHUNK);
    return Array.from({ length: total }, (_, i) =>
      `TK4:${i+1}/${total}:${str.slice(i * CHUNK, (i+1) * CHUNK)}`
    );
  }

  function _renderQR() {
    const el    = document.getElementById('qrDisplay');
    const isDark= document.documentElement.getAttribute('data-theme') === 'dark';
    el.innerHTML = '';
    if (!_chunks.length) return;
    if (typeof QRCode === 'undefined') {
      el.innerHTML = '<p style="color:var(--text3);font-size:13px;padding:40px 20px;text-align:center">QRCode library unavailable — check internet.</p>';
      return;
    }
    new QRCode(el, {
      text:         _chunks[_current],
      width:        240, height:240,
      colorDark:    isDark ? '#e2e8f0' : '#0f172a',
      colorLight:   isDark ? '#0c1728' : '#ffffff',
      correctLevel: QRCode.CorrectLevel.M
    });
    document.getElementById('qrChunkInfo').textContent = `${_current+1} / ${_chunks.length}`;
    document.getElementById('qrPrev').disabled = _current === 0;
    document.getElementById('qrNext').disabled = _current === _chunks.length - 1;
  }

  function openExport() {
    const json  = JSON.stringify({
      _ternakai:      '4.0',
      _via:           'qr',
      accounts:       Store.state.accounts,
      apikeys:        Store.state.apikeys,
      customFamilies: Store.state.customFamilies
    });
    _chunks  = _chunkStr(json);
    _current = 0;
    document.getElementById('qr-export-panel').style.display = '';
    document.getElementById('qr-scan-panel').style.display   = 'none';
    _renderQR();
    openModal('qrModal');
  }

  function next() { if (_current < _chunks.length - 1) { _current++; _renderQR(); } }
  function prev() { if (_current > 0)                  { _current--; _renderQR(); } }

  // ── Import / Scanner ──
  let _scanChunks = {};
  let _scanTotal  = 0;
  let _scanStream = null;
  let _scanRaf    = null;

  function openScan() {
    _scanChunks = {}; _scanTotal = 0;
    document.getElementById('qr-export-panel').style.display = 'none';
    document.getElementById('qr-scan-panel').style.display   = '';
    document.getElementById('scan-status').textContent = 'Point camera at a TERNAKAI QR code';
    document.getElementById('scan-progress').innerHTML = '';
    openModal('qrModal');
    _startCamera();
  }

  async function _startCamera() {
    const video = document.getElementById('scanVideo');
    try {
      _scanStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode:'environment', width:{ ideal:640 }, height:{ ideal:480 } }
      });
      video.srcObject = _scanStream;
      await video.play();
      _scanLoop(video);
    } catch (err) {
      document.getElementById('scan-status').textContent = 'Camera error: ' + err.message;
    }
  }

  function _stopCamera() {
    cancelAnimationFrame(_scanRaf);
    if (_scanStream) { _scanStream.getTracks().forEach(t => t.stop()); _scanStream = null; }
  }

  function _scanLoop(video) {
    const canvas = document.createElement('canvas');
    const ctx    = canvas.getContext('2d');

    function tick() {
      if (!_scanStream) return;
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width  = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        try {
          const code = jsQR(imageData.data, canvas.width, canvas.height, { inversionAttempts:'dontInvert' });
          if (code && code.data) _handleQRChunk(code.data);
        } catch (_) { /* jsQR can throw on bad frames */ }
      }
      _scanRaf = requestAnimationFrame(tick);
    }
    _scanRaf = requestAnimationFrame(tick);
  }

  function _handleQRChunk(raw) {
    const m = raw.match(/^TK4:(\d+)\/(\d+):(.*)$/s);
    if (!m) return;
    const [, idx, total, data] = m;
    const i = parseInt(idx, 10);
    const n = parseInt(total, 10);
    if (_scanTotal === 0) { _scanTotal = n; _renderScanProgress(n); }
    if (!_scanChunks[i]) {
      _scanChunks[i] = data;
      _markChunkScanned(i);
      document.getElementById('scan-status').textContent =
        `Chunk ${i}/${n} captured — ${Object.keys(_scanChunks).length}/${n} total`;
    }
    if (Object.keys(_scanChunks).length === _scanTotal) {
      _stopCamera();
      _reassemble();
    }
  }

  function _renderScanProgress(n) {
    const el = document.getElementById('scan-progress');
    el.innerHTML = Array.from({ length:n }, (_, i) =>
      `<div class="scan-chunk-dot" id="scd-${i+1}">${i+1}</div>`
    ).join('');
  }

  function _markChunkScanned(i) {
    const el = document.getElementById('scd-' + i);
    if (el) el.classList.add('scanned');
  }

  async function _reassemble() {
    try {
      const json = Array.from({ length:_scanTotal }, (_, i) => _scanChunks[i+1]).join('');
      const obj  = JSON.parse(json);
      closeModal('qrModal');
      await IO.applyData({
        accounts:       obj.accounts       ?? [],
        apikeys:        obj.apikeys        ?? [],
        customFamilies: obj.customFamilies ?? []
      }, App.isOnboarding() ? 'onboarding' : 'app');
    } catch (err) {
      document.getElementById('scan-status').textContent = 'Reassembly error: ' + err.message;
    }
  }

  function onClose() { _stopCamera(); }

  return { openExport, openScan, next, prev, onClose };
})();

/* ════════════════════════════════════════════════════════════
   AI CATALOG — families, categories, providers
════════════════════════════════════════════════════════════ */
const CATS = {
  'LLM':         { icon:'🧠', color:'#00d4aa' },
  'Code AI':     { icon:'💻', color:'#8b5cf6' },
  'Image Gen':   { icon:'🎨', color:'#f59e0b' },
  'Voice / TTS': { icon:'🎙️', color:'#ec4899' },
  'AI Agent':    { icon:'🤖', color:'#06b6d4' },
  'Video Gen':   { icon:'🎬', color:'#ef4444' },
  'Search AI':   { icon:'🔍', color:'#10b981' },
  'Other':       { icon:'✨', color:'#94a3b8' }
};

const BASE_FAMILIES = {
  'ChatGPT':       { cat:'LLM',         domain:'chat.openai.com',      color:'#10a37f' },
  'Claude':        { cat:'LLM',         domain:'claude.ai',            color:'#d97706' },
  'Gemini':        { cat:'LLM',         domain:'gemini.google.com',    color:'#4285f4' },
  'Groq':          { cat:'LLM',         domain:'groq.com',             color:'#f97316' },
  'Grok':          { cat:'LLM',         domain:'x.ai',                 color:'#94a3b8' },
  'Mistral':       { cat:'LLM',         domain:'mistral.ai',           color:'#ff7000' },
  'Perplexity':    { cat:'LLM',         domain:'perplexity.ai',        color:'#1fb8cd' },
  'DeepSeek':      { cat:'LLM',         domain:'deepseek.com',         color:'#4d6bfe' },
  'OpenRouter':    { cat:'LLM',         domain:'openrouter.ai',        color:'#6366f1' },
  'Cohere':        { cat:'LLM',         domain:'cohere.com',           color:'#39b2a7' },
  'Meta Llama':    { cat:'LLM',         domain:'llama.meta.com',       color:'#0668e1' },
  'GitHub Copilot':{ cat:'Code AI',     domain:'github.com',           color:'#6e7681' },
  'Cursor':        { cat:'Code AI',     domain:'cursor.com',           color:'#8b5cf6' },
  'Codeium':       { cat:'Code AI',     domain:'codeium.com',          color:'#09b6a2' },
  'Tabnine':       { cat:'Code AI',     domain:'tabnine.com',          color:'#5856d6' },
  'Amazon Q':      { cat:'Code AI',     domain:'aws.amazon.com',       color:'#ff9900' },
  'Replit AI':     { cat:'Code AI',     domain:'replit.com',           color:'#f26207' },
  'Midjourney':    { cat:'Image Gen',   domain:'midjourney.com',       color:'#9b59b6' },
  'DALL-E':        { cat:'Image Gen',   domain:'openai.com',           color:'#10a37f' },
  'Stable Diffusion':{ cat:'Image Gen', domain:'stability.ai',         color:'#7c3aed' },
  'Adobe Firefly': { cat:'Image Gen',   domain:'firefly.adobe.com',    color:'#ff0000' },
  'Ideogram':      { cat:'Image Gen',   domain:'ideogram.ai',          color:'#6366f1' },
  'Flux':          { cat:'Image Gen',   domain:'blackforestlabs.ai',   color:'#8b5cf6' },
  'ElevenLabs':    { cat:'Voice / TTS', domain:'elevenlabs.io',        color:'#f59e0b' },
  'Play.ht':       { cat:'Voice / TTS', domain:'play.ht',              color:'#8b5cf6' },
  'Murf AI':       { cat:'Voice / TTS', domain:'murf.ai',              color:'#06b6d4' },
  'Suno':          { cat:'Voice / TTS', domain:'suno.com',             color:'#ec4899' },
  'Udio':          { cat:'Voice / TTS', domain:'udio.com',             color:'#8b5cf6' },
  'AutoGPT':       { cat:'AI Agent',    domain:'agpt.co',              color:'#10a37f' },
  'CrewAI':        { cat:'AI Agent',    domain:'crewai.com',           color:'#ef4444' },
  'n8n AI':        { cat:'AI Agent',    domain:'n8n.io',               color:'#ea580c' },
  'Zapier AI':     { cat:'AI Agent',    domain:'zapier.com',           color:'#ff4f00' },
  'LangChain':     { cat:'AI Agent',    domain:'langchain.com',        color:'#10a37f' },
  'Make AI':       { cat:'AI Agent',    domain:'make.com',             color:'#6366f1' },
  'Runway':        { cat:'Video Gen',   domain:'runwayml.com',         color:'#00d4aa' },
  'Pika Labs':     { cat:'Video Gen',   domain:'pika.art',             color:'#8b5cf6' },
  'Kling AI':      { cat:'Video Gen',   domain:'klingai.com',          color:'#4d6bfe' },
  'HeyGen':        { cat:'Video Gen',   domain:'heygen.com',           color:'#f59e0b' },
  'Sora':          { cat:'Video Gen',   domain:'openai.com',           color:'#10a37f' },
  'Bing Copilot':  { cat:'Search AI',   domain:'bing.com',             color:'#0078d4' },
  'You.com':       { cat:'Search AI',   domain:'you.com',              color:'#1fb8cd' },
  'Lainnya':       { cat:'Other',       domain:null,                   color:'#8b5cf6' }
};

const PROVIDERS = {
  'Anthropic':   { domain:'anthropic.com',        color:'#d97706' },
  'OpenAI':      { domain:'openai.com',            color:'#10a37f' },
  'Google':      { domain:'google.com',            color:'#4285f4' },
  'Groq':        { domain:'groq.com',              color:'#f97316' },
  'xAI':         { domain:'x.ai',                  color:'#94a3b8' },
  'Mistral':     { domain:'mistral.ai',            color:'#ff7000' },
  'Perplexity':  { domain:'perplexity.ai',         color:'#1fb8cd' },
  'DeepSeek':    { domain:'deepseek.com',          color:'#4d6bfe' },
  'OpenRouter':  { domain:'openrouter.ai',         color:'#6366f1' },
  'Cohere':      { domain:'cohere.com',            color:'#39b2a7' },
  'AWS':         { domain:'aws.amazon.com',        color:'#ff9900' },
  'Azure':       { domain:'azure.microsoft.com',   color:'#0078d4' },
  'GitHub':      { domain:'github.com',            color:'#6e7681' },
  'Stability AI':{ domain:'stability.ai',          color:'#7c3aed' },
  'ElevenLabs':  { domain:'elevenlabs.io',         color:'#f59e0b' },
  'Replicate':   { domain:'replicate.com',         color:'#0ea5e9' },
  'Hugging Face':{ domain:'huggingface.co',        color:'#ffd21e' },
  'Lainnya':     { domain:null,                    color:'#8b5cf6' }
};

/* Predefined tags with emoji + category */
const PRESET_TAGS = [
  { label:'Chat',          color:'#00d4aa' },
  { label:'Code',          color:'#8b5cf6' },
  { label:'Image Gen',     color:'#f59e0b' },
  { label:'Research',      color:'#4285f4' },
  { label:'Writing',       color:'#ec4899' },
  { label:'Video',         color:'#ef4444' },
  { label:'Audio / TTS',   color:'#06b6d4' },
  { label:'Translation',   color:'#10b981' },
  { label:'Data Analysis', color:'#f97316' },
  { label:'Work',          color:'#6366f1' },
  { label:'Personal',      color:'#94a3b8' },
  { label:'Testing',       color:'#fbbf24' },
];

/* ════════════════════════════════════════════════════════════
   I18N
════════════════════════════════════════════════════════════ */
const I18N = {
  id:{
    nav_dash:'Dashboard',nav_acc:'Akun',nav_api:'API Keys',nav_set:'Pengaturan',
    dash_tag:'System Overview',dash_sub:'Kelola seluruh akun & API key AI kamu dari satu panel.',
    stat_total:'Total Akun',stat_fam:'AI Families',stat_prem:'Premium',
    stat_lim:'Limit/Suspend',stat_keys:'API Keys',
    news_title:'Berita AI',tips_title:'AI Tips',powered_by:'Powered by Claude',breakdown:'Family Breakdown',
    sec_notice:'Data disimpan di IndexedDB. Hover untuk reveal. Export untuk backup.',
    acc_tag:'Manajemen Akun',acc_title:'AI Accounts',
    api_tag:'API Management',api_title:'API Keys',
    set_tag:'Konfigurasi',set_title:'Pengaturan',
    set_appear:'Tampilan',set_appear_sub:'Tema dan bahasa aplikasi.',
    lbl_theme:'Tema',lbl_lang:'Bahasa',
    set_cat:'Custom AI Family',set_cat_sub:'Tambahkan AI family yang belum ada di katalog.',
    lbl_fname:'Nama Family',lbl_fcat:'Kategori',
    set_data:'Vault Data',set_data_sub:'Export, import, atau reset seluruh data vault.',
    btn_export:'Export cred.json',btn_import:'Import cred.json',btn_clear:'Reset Vault',
    modal_acc_title:'Register Akun Baru',modal_acc_sub:'Simpan detail akun AI',
    modal_api_title:'Tambah API Key',modal_api_sub:'Simpan API key untuk diakses kapan saja',
    lbl_email:'Email / Username',lbl_pass:'Password',
    lbl_sub:'Status Berlangganan',
    lbl_status:'Status Akun',lbl_tags:'Tags',lbl_desc:'Deskripsi / Kegunaan',
    lbl_label:'Label',lbl_env:'Environment',lbl_apikey:'API Key',
    btn_cancel:'Batal',btn_save:'Simpan',
    th_cred:'Kredensial',th_models:'AI Services',th_status:'Status',th_tags:'Tags',th_desc:'Deskripsi',
    empty_acc:'Belum ada akun',empty_acc_sub:'Klik Tambah Akun untuk memulai',
    empty_api:'Belum ada API key',empty_api_sub:'Klik Tambah API Key untuk memulai',
    add_acc:'Tambah Akun',add_api:'Tambah API Key',
    toast_copied:'Disalin!',toast_saved:'Tersimpan!',toast_imported:'Data diimport!',
    toast_cleared:'Vault direset!',toast_err:'Gagal',
    ob_new:'Buat Vault Baru',ob_new_sub:'Mulai vault kosong',
    ob_import:'Import cred.json',ob_import_sub:'Restore dari file backup',
    ob_scan:'Scan QR',ob_scan_sub:'Transfer dari perangkat lain',
  },
  en:{
    nav_dash:'Dashboard',nav_acc:'Accounts',nav_api:'API Keys',nav_set:'Settings',
    dash_tag:'System Overview',dash_sub:'Manage all your AI accounts & API keys from one panel.',
    stat_total:'Total Accounts',stat_fam:'AI Families',stat_prem:'Premium',
    stat_lim:'Limit/Suspended',stat_keys:'API Keys',
    news_title:'AI News',tips_title:'AI Tips',powered_by:'Powered by Claude',breakdown:'Family Breakdown',
    sec_notice:'Data stored in IndexedDB. Hover to reveal. Export to back up.',
    acc_tag:'Account Management',acc_title:'AI Accounts',
    api_tag:'API Management',api_title:'API Keys',
    set_tag:'Configuration',set_title:'Settings',
    set_appear:'Appearance',set_appear_sub:'Customize theme and language.',
    lbl_theme:'Theme',lbl_lang:'Language',
    set_cat:'Custom AI Family',set_cat_sub:'Add custom families not in the built-in catalog.',
    lbl_fname:'Family Name',lbl_fcat:'Category',
    set_data:'Vault Data',set_data_sub:'Export, import, or reset all vault data.',
    btn_export:'Export cred.json',btn_import:'Import cred.json',btn_clear:'Reset Vault',
    modal_acc_title:'Register New Account',modal_acc_sub:'Save AI account details',
    modal_api_title:'Add API Key',modal_api_sub:'Save an API key for quick access',
    lbl_email:'Email / Username',lbl_pass:'Password',
    lbl_sub:'Subscription Tier',
    lbl_status:'Account Status',lbl_tags:'Tags',lbl_desc:'Description / Purpose',
    lbl_label:'Label',lbl_env:'Environment',lbl_apikey:'API Key',
    btn_cancel:'Cancel',btn_save:'Save',
    th_cred:'Credentials',th_models:'AI Services',th_status:'Status',th_tags:'Tags',th_desc:'Description',
    empty_acc:'No accounts yet',empty_acc_sub:'Click Add Account to get started',
    empty_api:'No API keys yet',empty_api_sub:'Click Add API Key to get started',
    add_acc:'Add Account',add_api:'Add API Key',
    toast_copied:'Copied!',toast_saved:'Saved!',toast_imported:'Data imported!',
    toast_cleared:'Vault reset!',toast_err:'Error',
    ob_new:'Create New Vault',ob_new_sub:'Start with an empty vault',
    ob_import:'Import cred.json',ob_import_sub:'Restore from a backup file',
    ob_scan:'Scan QR',ob_scan_sub:'Transfer from another device',
  }
};
function t(key) { return I18N[Store.state.prefs.lang]?.[key] ?? key; }

/* ════════════════════════════════════════════════════════════
   FORM STATE — ephemeral, not persisted
════════════════════════════════════════════════════════════ */
let selFamily  = null;
let selStatus  = 'Active';
let selSub     = 'Free';
let selCat     = 'LLM';
let pendingSvcs= [];   // [{cat, family, sub}]
let pendingTags= [];
let selProvider= null;

/* ════════════════════════════════════════════════════════════
   CLOCK
════════════════════════════════════════════════════════════ */
setInterval(() => {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('id-ID',{ hour12:false });
}, 1000);

/* ════════════════════════════════════════════════════════════
   THEME & LANG
════════════════════════════════════════════════════════════ */
async function applyTheme(th) {
  Store.state.prefs.theme = th;
  document.documentElement.setAttribute('data-theme', th);
  const icon = document.getElementById('themeIcon');
  if (icon) icon.className = th === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
  ['dark','light'].forEach(v => {
    const b = document.getElementById('set-'+v+'-btn');
    if (b) b.className = 'sub-btn' + (th===v ? (v==='dark' ? ' sub-pro' : ' sub-free') : '');
  });
  if (DB) { try { await Store.persist(); } catch(_){} }
}
function toggleTheme() { applyTheme(Store.state.prefs.theme === 'dark' ? 'light' : 'dark'); }
function setTheme(v)   { applyTheme(v); }

async function applyLang(l) {
  Store.state.prefs.lang = l;
  document.documentElement.lang = l;
  const lbl = document.getElementById('langLabel');
  if (lbl) lbl.textContent = l === 'id' ? 'EN' : 'ID';
  const btn = document.getElementById('langBtn');
  if (btn) btn.classList.toggle('on', l === 'en');
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const k = el.getAttribute('data-i18n');
    if (I18N[l]?.[k]) el.textContent = I18N[l][k];
  });
  ['id','en'].forEach(v => {
    const b = document.getElementById('set-'+v+'-btn');
    if (b) b.className = 'sub-btn' + (l===v ? ' sub-plus' : '');
  });
  updateCatFilter();
  if (DB) { try { await Store.persist(); } catch(_){} }
}
function toggleLang() { applyLang(Store.state.prefs.lang === 'id' ? 'en' : 'id'); }
function setLang(v)   { applyLang(v); }

/* ════════════════════════════════════════════════════════════
   NAV
════════════════════════════════════════════════════════════ */
function go(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  document.getElementById('nav-' + name).classList.add('active');
  if (name === 'dashboard') { renderBreakdown(); updateStorageInfo(); }
  if (name === 'settings')  { renderCustomFamilyList(); updateStorageInfo(); }
}

/* ════════════════════════════════════════════════════════════
   TOAST
════════════════════════════════════════════════════════════ */
let _toastTimer;
function showToast(msg, type = 'ok') {
  const el     = document.getElementById('toast');
  const colors = { ok:'var(--mint)', err:'#f87171', info:'#a78bfa' };
  const icons  = { ok:'fa-circle-check', err:'fa-circle-xmark', info:'fa-circle-info' };
  el.innerHTML = `<i class="fa-solid ${icons[type]}" style="color:${colors[type]}"></i> ${msg}`;
  el.style.display = 'flex';
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { el.style.display = 'none'; }, 2800);
}

/* ════════════════════════════════════════════════════════════
   UTILITIES
════════════════════════════════════════════════════════════ */
function copyText(val, btn) {
  navigator.clipboard.writeText(val).then(() => {
    showToast(t('toast_copied'));
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = '<i class="fa-solid fa-check" style="color:var(--mint)"></i>';
      setTimeout(() => { btn.innerHTML = orig; }, 1500);
    }
  });
}

function getFamilies() {
  const all = { ...BASE_FAMILIES };
  Store.state.customFamilies.forEach(f => {
    all[f.name] = { cat:f.cat, domain:null, color:f.color || '#8b5cf6' };
  });
  return all;
}

function favicon(domain) {
  return domain ? `https://www.google.com/s2/favicons?domain=${domain}&sz=64` : null;
}

function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) {
  document.getElementById(id).classList.remove('open');
  if (id === 'qrModal') QR.onClose();
}

/* ════════════════════════════════════════════════════════════
   STATS & BREAKDOWN
════════════════════════════════════════════════════════════ */
function updateStats() {
  const { accounts, apikeys } = Store.state;
  document.getElementById('st-total').textContent   = accounts.length;
  document.getElementById('st-apikeys').textContent = apikeys.length;
  document.getElementById('badge-acc').textContent  = accounts.length;
  document.getElementById('badge-api').textContent  = apikeys.length;

  const fams = new Set(accounts.flatMap(a => a.ai_services.map(s => s.family)));
  document.getElementById('st-fam').textContent  = fams.size;

  const prem = accounts.filter(a => a.ai_services.some(s => s.sub === 'Pro' || s.sub === 'Plus')).length;
  document.getElementById('st-prem').textContent = prem;

  const lim = accounts.filter(a => a.status === 'Limit' || a.status === 'Banned').length;
  document.getElementById('st-lim').textContent  = lim;
}

function renderBreakdown() {
  const el = document.getElementById('breakdownList');
  if (!el) return;
  const tally = {};
  Store.state.accounts.forEach(a =>
    a.ai_services.forEach(s => { tally[s.family] = (tally[s.family] || 0) + 1; })
  );
  if (!Object.keys(tally).length) {
    el.innerHTML = '<p style="font-size:12px;color:var(--text3);text-align:center;padding:10px 0">No data yet</p>';
    return;
  }
  const fams  = getFamilies();
  const total = Object.values(tally).reduce((a,b) => a+b, 0);
  el.innerHTML = Object.entries(tally).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([fam,n]) => {
    const meta = fams[fam] || { domain:null, color:'#8b5cf6' };
    const pct  = Math.round(n/total*100);
    const fv   = favicon(meta.domain);
    return `<div style="display:flex;align-items:center;gap:10px">
      ${fv ? `<img src="${fv}" style="width:16px;height:16px;border-radius:4px;flex-shrink:0" onerror="this.style.display='none'">` :
             `<div style="width:16px;height:16px;border-radius:4px;background:${meta.color}22;flex-shrink:0"></div>`}
      <div style="flex:1;min-width:0">
        <div style="display:flex;justify-content:space-between">
          <span style="font-size:12px;font-weight:700;color:var(--text2)">${fam}</span>
          <span style="font-size:11px;color:var(--text3)">${n}</span>
        </div>
        <div class="prog-bar"><div class="prog-fill" style="width:${pct}%;background:${meta.color}"></div></div>
      </div>
    </div>`;
  }).join('');
}

async function updateStorageInfo() {
  const el = document.getElementById('vaultStorageInfo');
  if (!el) return;
  try {
    const kb = await DB.sizeKB();
    el.textContent = `Vault: ~${kb} KB · ${Store.state.accounts.length} accounts · ${Store.state.apikeys.length} keys`;
  } catch(_) {}
}

/* ════════════════════════════════════════════════════════════
   RENDER: ACCOUNTS
════════════════════════════════════════════════════════════ */
function renderAccounts() {
  const q    = (document.getElementById('searchAcc')?.value || '').toLowerCase();
  const catF = document.getElementById('filterCat')?.value  || '';
  const stF  = document.getElementById('filterStatus')?.value || '';
  const fams = getFamilies();

  let data = [...Store.state.accounts].sort((a,b) => (b.pinned?1:0) - (a.pinned?1:0));
  if (q)    data = data.filter(a =>
    a.email.toLowerCase().includes(q)       ||
    (a.description||'').toLowerCase().includes(q) ||
    a.ai_services.some(s => s.family.toLowerCase().includes(q)) ||
    (a.tags||[]).some(tag => tag.toLowerCase().includes(q))
  );
  if (catF) data = data.filter(a => a.ai_services.some(s => s.cat === catF));
  if (stF)  data = data.filter(a => a.status === stF);

  const tbody = document.getElementById('accBody');
  const empty = document.getElementById('accEmpty');
  tbody.innerHTML = '';

  if (!data.length) { empty.style.display = ''; return; }
  empty.style.display = 'none';

  const stMap = {
    Active: `<span class="badge b-active"><span style="width:6px;height:6px;background:var(--mint);border-radius:50%;display:inline-block"></span> Active</span>`,
    Limit:  `<span class="badge b-limit"><i class="fa-solid fa-hourglass-half"></i> Limit</span>`,
    Banned: `<span class="badge b-banned"><i class="fa-solid fa-ban"></i> Banned</span>`
  };

  data.forEach(acc => {
    const svcTags = acc.ai_services.map(s => {
      const meta   = fams[s.family] || { domain:null, color:'#8b5cf6' };
      const fv     = favicon(meta.domain);
      const subCls = s.sub==='Pro' ? 'b-pro' : s.sub==='Plus' ? 'b-plus' : 'b-free';
      return `<span class="model-tag" style="background:${meta.color}13;border-color:${meta.color}2e;color:${meta.color}">
        ${fv ? `<img src="${fv}" onerror="this.style.display='none'">` : ''}
        ${s.family}
        <span class="badge ${subCls}" style="padding:1px 5px;font-size:9px;border-radius:4px">${s.sub}</span>
      </span>`;
    }).join('');

    const tagChips = (acc.tags||[]).map(tag => `<span class="tag-chip">${tag}</span>`).join('');
    const sp       = acc.password.replace(/'/g,"\\'");

    const tr = document.createElement('tr');
    if (acc.pinned) tr.className = 'tr-pinned';
    tr.innerHTML = `
      <td style="padding:16px 8px 16px 20px">
        <button onclick="togglePin('${acc.id}',this)" class="btn-icon ${acc.pinned?'pin-on':''}" title="Pin">
          <i class="fa-${acc.pinned?'solid':'regular'} fa-star" style="font-size:12px"></i>
        </button>
      </td>
      <td>
        <div style="font-weight:700;font-size:14px;margin-bottom:7px">${acc.email}</div>
        <div class="secret-wrap">
          <span class="secret-text">${acc.password}</span>
          <button class="secret-copy" onclick="copyText('${sp}',this)" title="Copy">
            <i class="fa-solid fa-copy"></i>
          </button>
        </div>
      </td>
      <td><div style="display:flex;flex-wrap:wrap;max-width:360px">${svcTags}</div></td>
      <td>${stMap[acc.status] || stMap.Active}</td>
      <td><div style="display:flex;flex-wrap:wrap;max-width:160px">${tagChips}</div></td>
      <td style="max-width:220px;font-size:13px;color:var(--text3);line-height:1.65">${acc.description||'—'}</td>
      <td>
        <button onclick="deleteAccount('${acc.id}')" class="btn-icon danger" title="Delete">
          <i class="fa-solid fa-trash" style="font-size:11px"></i>
        </button>
      </td>`;
    tbody.appendChild(tr);
  });
}

async function togglePin(id, btn) {
  const acc = Store.state.accounts.find(a => a.id === id);
  if (!acc) return;
  acc.pinned = !acc.pinned;
  btn.className = 'btn-icon ' + (acc.pinned?'pin-on':'');
  btn.innerHTML = `<i class="fa-${acc.pinned?'solid':'regular'} fa-star" style="font-size:12px"></i>`;
  await Store.persist(); renderAccounts();
}

async function deleteAccount(id) {
  if (!confirm(t('del_confirm') || 'Delete this account?')) return;
  Store.state.accounts = Store.state.accounts.filter(a => a.id !== id);
  await Store.persist(); renderAccounts(); updateStats();
}

/* ════════════════════════════════════════════════════════════
   RENDER: API KEYS
════════════════════════════════════════════════════════════ */
function renderApiKeys() {
  const q   = (document.getElementById('searchApi')?.value || '').toLowerCase();
  let data  = Store.state.apikeys;
  if (q) data = data.filter(k =>
    k.label.toLowerCase().includes(q) ||
    k.provider.toLowerCase().includes(q) ||
    (k.description||'').toLowerCase().includes(q)
  );

  const grid  = document.getElementById('apiGrid');
  const empty = document.getElementById('apiEmpty');
  grid.innerHTML = '';
  if (!data.length) { empty.style.display=''; return; }
  empty.style.display = 'none';

  const envColors = { Production:'#ef4444', Development:'#f59e0b', Testing:'#06b6d4', Personal:'#8b5cf6' };

  data.forEach(k => {
    const meta    = PROVIDERS[k.provider] || { domain:null, color:'#8b5cf6' };
    const fv      = favicon(meta.domain);
    const envColor= envColors[k.env] || '#94a3b8';
    const sk      = k.key.replace(/'/g,"\\'");

    const div = document.createElement('div');
    div.className = 'card'; div.style.padding = '22px';
    div.innerHTML = `
      <div style="display:flex;align-items:start;justify-content:space-between;margin-bottom:14px">
        <div style="display:flex;align-items:center;gap:12px">
          <div style="width:42px;height:42px;border-radius:11px;background:${meta.color}16;border:1px solid ${meta.color}28;display:flex;align-items:center;justify-content:center;flex-shrink:0">
            ${fv ? `<img src="${fv}" style="width:22px;height:22px;border-radius:4px" onerror="this.style.display='none'">` :
                   `<i class='fa-solid fa-key' style='color:${meta.color};font-size:14px'></i>`}
          </div>
          <div>
            <div style="font-size:15px;font-weight:700">${k.label}</div>
            <div style="display:flex;align-items:center;gap:7px;margin-top:4px">
              <span style="font-size:10px;color:var(--text3);font-family:'JetBrains Mono',monospace">${k.provider}</span>
              <span style="font-size:9px;font-weight:700;padding:2px 6px;border-radius:5px;background:${envColor}14;color:${envColor};border:1px solid ${envColor}26;font-family:'JetBrains Mono',monospace">${k.env||'—'}</span>
            </div>
          </div>
        </div>
        <button onclick="deleteApiKey('${k.id}')" class="btn-icon danger">
          <i class="fa-solid fa-trash" style="font-size:11px"></i>
        </button>
      </div>
      <div class="key-box">
        <code>${k.key}</code>
        <button class="key-copy-btn" onclick="copyText('${sk}',this)" title="Copy">
          <i class="fa-solid fa-copy"></i>
        </button>
      </div>
      <p style="font-size:13px;color:var(--text3);line-height:1.65;margin-bottom:16px">${k.description||'—'}</p>
      <div style="display:flex;align-items:center;justify-content:space-between;padding-top:12px;border-top:1px solid var(--border)">
        <span style="font-size:10px;color:var(--text3);font-family:'JetBrains Mono',monospace">${k.created||'—'}</span>
        <span style="font-size:10px;font-weight:700;padding:3px 9px;border-radius:6px;background:${meta.color}14;color:${meta.color}">${k.provider}</span>
      </div>`;
    grid.appendChild(div);
  });
}

async function deleteApiKey(id) {
  if (!confirm(t('del_confirm') || 'Delete this key?')) return;
  Store.state.apikeys = Store.state.apikeys.filter(k => k.id !== id);
  await Store.persist(); renderApiKeys(); updateStats();
}

/* ════════════════════════════════════════════════════════════
   PROMISE-BASED MODALS (password + import mode)
════════════════════════════════════════════════════════════ */
function promptPassword(title, subtitle) {
  return new Promise((resolve, reject) => {
    document.getElementById('pwdModalTitle').textContent = title;
    document.getElementById('pwdModalSub').textContent   = subtitle;
    document.getElementById('pwdInput').value = '';
    openModal('pwdModal');
    const form   = document.getElementById('pwdForm');
    const cancel = document.getElementById('pwdModalCancel');
    const cleanup = () => {
      form.onsubmit = null; cancel.onclick = null; closeModal('pwdModal');
    };
    form.onsubmit  = e => { e.preventDefault(); cleanup(); resolve(document.getElementById('pwdInput').value); };
    cancel.onclick = () => { cleanup(); reject(new Error('cancelled')); };
  });
}

function promptImportMode(subtitle) {
  return new Promise((resolve, reject) => {
    document.getElementById('importModeSub').textContent = subtitle;
    openModal('importModeModal');
    const cleanup = () => closeModal('importModeModal');
    document.getElementById('importModeReplace').onclick = () => { cleanup(); resolve('replace'); };
    document.getElementById('importModeMerge').onclick   = () => { cleanup(); resolve('merge'); };
    document.getElementById('importModeCancel').onclick  = () => { cleanup(); reject(new Error('cancelled')); };
  });
}

/* ════════════════════════════════════════════════════════════
   FORM: ADD ACCOUNT
════════════════════════════════════════════════════════════ */
function openAddAccount() {
  selFamily = null; selStatus = 'Active'; selSub = 'Free';
  selCat = Object.keys(CATS)[0]; pendingSvcs = []; pendingTags = [];
  document.getElementById('addAccForm').reset();
  ['ac-status-v','ac-family-v','ac-sub-v'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = id==='ac-status-v' ? 'Active' : id==='ac-sub-v' ? 'Free' : '';
  });
  document.getElementById('svcDetail').style.display       = 'none';
  document.getElementById('pendingSvcsArea').style.display = 'none';
  document.getElementById('pendingSvcsList').innerHTML     = '';
  document.getElementById('tagsList').innerHTML            = '';
  buildCatTabs(); buildFamGrid(); buildTagPresets();
  resetSubBtns(); resetStatusBtns();
  document.getElementById('stb-active').classList.add('st-active');
  openModal('addModal');
}

function buildCatTabs() {
  const el = document.getElementById('catTabs');
  el.innerHTML = '';
  const customCats = [...new Set(Store.state.customFamilies.map(f=>f.cat).filter(c=>!CATS[c]))];
  [...Object.entries(CATS), ...customCats.map(c=>[c,{icon:'✨',color:'#94a3b8'}])].forEach(([cat,meta]) => {
    const btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'cat-tab' + (cat===selCat?' sel':'');
    btn.innerHTML = `${meta.icon} ${cat}`;
    btn.onclick = () => pickCat(cat);
    el.appendChild(btn);
  });
}

function pickCat(cat) {
  selCat = cat;
  document.querySelectorAll('#catTabs .cat-tab').forEach(b => {
    b.classList.toggle('sel', b.textContent.trim().endsWith(cat));
  });
  buildFamGrid();
}

function buildFamGrid() {
  const fams = getFamilies();
  const el   = document.getElementById('famGrid');
  el.innerHTML = '';
  Object.entries(fams).filter(([,f])=>f.cat===selCat).forEach(([name,meta]) => {
    const div = document.createElement('div');
    div.className = 'family-card' + (name===selFamily?' sel':'');
    div.onclick   = () => pickFamily(name, div);
    const fv = favicon(meta.domain);
    div.innerHTML = fv
      ? `<img src="${fv}" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
         <div class="fam-icon" style="background:${meta.color}18;display:none">
           <i class="fa-solid fa-microchip" style="color:${meta.color};font-size:13px"></i></div>
         <div class="fam-name">${name}</div>`
      : `<div class="fam-icon" style="background:${meta.color}18">
           <span style="font-size:16px">${CATS[meta.cat]?.icon||'✨'}</span></div>
         <div class="fam-name">${name}</div>`;
    el.appendChild(div);
  });
}

function pickFamily(name, el) {
  document.querySelectorAll('#famGrid .family-card').forEach(c=>c.classList.remove('sel'));
  el.classList.add('sel');
  selFamily = name;
  document.getElementById('ac-family-v').value = name;
  document.getElementById('svcDetail').style.display = '';
}

function pickSub(s) {
  selSub = s;
  document.getElementById('ac-sub-v').value = s;
  resetSubBtns();
  const map = { Free:'sub-free', Plus:'sub-plus', Pro:'sub-pro' };
  document.getElementById('sb-'+s.toLowerCase()).classList.add(map[s]);
}
function resetSubBtns() { ['free','plus','pro'].forEach(s=>document.getElementById('sb-'+s).className='sub-btn'); }

function pickStatus(s) {
  selStatus = s;
  document.getElementById('ac-status-v').value = s;
  resetStatusBtns();
  const map = { Active:'st-active', Limit:'st-limit', Banned:'st-banned' };
  document.getElementById('stb-'+s.toLowerCase()).classList.add(map[s]);
}
function resetStatusBtns() { ['active','limit','banned'].forEach(s=>document.getElementById('stb-'+s).className='status-btn'); }

function addSvcToList() {
  if (!selFamily) { showToast('Select an AI family first', 'err'); return; }
  pendingSvcs.push({ cat:selCat, family:selFamily, sub:selSub });
  renderPendingSvcs();
  showToast('Service added ✓', 'info');
}

function renderPendingSvcs() {
  const area = document.getElementById('pendingSvcsArea');
  const list = document.getElementById('pendingSvcsList');
  if (!pendingSvcs.length) { area.style.display='none'; return; }
  area.style.display = '';
  const fams = getFamilies();
  list.innerHTML = pendingSvcs.map((s,i) => {
    const meta   = fams[s.family] || { domain:null, color:'#8b5cf6' };
    const subCls = s.sub==='Pro'?'b-pro':s.sub==='Plus'?'b-plus':'b-free';
    const fv     = favicon(meta.domain);
    return `<span style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:8px;border:1px solid ${meta.color}30;background:${meta.color}11;font-size:11px;font-family:'JetBrains Mono',monospace;font-weight:700;color:${meta.color}">
      ${fv?`<img src="${fv}" style="width:12px;height:12px;border-radius:3px">`:''}
      ${s.family}
      <span class="badge ${subCls}" style="padding:1px 5px;font-size:9px">${s.sub}</span>
      <button type="button" onclick="removePendingSvc(${i})" style="background:none;border:none;cursor:pointer;color:${meta.color};opacity:.7;font-size:14px;line-height:1;padding:0">×</button>
    </span>`;
  }).join('');
}
function removePendingSvc(i) { pendingSvcs.splice(i,1); renderPendingSvcs(); }

/* ── Tags ─────────────────────────────────────────────── */
function buildTagPresets() {
  const el = document.getElementById('tagPresets');
  if (!el) return;
  el.innerHTML = PRESET_TAGS.map(p =>
    `<button type="button" class="tag-preset-chip ${pendingTags.includes(p.label)?'sel':''}"
      style="${pendingTags.includes(p.label)?`border-color:${p.color};color:${p.color};background:${p.color}14`:''}"
      onclick="togglePresetTag('${p.label}','${p.color}',this)">${p.label}</button>`
  ).join('');
}

function togglePresetTag(label, color, btn) {
  const i = pendingTags.indexOf(label);
  if (i > -1) {
    pendingTags.splice(i,1);
    btn.classList.remove('sel');
    btn.style.borderColor = ''; btn.style.color = ''; btn.style.background = '';
  } else {
    pendingTags.push(label);
    btn.classList.add('sel');
    btn.style.borderColor = color; btn.style.color = color; btn.style.background = color+'14';
  }
  renderTagsList();
}

function addCustomTag() {
  const inp = document.getElementById('ac-tag-input');
  const v   = inp.value.trim();
  if (v && !pendingTags.includes(v)) { pendingTags.push(v); renderTagsList(); }
  inp.value = '';
}

function renderTagsList() {
  document.getElementById('tagsList').innerHTML = pendingTags.map((tag,i) =>
    `<span class="tag-chip">${tag}<button class="tag-rm" onclick="removeTag(${i})">×</button></span>`
  ).join('');
}
function removeTag(i) { pendingTags.splice(i,1); renderTagsList(); buildTagPresets(); }

/* ════════════════════════════════════════════════════════════
   FORM: ADD API KEY
════════════════════════════════════════════════════════════ */
function openAddApi() {
  selProvider = null;
  document.getElementById('addApiForm').reset();
  document.getElementById('api-prov-v').value = '';
  const grid = document.getElementById('provGrid');
  grid.innerHTML = '';
  Object.entries(PROVIDERS).forEach(([name,meta]) => {
    const div = document.createElement('div');
    div.className = 'prov-card';
    div.onclick = () => {
      document.querySelectorAll('#provGrid .prov-card').forEach(c=>c.classList.remove('sel'));
      div.classList.add('sel'); selProvider = name;
      document.getElementById('api-prov-v').value = name;
    };
    const fv = favicon(meta.domain);
    div.innerHTML = fv
      ? `<img src="${fv}" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
         <div class="prov-icon" style="background:${meta.color}18;display:none">
           <i class="fa-solid fa-key" style="color:${meta.color};font-size:12px"></i></div>
         <div class="pn">${name}</div>`
      : `<div class="prov-icon" style="background:${meta.color}18">
           <i class="fa-solid fa-key" style="color:${meta.color};font-size:12px"></i></div>
         <div class="pn">${name}</div>`;
    grid.appendChild(div);
  });
  openModal('addApiModal');
}

/* ════════════════════════════════════════════════════════════
   FORM SUBMIT HANDLERS
════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('ac-tag-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); addCustomTag(); }
  });

  document.getElementById('addAccForm').addEventListener('submit', async e => {
    e.preventDefault();
    let svcs = [...pendingSvcs];
    if (!svcs.length && selFamily) {
      svcs.push({ cat:selCat, family:selFamily, sub:selSub });
    }
    if (!svcs.length) { showToast('Select at least 1 AI family', 'err'); return; }

    Store.state.accounts.unshift({
      id:          'a' + Date.now(),
      email:       document.getElementById('ac-email').value,
      password:    document.getElementById('ac-pass').value,
      status:      document.getElementById('ac-status-v').value,
      pinned:      false,
      tags:        [...pendingTags],
      description: document.getElementById('ac-desc').value,
      ai_services: svcs
    });
    await Store.persist();
    renderAccounts(); updateStats();
    closeModal('addModal'); go('accounts');
    showToast(t('toast_saved'));
  });

  document.getElementById('addApiForm').addEventListener('submit', async e => {
    e.preventDefault();
    Store.state.apikeys.unshift({
      id:          'k' + Date.now(),
      provider:    selProvider || 'Lainnya',
      label:       document.getElementById('api-label').value,
      env:         document.getElementById('api-env').value,
      key:         document.getElementById('api-key').value,
      description: document.getElementById('api-desc').value,
      created:     new Date().toISOString().split('T')[0]
    });
    await Store.persist();
    renderApiKeys(); updateStats();
    closeModal('addApiModal'); go('apikeys');
    showToast(t('toast_saved'));
  });
});

/* ════════════════════════════════════════════════════════════
   EXPORT MODAL
════════════════════════════════════════════════════════════ */
function openExportModal() {
  document.getElementById('exportEncryptToggle').checked = false;
  document.getElementById('exportPasswordFields').style.display = 'none';
  document.getElementById('exportPwd').value = '';
  document.getElementById('exportPwdConfirm').value = '';
  document.getElementById('exportSummary').textContent =
    `Vault: ${Store.state.accounts.length} account(s), ${Store.state.apikeys.length} API key(s), ${Store.state.customFamilies.length} custom famil(ies).`;
  openModal('exportModal');
}
function toggleExportPassword() {
  document.getElementById('exportPasswordFields').style.display =
    document.getElementById('exportEncryptToggle').checked ? 'flex' : 'none';
}

/* ════════════════════════════════════════════════════════════
   SETTINGS: CUSTOM FAMILIES & DATA
════════════════════════════════════════════════════════════ */
function updateCatFilter() {
  const sel = document.getElementById('filterCat');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = `<option value="">${Store.state.prefs.lang==='id' ? 'Semua Kategori' : 'All Categories'}</option>`;
  Object.keys(CATS).forEach(cat => {
    const o = document.createElement('option');
    o.value = cat; o.textContent = CATS[cat].icon + ' ' + cat;
    sel.appendChild(o);
  });
  sel.value = cur;
}

function renderCustomFamilyList() {
  const el = document.getElementById('customFamilyList');
  if (!el) return;
  if (!Store.state.customFamilies.length) {
    el.innerHTML = `<p style="font-size:12px;color:var(--text3)">${Store.state.prefs.lang==='id' ? 'Belum ada family custom.' : 'No custom families yet.'}</p>`;
    return;
  }
  el.innerHTML = Store.state.customFamilies.map((f,i) =>
    `<span class="tag-chip" style="border-color:${f.color||'#8b5cf6'}30;color:${f.color||'#8b5cf6'};background:${f.color||'#8b5cf6'}11;padding:5px 10px;font-size:11px">
      ${f.name} <span style="opacity:.5">· ${f.cat}</span>
      <button class="tag-rm" onclick="removeCustomFamily(${i})">×</button>
    </span>`
  ).join('');
}

async function addCustomFamily() {
  const name = document.getElementById('new-fam-name').value.trim();
  const cat  = document.getElementById('new-fam-cat').value;
  if (!name) { showToast('Name is required', 'err'); return; }
  if (Store.state.customFamilies.some(f=>f.name===name)) { showToast('Already exists', 'err'); return; }
  Store.state.customFamilies.push({ name, cat, color:'#8b5cf6' });
  document.getElementById('new-fam-name').value = '';
  await Store.persist(); renderCustomFamilyList();
  showToast(t('toast_saved'));
}

async function removeCustomFamily(i) {
  Store.state.customFamilies.splice(i,1);
  await Store.persist(); renderCustomFamilyList();
}

async function confirmClearData() {
  const msg = Store.state.prefs.lang==='id'
    ? 'Reset seluruh vault? Data tidak dapat dikembalikan!'
    : 'Reset the entire vault? This cannot be undone!';
  if (!confirm(msg)) return;
  Store.state.accounts = []; Store.state.apikeys = []; Store.state.customFamilies = [];
  await Store.persist(); renderAll(); showToast(t('toast_cleared'), 'info');
}

/* ════════════════════════════════════════════════════════════
   NEWS & TIPS
════════════════════════════════════════════════════════════ */
const FALLBACK_TIPS = [
  { icon:'🔑', title:'Rotate API Keys',       tip:'Change API keys every 90 days to prevent misuse.',                tag:'Security' },
  { icon:'⚡', title:'Groq for Fast Inference',tip:'Groq offers ~300 tok/s — ideal for real-time applications.',     tag:'Speed' },
  { icon:'🎯', title:'Specific System Prompts',tip:'The more detailed your system prompt, the more consistent output.',tag:'Prompting' },
  { icon:'💰', title:'Use Mini Models',        tip:'Use mini/haiku for routine tasks — saves up to 20× cost.',       tag:'Cost' }
];
const FALLBACK_NEWS = [
  { title:'OpenAI GPT-4o: Enhanced multimodal capabilities',     link:'#', pubDate:'2025-03-15', src:'TechCrunch' },
  { title:'Google Gemini 2.5 Pro breaks coding benchmark records',link:'#', pubDate:'2025-03-12', src:'The Verge'  },
  { title:'Anthropic Claude 3.7: extended thinking mode',         link:'#', pubDate:'2025-03-10', src:'VentureBeat'},
  { title:'Meta Llama 3.3 with improved reasoning released',      link:'#', pubDate:'2025-03-08', src:'TechCrunch' },
];

async function loadNews() {
  const el   = document.getElementById('newsContainer');
  const icon = document.getElementById('newsRefreshIcon');
  el.innerHTML = shimmerHTML(3); icon.className = 'fa-solid fa-rotate-right fa-spin';
  try {
    const res  = await fetch('https://api.rss2json.com/v1/api.json?rss_url=https://techcrunch.com/category/artificial-intelligence/feed/&count=4');
    const data = await res.json();
    if (data.status==='ok' && data.items?.length) {
      el.innerHTML = data.items.map((item,i) => `
        <div class="news-card" style="animation:fadeUp .35s ${i*.07}s both">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px">
            <span class="news-src">TechCrunch AI</span>
            <span class="news-date">${new Date(item.pubDate).toLocaleDateString(Store.state.prefs.lang==='id'?'id-ID':'en-US',{month:'short',day:'numeric'})}</span>
          </div>
          <a href="${item.link}" target="_blank" rel="noopener" class="news-title">${item.title}</a>
        </div>`).join('');
      return;
    }
    throw new Error('no items');
  } catch {
    el.innerHTML = FALLBACK_NEWS.map((n,i) => `
      <div class="news-card" style="animation:fadeUp .35s ${i*.07}s both">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span class="news-src">${n.src}</span><span class="news-date">${n.pubDate}</span>
        </div>
        <span class="news-title" style="cursor:default">${n.title}</span>
      </div>`).join('');
  } finally { icon.className = 'fa-solid fa-rotate-right'; }
}

async function loadTips() {
  const el   = document.getElementById('tipsContainer');
  const icon = document.getElementById('tipsRefreshIcon');
  const btn  = document.getElementById('tipsRefreshBtn');
  el.innerHTML = shimmerHTML(3); icon.className = 'fa-solid fa-rotate-right fa-spin'; btn.disabled = true;
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        model:'claude-sonnet-4-20250514', max_tokens:900,
        messages:[{ role:'user', content:`Give 4 practical AI tips for developers in ${Store.state.prefs.lang==='id'?'Bahasa Indonesia':'English'}. Reply ONLY with JSON array, no markdown. Format: [{"icon":"emoji","title":"max 5 words","tip":"1-2 sentences","tag":"1 word"}]` }]
      })
    });
    const data = await res.json();
    const raw  = data.content.map(c=>c.text||'').join('').trim().replace(/```json|```/gm,'').trim();
    renderTips(JSON.parse(raw));
  } catch { renderTips(FALLBACK_TIPS); }
  finally  { icon.className='fa-solid fa-rotate-right'; btn.disabled=false; }
}

function renderTips(tips) {
  document.getElementById('tipsContainer').innerHTML = tips.map((tip,i) => `
    <div class="tip-card" style="animation:fadeUp .35s ${i*.07}s both">
      <div style="display:flex;align-items:start;gap:11px">
        <span style="font-size:20px;line-height:1;flex-shrink:0;margin-top:1px">${tip.icon}</span>
        <div>
          <div style="display:flex;align-items:center;gap:7px;margin-bottom:4px">
            <h4 style="font-size:13px;font-weight:700">${tip.title}</h4>
            <span style="font-size:9px;font-weight:700;padding:2px 6px;border-radius:5px;background:var(--mint-dim);color:var(--mint);border:1px solid var(--mint-border);font-family:'JetBrains Mono',monospace">${tip.tag}</span>
          </div>
          <p style="font-size:12px;color:var(--text3);line-height:1.7">${tip.tip}</p>
        </div>
      </div>
    </div>`).join('');
}

function shimmerHTML(n) {
  return Array(n).fill(`<div class="shimmer" style="height:68px;margin-bottom:8px"></div>`).join('');
}

/* ════════════════════════════════════════════════════════════
   RENDER ALL
════════════════════════════════════════════════════════════ */
function renderAll() {
  updateStats(); renderBreakdown(); renderAccounts();
  renderApiKeys(); renderCustomFamilyList(); updateCatFilter();
  applyTheme(Store.state.prefs.theme);
  applyLang(Store.state.prefs.lang);
}

/* ════════════════════════════════════════════════════════════
   PWA INSTALL (Android Chrome)
════════════════════════════════════════════════════════════ */
let _deferredInstall = null;
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  _deferredInstall = e;
  const bar = document.getElementById('pwa-bar');
  if (bar) bar.classList.add('show');
});
function installPWA() {
  if (!_deferredInstall) return;
  _deferredInstall.prompt();
  _deferredInstall.userChoice.then(() => {
    _deferredInstall = null;
    const bar = document.getElementById('pwa-bar');
    if (bar) bar.classList.remove('show');
  });
}

/* ════════════════════════════════════════════════════════════
   MODULE: App — lifecycle controller
════════════════════════════════════════════════════════════ */
const App = (() => {
  let _onboarding = true;

  async function init() {
    try {
      await DB.init();
    } catch (err) {
      console.warn('IndexedDB unavailable:', err.message);
      showToast('Storage unavailable — data will not persist', 'err');
      _onboarding = false;
      showApp(); renderAll();
      return;
    }
    const raw = await DB.load();
    if (!raw) {
      showOnboarding();
    } else {
      Store.hydrate(raw);
      _onboarding = false;
      showApp(); renderAll();
    }
  }

  function showOnboarding() {
    _onboarding = true;
    document.getElementById('screen-onboarding').style.display = 'flex';
    document.getElementById('screen-app').style.display        = 'none';
    applyTheme(Store.state.prefs.theme);
    applyLang(Store.state.prefs.lang);
  }

  function showApp() {
    _onboarding = false;
    document.getElementById('screen-onboarding').style.display = 'none';
    document.getElementById('screen-app').style.display        = 'flex';
  }

  async function createNewVault() {
    await Store.persist();  // write empty vault → marks DB as initialized
    showApp(); renderAll(); loadNews(); loadTips();
  }

  function isOnboarding() { return _onboarding; }

  return { init, showOnboarding, showApp, createNewVault, isOnboarding };
})();

/* ════════════════════════════════════════════════════════════
   SERVICE WORKER REGISTRATION
════════════════════════════════════════════════════════════ */
if ('serviceWorker' in navigator && location.protocol !== 'file:') {
  window.addEventListener('load', () => {
    // SW lives one level up from app/
    navigator.serviceWorker.register('../sw.js', { scope: '../' })
      .then(reg => console.info('[SW] registered, scope:', reg.scope))
      .catch(err => console.warn('[SW] registration failed:', err));
  });
}

/* ════════════════════════════════════════════════════════════
   BOOT
════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  App.init().then(() => {
    if (!App.isOnboarding()) { loadNews(); loadTips(); }
  }).catch(err => {
    console.error('Boot failed:', err);
    showToast('App failed to initialize: ' + err.message, 'err');
  });
});
