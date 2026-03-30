/**
 * app.js — VaultX Application Logic
 *
 * State management, UI rendering, and storage.
 * All sensitive data is encrypted via crypto.js before hitting localStorage.
 */

'use strict';

// ── Constants ────────────────────────────────────────────────────────────────
const STORAGE_KEY   = 'vaultx_data';
const META_KEY      = 'vaultx_meta';
const AUTO_LOCK_MS  = 15 * 60 * 1000;  // auto-lock after 15 minutes

// ── State ─────────────────────────────────────────────────────────────────────
let masterPassword  = null;
let entries         = [];          // decrypted in-memory array
let editIndex       = null;        // null = new entry, number = editing
let activeCategory  = 'all';
let autoLockTimer   = null;

// ── Category icons ────────────────────────────────────────────────────────────
const CAT_ICONS = {
  Social: '💬', Work: '💼', Finance: '💳',
  Shopping: '🛍️', Other: '🔑',
};

// ── Strength scoring ──────────────────────────────────────────────────────────
function scorePassword(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw))         score++;
  if (/[a-z]/.test(pw))         score++;
  if (/[0-9]/.test(pw))         score++;
  if (/[^A-Za-z0-9]/.test(pw))  score++;
  return Math.min(score, 5);
}

function strengthLabel(score) {
  return ['', 'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'][score] || '';
}

function strengthColor(score) {
  return ['', '#ff4f4f','#ff8c42','#f5c518','#00d4aa','#00d4aa'][score] || '#ccc';
}

function updateStrengthBar(inputId, barId, labelId) {
  const pw    = document.getElementById(inputId).value;
  const score = scorePassword(pw);
  const bar   = document.getElementById(barId);
  const lbl   = document.getElementById(labelId);
  bar.style.background = strengthColor(score);
  bar.style.width      = `${(score / 5) * 100}%`;
  lbl.textContent      = pw ? strengthLabel(score) : '';
  lbl.style.color      = strengthColor(score);
}

// ── Initialise ────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  const meta = loadMeta();
  if (meta) {
    show('unlock-form');
    document.getElementById('unlock-pass').addEventListener('keydown', e => {
      if (e.key === 'Enter') unlockVault();
    });
    document.getElementById('setup-pass').addEventListener('input', () =>
      updateStrengthBar('setup-pass', 'strength-bar', 'strength-label'));
  } else {
    show('setup-form');
    document.getElementById('setup-pass').addEventListener('input', () =>
      updateStrengthBar('setup-pass', 'strength-bar', 'strength-label'));
  }
});

// ── Meta helpers ──────────────────────────────────────────────────────────────
function loadMeta() {
  try { return JSON.parse(localStorage.getItem(META_KEY)); } catch { return null; }
}

function saveMeta(obj) {
  localStorage.setItem(META_KEY, JSON.stringify(obj));
}

// ── Screens ───────────────────────────────────────────────────────────────────
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function show(id) {
  document.querySelectorAll('.card').forEach(c => c.style.display = 'none');
  document.getElementById(id).style.display = 'block';
}

// ── Setup vault ───────────────────────────────────────────────────────────────
async function setupVault() {
  const pw  = document.getElementById('setup-pass').value;
  const pw2 = document.getElementById('setup-confirm').value;
  const err = document.getElementById('setup-error');

  if (!pw)           { err.textContent = 'Enter a master password.'; return; }
  if (pw.length < 8) { err.textContent = 'Password must be at least 8 characters.'; return; }
  if (pw !== pw2)    { err.textContent = 'Passwords do not match.'; return; }
  err.textContent = '';

  const salt      = Crypto.generateSalt();
  const saltBytes = Crypto.b64ToBuf(salt);
  const hash      = await Crypto.hashPassword(pw, saltBytes);

  saveMeta({ salt, hash });
  masterPassword = pw;
  entries        = [];

  await saveVault();
  bootVault();
}

// ── Unlock vault ──────────────────────────────────────────────────────────────
async function unlockVault() {
  const pw  = document.getElementById('unlock-pass').value;
  const err = document.getElementById('unlock-error');

  if (!pw) { err.textContent = 'Enter your master password.'; return; }
  err.textContent = 'Verifying…';

  const meta = loadMeta();
  const ok   = await Crypto.verifyPassword(pw, meta.hash, meta.salt);

  if (!ok) {
    err.textContent = '❌ Wrong password. Try again.';
    return;
  }

  err.textContent = '';
  masterPassword  = pw;

  // Load existing vault data
  const raw = localStorage.getItem(STORAGE_KEY);
  if (raw) {
    try {
      const decrypted = await Crypto.decrypt(raw, masterPassword);
      entries = JSON.parse(decrypted);
    } catch {
      err.textContent = 'Failed to decrypt vault. Data may be corrupted.';
      masterPassword = null;
      return;
    }
  } else {
    entries = [];
  }

  bootVault();
}

// ── Lock vault ────────────────────────────────────────────────────────────────
function lockVault() {
  masterPassword = null;
  entries        = [];
  clearTimeout(autoLockTimer);

  document.getElementById('unlock-pass').value = '';
  document.getElementById('unlock-error').textContent = '';
  show('unlock-form');
  showScreen('lock-screen');
  toast('🔒 Vault locked');
}

// ── Boot vault screen ─────────────────────────────────────────────────────────
function bootVault() {
  renderEntries();
  updateStats();
  showScreen('vault-screen');
  resetAutoLock();
  document.addEventListener('mousemove', resetAutoLock);
  document.addEventListener('keydown',   resetAutoLock);
}

function resetAutoLock() {
  clearTimeout(autoLockTimer);
  autoLockTimer = setTimeout(() => {
    lockVault();
    toast('⏱️ Auto-locked due to inactivity');
  }, AUTO_LOCK_MS);
}

// ── Save vault (encrypt to localStorage) ─────────────────────────────────────
async function saveVault() {
  const plaintext = JSON.stringify(entries);
  const encrypted = await Crypto.encrypt(plaintext, masterPassword);
  localStorage.setItem(STORAGE_KEY, encrypted);
}

// ── Render entries ─────────────────────────────────────────────────────────────
function renderEntries(list) {
  const grid  = document.getElementById('entries-grid');
  const empty = document.getElementById('empty-state');
  if (!list) list = filteredList();

  grid.innerHTML = '';

  if (list.length === 0) {
    empty.style.display = 'block';
    document.getElementById('entry-count').textContent = '';
    return;
  }

  empty.style.display = 'none';
  document.getElementById('entry-count').textContent = `${list.length} item${list.length !== 1 ? 's' : ''}`;

  list.forEach(({ entry, realIdx }) => {
    const score = scorePassword(entry.password);
    const card  = document.createElement('div');
    card.className = 'entry-card';
    card.innerHTML = `
      <div class="entry-header">
        <div class="entry-icon">${CAT_ICONS[entry.category] || '🔑'}</div>
        <span class="entry-cat-badge">${entry.category}</span>
      </div>
      <div class="entry-name">${escHtml(entry.name)}</div>
      <div class="entry-user">${escHtml(entry.username)}</div>
      <div class="entry-footer">
        <div class="strength-dot" style="background:${strengthColor(score)}" title="${strengthLabel(score)}"></div>
        <div class="entry-actions">
          <button class="entry-btn" onclick="copyPass(${realIdx},event)" title="Copy password">📋 Copy</button>
          <button class="entry-btn" onclick="openView(${realIdx},event)" title="View">View</button>
          <button class="entry-btn del" onclick="confirmDelete(${realIdx},event)" title="Delete">✕</button>
        </div>
      </div>`;
    grid.appendChild(card);
  });
}

function filteredList() {
  const q   = (document.getElementById('search-input').value || '').toLowerCase();
  const cat = activeCategory;
  return entries
    .map((e, i) => ({ entry: e, realIdx: i }))
    .filter(({ entry }) => {
      const matchCat  = cat === 'all' || entry.category === cat;
      const matchQ    = !q || entry.name.toLowerCase().includes(q) || entry.username.toLowerCase().includes(q);
      return matchCat && matchQ;
    });
}

function filterEntries()  { renderEntries(); updateStats(); }

function filterByCategory(btn) {
  document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  activeCategory = btn.dataset.cat;
  document.getElementById('vault-heading').textContent =
    activeCategory === 'all' ? 'All Passwords' : activeCategory;
  renderEntries();
}

// ── Stats ─────────────────────────────────────────────────────────────────────
function updateStats() {
  document.getElementById('stat-total').textContent = entries.length;

  const weak = entries.filter(e => scorePassword(e.password) <= 2).length;
  document.getElementById('stat-weak').textContent = weak;

  const pwMap = {};
  entries.forEach(e => { pwMap[e.password] = (pwMap[e.password] || 0) + 1; });
  const reused = entries.filter(e => pwMap[e.password] > 1).length;
  document.getElementById('stat-reused').textContent = reused;
}

// ── Add / Edit modal ──────────────────────────────────────────────────────────
function openModal(idx) {
  editIndex = idx !== undefined ? idx : null;

  document.getElementById('modal-title').textContent = editIndex !== null ? 'Edit Password' : 'Add Password';
  document.getElementById('modal-error').textContent = '';

  if (editIndex !== null) {
    const e = entries[editIndex];
    document.getElementById('f-name').value  = e.name;
    document.getElementById('f-url').value   = e.url    || '';
    document.getElementById('f-user').value  = e.username;
    document.getElementById('f-pass').value  = e.password;
    document.getElementById('f-cat').value   = e.category;
    document.getElementById('f-notes').value = e.notes  || '';
    updateModalStrength();
  } else {
    ['f-name','f-url','f-user','f-pass','f-notes'].forEach(id =>
      document.getElementById(id).value = '');
    document.getElementById('f-cat').value = 'Other';
    document.getElementById('modal-strength-bar').style.background = '';
    document.getElementById('modal-strength-bar').style.width = '0';
    document.getElementById('modal-strength-label').textContent = '';
  }

  document.getElementById('modal-overlay').classList.add('open');
  setTimeout(() => document.getElementById('f-name').focus(), 100);
}

function closeModal() { document.getElementById('modal-overlay').classList.remove('open'); }
function closeModalOutside(e) { if (e.target === document.getElementById('modal-overlay')) closeModal(); }

function updateModalStrength() {
  updateStrengthBar('f-pass', 'modal-strength-bar', 'modal-strength-label');
}

async function saveEntry() {
  const name     = document.getElementById('f-name').value.trim();
  const username = document.getElementById('f-user').value.trim();
  const password = document.getElementById('f-pass').value;
  const url      = document.getElementById('f-url').value.trim();
  const category = document.getElementById('f-cat').value;
  const notes    = document.getElementById('f-notes').value.trim();
  const err      = document.getElementById('modal-error');

  if (!name)     { err.textContent = 'Site / App Name is required.'; return; }
  if (!username) { err.textContent = 'Username / Email is required.'; return; }
  if (!password) { err.textContent = 'Password is required.'; return; }
  err.textContent = '';

  const entry = { name, username, password, url, category, notes, updatedAt: Date.now() };

  if (editIndex !== null) {
    entries[editIndex] = entry;
    toast('✅ Password updated');
  } else {
    entry.createdAt = Date.now();
    entries.push(entry);
    toast('✅ Password saved');
  }

  await saveVault();
  closeModal();
  renderEntries();
  updateStats();
}

// ── View modal ────────────────────────────────────────────────────────────────
function openView(idx, event) {
  if (event) event.stopPropagation();
  const e = entries[idx];
  document.getElementById('view-title').textContent = e.name;

  const rows = [
    { label: 'Username / Email', val: e.username, copy: true },
    { label: 'Password',         val: e.password,  copy: true, mono: true },
    e.url   ? { label: 'URL',   val: e.url  } : null,
    e.notes ? { label: 'Notes', val: e.notes } : null,
    { label: 'Category', val: e.category },
  ].filter(Boolean);

  document.getElementById('view-body').innerHTML = rows.map(r => `
    <div class="view-row">
      <label>${r.label}</label>
      <div class="view-val" style="${r.mono ? 'font-family:var(--mono)' : ''}">
        <span>${r.label === 'Password' ? '••••••••••••' : escHtml(r.val)}</span>
        ${r.copy ? `<button class="copy-inline" onclick="copyText('${escAttr(r.val)}', '${r.label}')" title="Copy">📋</button>` : ''}
      </div>
    </div>`).join('');

  document.getElementById('view-edit-btn').onclick = () => { closeView(); openModal(idx); };
  document.getElementById('view-overlay').classList.add('open');
}

function closeView() { document.getElementById('view-overlay').classList.remove('open'); }
function closeViewOutside(e) { if (e.target === document.getElementById('view-overlay')) closeView(); }

// ── Delete ────────────────────────────────────────────────────────────────────
function confirmDelete(idx, event) {
  if (event) event.stopPropagation();
  showConfirm(
    'Delete Password',
    `Delete "${entries[idx].name}"? This cannot be undone.`,
    async () => {
      entries.splice(idx, 1);
      await saveVault();
      renderEntries();
      updateStats();
      toast('🗑️ Entry deleted');
    }
  );
}

// ── Copy helpers ──────────────────────────────────────────────────────────────
async function copyPass(idx, event) {
  if (event) event.stopPropagation();
  await copyText(entries[idx].password, 'Password');
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`📋 ${label} copied!`);
  } catch {
    toast('❌ Copy failed — check browser permissions');
  }
}

// ── Password Generator ────────────────────────────────────────────────────────
let lastGenPass = '';

function openGenerator() {
  document.getElementById('gen-overlay').classList.add('open');
}

function closeGen() { document.getElementById('gen-overlay').classList.remove('open'); }
function closeGenOutside(e) { if (e.target === document.getElementById('gen-overlay')) closeGen(); }

function updateLenLabel() {
  document.getElementById('len-label').textContent = document.getElementById('gen-length').value;
}

function generatePassword() {
  const len    = +document.getElementById('gen-length').value;
  const upper  = document.getElementById('gen-upper').checked;
  const lower  = document.getElementById('gen-lower').checked;
  const num    = document.getElementById('gen-num').checked;
  const sym    = document.getElementById('gen-sym').checked;

  let chars = '';
  if (upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lower) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (num)   chars += '0123456789';
  if (sym)   chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';

  if (!chars) { document.getElementById('gen-output').textContent = 'Select at least one option'; return; }

  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  lastGenPass = Array.from(arr).map(v => chars[v % chars.length]).join('');
  document.getElementById('gen-output').textContent = lastGenPass;
}

async function copyGenPassword() {
  if (!lastGenPass) { toast('Generate a password first'); return; }
  await copyText(lastGenPass, 'Password');
}

function generateAndFill() {
  const len    = 16;
  const chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  const arr    = new Uint32Array(len);
  crypto.getRandomValues(arr);
  const pw = Array.from(arr).map(v => chars[v % chars.length]).join('');
  document.getElementById('f-pass').value = pw;
  updateModalStrength();
  toast('⚡ Strong password generated!');
}

// ── Confirm dialog ────────────────────────────────────────────────────────────
function showConfirm(title, msg, onConfirm) {
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-msg').textContent   = msg;
  document.getElementById('confirm-ok-btn').onclick    = () => { closeConfirm(); onConfirm(); };
  document.getElementById('confirm-overlay').classList.add('open');
}

function closeConfirm() { document.getElementById('confirm-overlay').classList.remove('open'); }

function confirmReset() {
  showConfirm(
    '⚠️ Reset Vault',
    'This will permanently delete ALL saved passwords and your master password. There is no recovery.',
    () => {
      localStorage.removeItem(STORAGE_KEY);
      localStorage.removeItem(META_KEY);
      show('setup-form');
      toast('Vault reset. Set a new master password.');
    }
  );
}

// ── Toggle password visibility ────────────────────────────────────────────────
function toggleVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '🙈';
  } else {
    input.type = 'password';
    btn.textContent = '👁';
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
let toastTimer;
function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

// ── Escape helpers ────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escAttr(str) {
  return String(str).replace(/'/g, '&#39;').replace(/"/g,'&quot;');
}
