const STORAGE_KEY = 'totoauth.accounts';
const PERIOD = 30;
const DIGITS = 6;

// --- TOTP ---

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input) {
  const clean = input.replace(/[\s=-]/g, '').toUpperCase();
  let bits = 0, value = 0;
  const bytes = [];
  for (const ch of clean) {
    const i = B32.indexOf(ch);
    if (i === -1) continue;
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

async function totp(secret, time = Date.now()) {
  const counter = Math.floor(time / 1000 / PERIOD);

  const msg = new ArrayBuffer(8);
  new DataView(msg).setUint32(4, counter, false);

  const key = await crypto.subtle.importKey(
    'raw',
    base32Decode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset]     & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8)  |
    (sig[offset + 3]  & 0xff);

  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

// --- storage ---

function load() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
  catch { return []; }
}

function save(accounts) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts));
}

// --- rendering ---

let accounts = load();
const listEl = document.getElementById('accounts');
const RING_R = 10;
const RING_C = 2 * Math.PI * RING_R;

function renderAccounts() {
  listEl.innerHTML = '';

  if (accounts.length === 0) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = 'No accounts yet.';
    listEl.appendChild(li);
    return;
  }

  for (const acc of accounts) {
    const li = document.createElement('li');
    li.dataset.id = acc.id;

    const info = document.createElement('div');
    info.className = 'account-info';

    const platform = document.createElement('div');
    platform.className = 'account-platform';
    platform.textContent = acc.platform;

    const username = document.createElement('div');
    username.className = 'account-username';
    username.textContent = acc.username;

    info.append(platform, username);

    const right = document.createElement('div');
    right.className = 'account-right';

    const code = document.createElement('div');
    code.className = 'account-code';
    code.textContent = '······';

    const timer = document.createElement('div');
    timer.className = 'timer';
    timer.innerHTML = `
      <svg width="26" height="26" viewBox="0 0 26 26">
        <circle class="track" cx="13" cy="13" r="${RING_R}"></circle>
        <circle class="progress" cx="13" cy="13" r="${RING_R}"
          stroke-dasharray="${RING_C}"
          stroke-dashoffset="0"></circle>
      </svg>
      <span class="timer-text"></span>
    `;

    const remove = document.createElement('button');
    remove.className = 'remove';
    remove.textContent = 'Remove';
    remove.onclick = () => {
      accounts = accounts.filter(a => a.id !== acc.id);
      save(accounts);
      renderAccounts();
      tick();
    };

    right.append(code, timer, remove);
    li.append(info, right);
    listEl.appendChild(li);
  }
}

async function tick() {
  const now = Date.now();
  const elapsed = (now / 1000) % PERIOD;
  const secondsLeft = Math.ceil(PERIOD - elapsed);

  for (const acc of accounts) {
    const li = listEl.querySelector(`[data-id="${acc.id}"]`);
    if (!li) continue;

    const codeEl = li.querySelector('.account-code');
    const timerEl = li.querySelector('.timer');
    const progressEl = li.querySelector('.progress');
    const textEl = li.querySelector('.timer-text');

    try {
      codeEl.textContent = await totp(acc.secret, now);
    } catch {
      codeEl.textContent = 'error';
    }

    const expiring = secondsLeft <= 5;
    codeEl.classList.toggle('expiring', expiring);
    timerEl.classList.toggle('expiring', expiring);

    textEl.textContent = secondsLeft;
    progressEl.style.strokeDashoffset = RING_C * (elapsed / PERIOD);
  }
}

setInterval(tick, 1000);

// --- add form ---

document.getElementById('add-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const platformEl = document.getElementById('platform-input');
  const usernameEl = document.getElementById('username-input');
  const secretEl = document.getElementById('secret-input');

  const platform = platformEl.value.trim();
  const username = usernameEl.value.trim();
  const secret = secretEl.value.trim().toUpperCase();
  if (!platform || !username || !secret) return;

  accounts.push({ id: crypto.randomUUID(), platform, username, secret });
  save(accounts);

  platformEl.value = '';
  usernameEl.value = '';
  secretEl.value = '';

  renderAccounts();
  tick();
});

renderAccounts();
tick();