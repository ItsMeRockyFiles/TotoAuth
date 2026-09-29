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

    const left = document.createElement('div');
    const label = document.createElement('div');
    label.className = 'account-label';
    label.textContent = acc.label;
    const secret = document.createElement('div');
    secret.className = 'account-secret';
    secret.textContent = acc.secret.slice(0, 4) + '···' + acc.secret.slice(-4);
    left.append(label, secret);

    const right = document.createElement('div');
    const code = document.createElement('div');
    code.className = 'account-code';
    code.textContent = '······';
    const remove = document.createElement('button');
    remove.className = 'remove';
    remove.textContent = 'Remove';
    remove.onclick = () => {
      accounts = accounts.filter(a => a.id !== acc.id);
      save(accounts);
      renderAccounts();
      tick();
    };
    right.append(code, remove);

    li.append(left, right);
    listEl.appendChild(li);
  }
}

async function tick() {
  const now = Date.now();
  const remaining = PERIOD - Math.floor(now / 1000) % PERIOD;

  for (const acc of accounts) {
    const li = listEl.querySelector(`[data-id="${acc.id}"]`);
    if (!li) continue;
    const codeEl = li.querySelector('.account-code');
    try {
      codeEl.textContent = await totp(acc.secret, now);
      codeEl.classList.toggle('expiring', remaining <= 5);
    } catch {
      codeEl.textContent = 'error';
    }
  }
}

setInterval(tick, 1000);

// --- add form ---

document.getElementById('add-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const labelEl = document.getElementById('label-input');
  const secretEl = document.getElementById('secret-input');
  const label = labelEl.value.trim();
  const secret = secretEl.value.trim().toUpperCase();
  if (!label || !secret) return;

  accounts.push({ id: crypto.randomUUID(), label, secret });
  save(accounts);
  labelEl.value = '';
  secretEl.value = '';
  renderAccounts();
  tick();
});

renderAccounts();
tick();

// --- code samples ---

const samples = {
  Python: `import hmac, hashlib, struct, time, base64

def totp(secret, digits=6, period=30):
    key = base64.b32decode(secret.upper())
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()

    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)`,

  JavaScript: `async function totp(secret, digits = 6, period = 30) {
  const counter = Math.floor(Date.now() / 1000 / period);
  const msg = new ArrayBuffer(8);
  new DataView(msg).setUint32(4, counter, false);

  const key = await crypto.subtle.importKey(
    "raw", base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));

  const offset = sig[sig.length - 1] & 0x0F;
  const binary =
    ((sig[offset] & 0x7F) << 24) |
    ((sig[offset + 1] & 0xFF) << 16) |
    ((sig[offset + 2] & 0xFF) << 8) |
    (sig[offset + 3] & 0xFF);

  return String(binary % 10 ** digits).padStart(digits, "0");
}`,

  Go: `func totp(secret string, digits, period int) string {
    key, _ := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
    counter := time.Now().Unix() / int64(period)

    msg := make([]byte, 8)
    binary.BigEndian.PutUint64(msg, uint64(counter))

    mac := hmac.New(sha1.New, key)
    mac.Write(msg)
    digest := mac.Sum(nil)

    offset := digest[len(digest)-1] & 0x0F
    binary := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7FFFFFFF
    code := binary % uint32(math.Pow10(digits))
    return fmt.Sprintf("%0*d", digits, code)
}`,

  Rust: `fn totp(secret: &str, digits: u32, period: u64) -> String {
    let key = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
        .expect("invalid secret");
    let counter = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap().as_secs() / period;

    let mut mac = Hmac::<Sha1>::new_from_slice(&key).unwrap();
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[19] & 0x0F) as usize;
    let binary = u32::from_be_bytes([
        digest[offset], digest[offset + 1],
        digest[offset + 2], digest[offset + 3],
    ]) & 0x7FFF_FFFF;

    format!("{:0width$}", binary % 10u32.pow(digits), width = digits as usize)
}`,
};

const tabsEl = document.getElementById('tabs');
const codeEl = document.getElementById('code');

Object.keys(samples).forEach((lang, i) => {
  const btn = document.createElement('button');
  btn.textContent = lang;
  if (i === 0) btn.classList.add('active');
  btn.onclick = () => {
    [...tabsEl.children].forEach(b => b.classList.toggle('active', b === btn));
    codeEl.textContent = samples[lang];
  };
  tabsEl.appendChild(btn);
});

codeEl.textContent = samples[Object.keys(samples)[0]];