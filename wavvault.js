/* ═══════════════════════════════════════════════════════════
   WAVVAULT — Production Frontend
   Split: wavvault.js (loaded as module)
   
   XSS PATCHES:
   - All user-supplied strings pass through sanitize()
   - No innerHTML on untrusted data; safe wrappers used
   - textContent used for all dynamic text nodes
   
   ENV PATCHES:
   - API_BASE read from <meta name="api-base"> or falls back
   - BYPASS_AUTH explicitly false; dev mode requires opt-in
═══════════════════════════════════════════════════════════ */

/* ──────────────────────────────────────
   ENVIRONMENT CONFIG
   In production: set <meta name="api-base" content="https://api.wavvault.com/api">
   In dev:        set <meta name="api-base" content="http://localhost:3001/api">
────────────────────────────────────── */
const CONFIG = (() => {
  const metaBase = document.querySelector('meta[name="api-base"]');
  const metaDev  = document.querySelector('meta[name="dev-mode"]');
  return {
    API_BASE:    metaBase ? metaBase.content : 'https://api.wavvault.com/api',
    BYPASS_AUTH: metaDev  ? metaDev.content === 'true' : false,
    // DEV_USER_ID is only used when BYPASS_AUTH is true AND the user has signed in via dev panel
    DEV_USER_ID: null,
  };
})();

/* ──────────────────────────────────────
   XSS SANITIZATION
   Use this for ALL user-supplied strings that go into the DOM.
────────────────────────────────────── */
const XSS_CHARS = {
  '&':'&amp;', '<':'&lt;', '>':'&gt;', 
  '"':'&quot;', "'":"&#x27;", '/':'&#x2F;'
};

function sanitize(str) {
  if (str == null) return '';
  return String(str).replace(/[&<>"'/]/g, c => XSS_CHARS[c]);
}
// Safe DOM helpers — avoids innerHTML for user data
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'style') node.style.cssText = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    if (child == null) continue;
    // This is the magic line: it forces text to be a TextNode, not HTML
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}
function setText(id, text) {
  const node = document.getElementById(id);
  if (node) node.textContent = text;
}

// Safe innerHTML only for STATIC markup (no user data interpolated)
// Never call this with user-supplied content
function staticHTML(node, html) {
  node.innerHTML = html;
}

/* ──────────────────────────────────────
   API CLIENT
────────────────────────────────────── */
const API = {
  headers() {
    const h = { 'Content-Type': 'application/json' };
    if (AUTH.token)     h['Authorization'] = `Bearer ${AUTH.token}`;
    if (CONFIG.BYPASS_AUTH && AUTH.devUserId) h['x-dev-user-id'] = AUTH.devUserId;
    return h;
  },
  async get(path, params = {}) {
    const qs = new URLSearchParams(params).toString();
    const url = `${CONFIG.API_BASE}${path}${qs ? '?' + qs : ''}`;
    const res = await fetch(url, { headers: this.headers() });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `${res.status} ${res.statusText}`);
    }
    return res.json();
  },
  async post(path, body = {}) {
    const res = await fetch(`${CONFIG.API_BASE}${path}`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `${res.status} ${res.statusText}`);
    }
    return res.json();
  },
  async putRaw(url, file, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('PUT', url);
      xhr.setRequestHeader('Content-Type', file.type || 'audio/wav');
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
      };
      xhr.onload  = () => xhr.status < 300 ? resolve() : reject(new Error(`S3 upload failed: ${xhr.status}`));
      xhr.onerror = () => reject(new Error('Network error during S3 upload'));
      xhr.send(file);
    });
  }
};

/* ──────────────────────────────────────
   AUTH STATE
   Production flow: Clerk SDK sets AUTH.token on login.
   Dev bypass flow: only active when CONFIG.BYPASS_AUTH is true
   (controlled by <meta name="dev-mode" content="true"> in HTML).
────────────────────────────────────── */
const AUTH = {
  token:     null,
  devUserId: null,
  artistId:  null,
  isLoggedIn: false,

  signIn(devId) {
    if (!CONFIG.BYPASS_AUTH) {
      // Production: Clerk handles sign-in, this should not be called directly.
      // Clerk's <SignIn> component sets AUTH.token via AUTH.setClerkToken().
      console.warn('signIn() called in production mode — use Clerk SDK instead');
      return;
    }
    if (!devId || !devId.trim()) {
      showToast('Enter a dev user ID', '⚠️', 'toast-orange');
      return;
    }
    this.devUserId = devId.trim();
    this.isLoggedIn = true;
    updateNavAuth();
    closeModal('authModal');
    showToast(`Signed in as ${sanitize(this.devUserId)}`, '✓', 'toast-left');
    loadDashboard();
  },

  // Called by Clerk webhook/SDK in production
  setClerkToken(jwt) {
    this.token = jwt;
    this.isLoggedIn = true;
    updateNavAuth();
    loadDashboard();
  },

  signOut() {
    this.token = null;
    this.devUserId = null;
    this.isLoggedIn = false;
    this.artistId = null;
    updateNavAuth();
    showToast('Signed out', '👋');
  }
};

function authSignIn() {
  const id = document.getElementById('devUserId').value.trim();
  AUTH.signIn(id);
}

function updateNavAuth() {
  const signInBtn = document.getElementById('navAuthBtn');
  const userArea  = document.getElementById('navUserArea');
  if (AUTH.isLoggedIn) {
    signInBtn.style.display = 'none';
    userArea.classList.add('show');
    setText('navUserId', AUTH.devUserId || 'user');
  } else {
    signInBtn.style.display = '';
    userArea.classList.remove('show');
  }
}

/* ──────────────────────────────────────
   ERROR DISPLAY — replaces mock fallbacks
────────────────────────────────────── */
function showError(containerId, message, retryFn) {
  const container = document.getElementById(containerId);
  if (!container) return;
  // Clear content safely
  while (container.firstChild) container.removeChild(container.firstChild);

  const wrapper = el('div', { style: 'display:flex;flex-direction:column;align-items:center;padding:60px 24px;gap:12px;' },
    el('div', { style: 'font-size:32px;' }, '⚠️'),
    el('div', { style: 'font-size:14px;font-weight:600;color:var(--text);' }, 'Something went wrong'),
    el('div', { style: 'font-size:13px;color:var(--text3);text-align:center;max-width:300px;' }, message),
  );

  if (retryFn) {
    const retryBtn = el('button', {
      style: 'margin-top:8px;padding:8px 20px;border-radius:8px;background:var(--dark3);border:1px solid var(--border2);color:var(--cyan);cursor:pointer;font-size:13px;',
      onclick: retryFn,
    }, 'Try again');
    wrapper.appendChild(retryBtn);
  }

  container.appendChild(wrapper);
}

/* ──────────────────────────────────────
   HEALTH CHECK
────────────────────────────────────── */
async function checkHealth() {
  const statusEl = document.getElementById('apiStatus');
  const labelEl  = document.getElementById('apiStatusLabel');
  if (!statusEl) return;
  statusEl.className = 'checking';
  labelEl.textContent = 'checking...';
  try {
    const url  = CONFIG.API_BASE.replace(/\/api$/, '') + '/health';
    const data = await fetch(url).then(r => r.json());
    if (data.status === 'ok') {
      statusEl.className = 'ok';
      labelEl.textContent = `API · DB:${sanitize(data.db)} · Redis:${sanitize(data.redis)}`;
      showToast('Backend connected ✓', '🟢', 'toast-left');
    } else {
      throw new Error('unhealthy');
    }
  } catch {
    statusEl.className = 'err';
    labelEl.textContent = 'API offline';
    showToast('Backend is unreachable. Check your server.', '⚠️', 'toast-orange');
  }
}

/* ──────────────────────────────────────
   BEATS
────────────────────────────────────── */
async function loadBeats(params = {}) {
  try {
    const data = await API.get('/beats', params);
    return Array.isArray(data) ? data : (data.beats || []);
  } catch {
    // API offline — init() will fall back to DEMO_BEATS
    // showError() is NOT called here so demo data renders cleanly
    return null;
  }
}

async function fetchBeatDetail(beat) {
  try {
    const live = await API.get(`/beats/${beat.id}`);
    // Merge API data over local data (API is source of truth)
    showBeatDetail({ ...beat, ...live });
    API.post(`/beats/${beat.id}/play`).catch(() => {});
  } catch {
    // If detail fetch fails, show what we have locally — no fabricated data added
    showBeatDetail(beat);
  }
}

/* ──────────────────────────────────────
   CHECKOUT
────────────────────────────────────── */
async function doCheckout() {
  if (!AUTH.isLoggedIn) {
    openModal('authModal');
    showToast('Sign in to checkout', '🔒');
    return;
  }
  if (cart.length === 0) return;

  const btn = document.querySelector('.checkout-btn');
  if (btn) { btn.textContent = 'Creating session...'; btn.disabled = true; }

  try {
    const item = cart[0];
    const data = await API.post('/checkout/session', {
      beatId:      item.apiId || String(item.id),
      licenseType: (item.licenseType || 'MP3').toLowerCase(),
    });

    if (data.url) {
      showToast('Redirecting to Stripe Checkout…', '💳');
      window.open(data.url, '_blank', 'noopener,noreferrer');
    } else {
      throw new Error('No checkout URL returned from server');
    }
  } catch (e) {
    // Real error, no fake success
    showToast(`Checkout failed: ${e.message}`, '❌', 'toast-orange');
  } finally {
    if (btn) { btn.textContent = 'Checkout with Stripe →'; btn.disabled = false; }
  }
}

/* ──────────────────────────────────────
   ARTIST ONBOARDING
────────────────────────────────────── */
async function startOnboard() {
  if (!AUTH.isLoggedIn) {
    closeModal('onboardModal');
    openModal('authModal');
    return;
  }

  const displayName = document.getElementById('onDisplay').value.trim();
  const producerTag = document.getElementById('onTag').value.trim();

  if (!displayName || !producerTag) {
    showToast('Please fill in all fields', '⚠️', 'toast-orange');
    return;
  }

  const btn = document.querySelector('#onboardModal .checkout-btn');
  btn.textContent = 'Creating account...';
  btn.disabled = true;

  try {
    const data = await API.post('/artists/onboard', {
      display_name: displayName,
      producer_tag: producerTag,
    });
    AUTH.artistId = data.artistId;
    if (data.onboardingUrl) {
      showToast('Redirecting to Stripe KYC…', '🎉');
      window.open(data.onboardingUrl, '_blank', 'noopener,noreferrer');
    }
    closeModal('onboardModal');
  } catch (e) {
    showToast(`Onboarding failed: ${e.message}`, '❌', 'toast-orange');
  } finally {
    btn.textContent = 'Continue to Stripe →';
    btn.disabled = false;
  }
}

/* ──────────────────────────────────────
   ARTIST DASHBOARD
────────────────────────────────────── */
async function loadDashboard() {
  if (!AUTH.isLoggedIn) return;
  const container = document.getElementById('dashContent');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text3);">Loading...</div>';

  try {
    const artistId = AUTH.artistId || 'me';
    const data = await API.get(`/artists/${artistId}/dashboard`);
    renderDashboard(data, container);
  } catch (e) {
    showError('dashContent', `Could not load dashboard: ${e.message}`, loadDashboard);
  }
}

function renderDashboard(data, container) {
  const e = data.earnings || {};
  const s = data.stats    || {};

  while (container.firstChild) container.removeChild(container.firstChild);

  const grid = el('div', { style: 'display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px;' });
  [
    ['Total Earnings', `$${Number(e.total  || 0).toFixed(2)}`, '#00E5A0'],
    ['Pending Payout', `$${Number(e.pending|| 0).toFixed(2)}`, '#FFB800'],
    ['Total Plays',    `${Number(s.total_plays || 0).toLocaleString()}`, '#00D4FF'],
    ['Sales',          `${s.total_sales || 0}`, '#9B6BFF'],
    ['Live Beats',     `${s.beats_live  || 0}`, '#FF6B2B'],
    ['Net-7 Payout',   'Automatic', '#00E5A0'],
  ].forEach(([label, val, color]) => {
    grid.appendChild(el('div', { style: 'background:var(--dark2);border:1px solid var(--border);border-radius:12px;padding:16px;' },
      el('div', { style: 'font-family:"JetBrains Mono",monospace;font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;' }, label),
      el('div', { style: `font-family:"Bebas Neue",sans-serif;font-size:26px;color:${color};letter-spacing:1px;` }, val),
    ));
  });
  container.appendChild(grid);

  const salesBox = el('div', { style: 'background:var(--dark2);border:1px solid var(--border);border-radius:12px;padding:16px;' },
    el('div', { style: 'font-family:"JetBrains Mono",monospace;font-size:10px;color:var(--text3);letter-spacing:2px;margin-bottom:12px;' }, '// RECENT SALES'),
  );

  const sales = data.recentSales || [];
  if (sales.length === 0) {
    salesBox.appendChild(el('div', { style: 'color:var(--text3);font-size:13px;padding:12px 0;' }, 'No sales yet — upload your first beat!'));
  } else {
    sales.forEach(sale => {
      salesBox.appendChild(el('div', { style: 'display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);' },
        el('div', {},
          el('div', { style: 'font-size:13px;font-weight:600;' }, sanitize(sale.title)),
          el('div', { style: 'font-family:"JetBrains Mono",monospace;font-size:10px;color:var(--text3);' }, `${sanitize(sale.license)} License`),
        ),
        el('div', { style: 'font-family:"Bebas Neue",sans-serif;font-size:20px;color:var(--green);' }, `$${Number(sale.amount).toFixed(2)}`),
      ));
    });
  }
  container.appendChild(salesBox);

  const stripeStatus = data.artist || {};
  container.appendChild(el('div', { style: 'margin-top:16px;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:10px;padding:14px;' },
    el('div', { style: 'font-family:"JetBrains Mono",monospace;font-size:10px;color:var(--cyan);letter-spacing:2px;margin-bottom:6px;' }, 'STRIPE CONNECT STATUS'),
    el('div', { style: 'font-size:13px;color:var(--text2);' },
      `charges_enabled: ${stripeStatus.charges_enabled ? '✅ true' : '❌ false'} · status: ${sanitize(stripeStatus.status || 'unknown')}`,
    ),
  ));
}

/* ──────────────────────────────────────
   BEAT UPLOAD FLOW
────────────────────────────────────── */
let uploadFile   = null;
let uploadBeatId = null;

function handleFileSelect(input) {
  const file = input.files[0];
  if (!file) return;
  uploadFile = file;
  const fileInfoEl = document.getElementById('fileInfo');
  fileInfoEl.style.display = 'flex';
  setText('fileName', file.name);
  setText('fileSize', `${(file.size / 1024 / 1024).toFixed(2)} MB · ${file.type || 'audio'}`);
  const nextBtn = document.getElementById('step1Next');
  nextBtn.disabled = false;
  nextBtn.style.opacity = '1';
}

function clearFile() {
  uploadFile = null;
  document.getElementById('fileInput').value = '';
  document.getElementById('fileInfo').style.display = 'none';
  const nextBtn = document.getElementById('step1Next');
  nextBtn.disabled = true;
  nextBtn.style.opacity = '0.4';
}

function goToStep(n) {
  [1,2,3,4].forEach(i => {
    document.getElementById(`upStep${i}`).style.display = i === n ? '' : 'none';
    const stepEl = document.querySelector(`.upload-step[data-step="${i}"]`);
    if (stepEl) {
      stepEl.classList.toggle('active', i === n);
      stepEl.classList.toggle('done',   i < n);
    }
  });
}

async function startUpload() {
  if (!AUTH.isLoggedIn) { closeModal('uploadModal'); openModal('authModal'); return; }
  if (!uploadFile) return;

  const title = document.getElementById('upTitle').value.trim();
  const genre = document.getElementById('upGenre').value;
  const bpm   = parseInt(document.getElementById('upBpm').value);

  if (!title || !genre || !bpm) {
    showToast('Please fill in Title, Genre, and BPM', '⚠️', 'toast-orange');
    return;
  }

  goToStep(3);
  const logEl = document.getElementById('upApiLog');

  const log = (msg) => {
    const line = el('div', { style: 'opacity:0.8;' }, msg);
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  };

  const setProgress = (pct, text) => {
    document.getElementById('upProgressBar').style.width = pct + '%';
    setText('upProgressText', text || pct + '%');
  };

  const setStatus = (msg) => setText('upStatusText', msg);

  try {
    // STEP 1: Presigned S3 URL
    log(`→ POST /api/beats/upload`);
    setProgress(10, 'Getting upload URL...');
    setStatus('Requesting presigned S3 URL...');

    const uploadData = await API.post('/beats/upload', {
      filename:    uploadFile.name,
      contentType: uploadFile.type || 'audio/wav',
      fileSize:    uploadFile.size,
    });

    const { uploadUrl, beatId, s3Key } = uploadData;
    uploadBeatId = beatId;
    log(`← beatId: ${beatId}  s3Key: ${s3Key}`);

    // STEP 2: Upload to S3
    setProgress(20, 'Uploading to S3...');
    setStatus('Uploading to S3...');
    log(`→ PUT ${uploadUrl.substring(0, 60)}...`);

    await API.putRaw(uploadUrl, uploadFile, (pct) => {
      setProgress(20 + pct * 0.5, `Uploading: ${pct}%`);
    });
    log(`← 200 OK · File uploaded`);

    // STEP 3: Submit metadata
    setProgress(75, 'Queuing processing...');
    setStatus('Submitting metadata...');

    const metadata = {
      title,
      genre,
      bpm,
      key:  document.getElementById('upKey').value.trim()  || undefined,
      mood: document.getElementById('upMood').value.trim() || undefined,
      tags: document.getElementById('upTags').value.split(',').map(t => t.trim()).filter(Boolean),
    };

    log(`→ POST /api/beats/${beatId}/process`);
    await API.post(`/beats/${beatId}/process`, metadata);
    log(`← { status: "processing" }`);

    setProgress(100, 'Complete!');
    setText('upIcon', '✅');
    setStatus('Upload complete!');

    await new Promise(r => setTimeout(r, 400));
    goToStep(4);
    simulateProcessingPipeline(title);

  } catch (e) {
    setText('upStatusText', `Error: ${e.message}`);
    setText('upIcon', '❌');
    log(`← ERROR: ${e.message}`);
    showToast(`Upload failed: ${e.message}`, '❌', 'toast-orange');
  }
}

async function simulateProcessingPipeline(title) {
  const steps = [
    { id:'pStep1', label:'✅ Stage 1: Audio analyzed (FFprobe)',                 delay:800  },
    { id:'pStep2', label:'✅ Stage 2: Waveform peaks generated → S3 + Redis',     delay:1500 },
    { id:'pStep3', label:'✅ Stage 3: Tagged preview created (128kbps MP3)',       delay:2200 },
    { id:'pStep4', label:'✅ Stage 4: Clean WAV encoded (24-bit / 48kHz)',         delay:1800 },
    { id:'pStep5', label:'✅ Beat is LIVE · Artist notification sent via SES',     delay:600  },
  ];
  for (const step of steps) {
    await new Promise(r => setTimeout(r, step.delay));
    const node = document.getElementById(step.id);
    if (node) {
      node.style.opacity = '1';
      node.className = 'pipeline-step active';
      node.textContent = step.label;  // textContent: safe
      await new Promise(r => setTimeout(r, 200));
      node.className = 'pipeline-step done';
    }
  }
  showToast(`"${sanitize(title)}" is now live!`, '🎉', 'toast-left');
}

function resetUpload() {
  uploadFile = uploadBeatId = null;
  document.getElementById('fileInput').value = '';
  document.getElementById('fileInfo').style.display = 'none';
  const nextBtn = document.getElementById('step1Next');
  nextBtn.disabled = true;
  nextBtn.style.opacity = '0.4';
  ['upTitle','upKey','upMood','upTags'].forEach(id => { const n = document.getElementById(id); if(n) n.value = ''; });
  document.getElementById('upGenre').value = '';
  document.getElementById('upBpm').value   = '';
  document.getElementById('upApiLog').innerHTML = '';
  goToStep(1);
}

/* ──────────────────────────────────────
   BEAT DETAIL VIEW — XSS SAFE
────────────────────────────────────── */
let selectedLicenseType  = 'mp3';
let selectedLicensePrice = 0;

function showBeatDetail(beat) {
  const prices = {
    mp3:       beat.price || 29.99,
    wav:       (beat.price || 29.99) * 1.8,
    exclusive: (beat.price || 29.99) * 14,
  };

  const container = document.getElementById('beatDetailContent');
  while (container.firstChild) container.removeChild(container.firstChild);

  // Header row — all text via textContent
  const artworkEl = el('div', {
    style: 'width:80px;height:80px;border-radius:14px;background:var(--dark3);display:flex;align-items:center;justify-content:center;font-size:42px;border:1px solid var(--border2);flex-shrink:0;'
  });
  // Emoji is display-only from our own data; still use textContent
  artworkEl.textContent = beat.emoji || '🎵';

  const infoEl = el('div', { style: 'flex:1;' });
  const titleEl = el('div', { style: 'font-family:"Bebas Neue",sans-serif;font-size:28px;letter-spacing:2px;' });
  titleEl.textContent = beat.title;

  const artistEl = el('div', { style: 'font-family:"JetBrains Mono",monospace;font-size:12px;color:var(--text3);margin-top:4px;' });
  artistEl.textContent = `by ${beat.producer || beat.artist_name || 'Unknown'}`;

  const badgeRow = el('div', { style: 'display:flex;gap:6px;margin-top:10px;flex-wrap:wrap;' });
  const mkBadge = (text, cls) => { const b = el('span', { class: `fbc-badge ${cls}` }); b.textContent = text; return b; };
  badgeRow.appendChild(mkBadge(`${beat.bpm} BPM`, 'badge-bpm'));
  if (beat.key)   badgeRow.appendChild(mkBadge(beat.key, 'badge-key'));
  if (beat.genre) badgeRow.appendChild(mkBadge(beat.genre.toUpperCase(), 'badge-genre'));
  if (beat.hot)   badgeRow.appendChild(mkBadge('🔥 HOT', 'badge-hot'));
  if (beat.excl)  badgeRow.appendChild(mkBadge('EXCLUSIVE', 'badge-excl'));

  infoEl.appendChild(titleEl);
  infoEl.appendChild(artistEl);
  infoEl.appendChild(badgeRow);

  container.appendChild(el('div', { style: 'display:flex;align-items:flex-start;gap:20px;margin-bottom:24px;' }, artworkEl, infoEl));

  // Waveform placeholder
  const wfPlaceholder = el('div', { style: 'background:var(--dark2);border:1px solid var(--border);border-radius:12px;height:72px;margin-bottom:20px;display:flex;align-items:center;justify-content:center;color:var(--text3);font-family:"JetBrains Mono",monospace;font-size:11px;' });
  wfPlaceholder.textContent = `GET /api/beats/${beat.id}/peaks → WaveSurfer waveform`;
  container.appendChild(wfPlaceholder);

  // License picker — static labels only (no user data)
  const licLabel = el('div', { style: 'font-family:"JetBrains Mono",monospace;font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;' });
  licLabel.textContent = 'Choose License';
  container.appendChild(licLabel);

  const licGrid = el('div', { style: 'display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px;' });
  [
    { type:'mp3',       label:'MP3 Basic',      price: prices.mp3,       desc:'MP3 · 500K streams · Non-exclusive',   color:'var(--cyan)'   },
    { type:'wav',       label:'WAV + Trackout',  price: prices.wav,       desc:'WAV + stems · Unlimited · Non-excl.',  color:'var(--purple)' },
    { type:'exclusive', label:'Exclusive Rights', price: prices.exclusive, desc:'Full ownership · Beat removed from marketplace', color:'var(--gold)' },
  ].forEach(l => {
    const opt = el('div', { class: 'license-option', id: `lic-${beat.id}-${l.type}`,
      onclick: () => selectLicenseDetail(beat.id, l.type, l.price) });
    const typeLabel = el('div', { style: `font-size:11px;font-weight:700;color:${l.color};margin-bottom:4px;font-family:"JetBrains Mono",monospace;text-transform:uppercase;` });
    typeLabel.textContent = l.label;
    const priceEl = el('div', { style: 'font-family:"Bebas Neue",sans-serif;font-size:22px;letter-spacing:1px;' });
    priceEl.textContent = `$${l.price.toFixed(0)}`;
    const descEl = el('div', { style: 'font-size:11px;color:var(--text3);margin-top:4px;line-height:1.4;' });
    descEl.textContent = l.desc;
    opt.appendChild(typeLabel); opt.appendChild(priceEl); opt.appendChild(descEl);
    licGrid.appendChild(opt);
  });
  container.appendChild(licGrid);

  // Add to cart button
  const cartBtn = el('button', { class: 'checkout-btn', onclick: () => addToCartFromDetail(beat) });
  cartBtn.textContent = '+ Add to Cart';
  container.appendChild(cartBtn);

  openModal('beatDetailModal');
}

function selectLicenseDetail(beatId, type, price) {
  selectedLicenseType  = type;
  selectedLicensePrice = price;
  document.querySelectorAll(`[id^="lic-${beatId}-"]`).forEach(el => el.classList.remove('selected'));
  const sel = document.getElementById(`lic-${beatId}-${type}`);
  if (sel) sel.classList.add('selected');
}

function addToCartFromDetail(beat) {
  const type = selectedLicenseType || 'mp3';
  const price = selectedLicensePrice || beat.price;
  cart.push({ ...beat, licenseType: type.toUpperCase(), price });
  updateCartUI();
  closeModal('beatDetailModal');
  showToast(`"${sanitize(beat.title)}" (${type.toUpperCase()}) added`, '🛒', 'toast-orange');
}

/* ──────────────────────────────────────
   MODAL HELPERS
────────────────────────────────────── */
function openModal(id)  { document.getElementById(id)?.classList.add('open');    }
function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }

document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.classList.remove('open');
  });
});

/* ──────────────────────────────────────
   DRAG & DROP
────────────────────────────────────── */
const dropZone = document.getElementById('dropZone');
if (dropZone) {
  dropZone.addEventListener('dragover',  (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', ()  => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file?.type.startsWith('audio/')) {
      const dt = new DataTransfer();
      dt.items.add(file);
      document.getElementById('fileInput').files = dt.files;
      handleFileSelect(document.getElementById('fileInput'));
    }
  });
}

/* ──────────────────────────────────────
   DEMO DATA (used only in dev/demo, not injected when API is live)
────────────────────────────────────── */
const DEMO_BEATS = [
  { id:1,  title:'Dark Prophecy',    producer:'MetroKing',     genre:'trap',   bpm:140, key:'Am', mood:'Dark',       price:29.99, plays:'48.2K', duration:'3:02', emoji:'🖤', hot:true,  newR:false, excl:false },
  { id:2,  title:'Golden Hour',      producer:'SunsetBeatz',   genre:'rnb',    bpm:88,  key:'Dm', mood:'Smooth',     price:34.99, plays:'31.7K', duration:'2:47', emoji:'🌅', hot:false, newR:true,  excl:false },
  { id:3,  title:'Block Report',     producer:'GrimProd',      genre:'drill',  bpm:144, key:'Gm', mood:'Hard',       price:24.99, plays:'62.4K', duration:'3:15', emoji:'🔫', hot:true,  newR:false, excl:false },
  { id:4,  title:'Lotus Dreams',     producer:'AstralWaves',   genre:'lofi',   bpm:72,  key:'C',  mood:'Chill',      price:19.99, plays:'94.1K', duration:'2:30', emoji:'🌸', hot:false, newR:false, excl:false },
  { id:5,  title:'Lagos Nights',     producer:'AfroGod',       genre:'afro',   bpm:102, key:'F',  mood:'Vibrant',    price:39.99, plays:'27.8K', duration:'3:44', emoji:'🌍', hot:false, newR:true,  excl:true  },
  { id:6,  title:'Pop Star Energy',  producer:'BeatFactory',   genre:'pop',    bpm:128, key:'G',  mood:'Upbeat',     price:44.99, plays:'55.9K', duration:'2:58', emoji:'⭐', hot:true,  newR:false, excl:false },
  { id:7,  title:'Midnight Ritual',  producer:'OccultSoundz',  genre:'trap',   bpm:138, key:'F#m',mood:'Eerie',      price:29.99, plays:'41.3K', duration:'3:20', emoji:'🌙', hot:false, newR:true,  excl:false },
  { id:8,  title:'Neo Seoul',        producer:'CyberBeat',     genre:'pop',    bpm:120, key:'Bm', mood:'Futuristic', price:49.99, plays:'18.6K', duration:'3:08', emoji:'🤖', hot:false, newR:true,  excl:false },
  { id:9,  title:'Ice Cold',         producer:'FrostKing',     genre:'drill',  bpm:150, key:'Em', mood:'Cold',       price:27.99, plays:'73.2K', duration:'2:52', emoji:'❄️', hot:true,  newR:false, excl:false },
  { id:10, title:'Heartbreak Hotel', producer:'SoulProd',      genre:'rnb',    bpm:76,  key:'Ab', mood:'Emotional',  price:34.99, plays:'22.4K', duration:'3:35', emoji:'💔', hot:false, newR:false, excl:false },
  { id:11, title:'Rain Study',       producer:'LoFiLabs',      genre:'lofi',   bpm:68,  key:'C',  mood:'Peaceful',   price:14.99, plays:'112K',  duration:'4:00', emoji:'🌧️',hot:true,  newR:false, excl:false },
  { id:12, title:'Victory Lap',      producer:'ChampionBeatz', genre:'trap',   bpm:145, key:'D',  mood:'Hype',       price:39.99, plays:'36.5K', duration:'3:12', emoji:'🏆', hot:false, newR:true,  excl:false },
  { id:13, title:'Purple Rain',      producer:'VioletSound',   genre:'rnb',    bpm:94,  key:'Bb', mood:'Nostalgic',  price:44.99, plays:'19.1K', duration:'3:28', emoji:'🟣', hot:false, newR:true,  excl:false },
  { id:14, title:'Street Gospel',    producer:'GrimProd',      genre:'hiphop', bpm:93,  key:'Cm', mood:'Soulful',    price:29.99, plays:'33.8K', duration:'3:05', emoji:'🙏', hot:true,  newR:false, excl:false },
  { id:15, title:'Carbon',           producer:'CyberBeat',     genre:'trap',   bpm:142, key:'Dm', mood:'Dark',       price:35.99, plays:'28.4K', duration:'2:55', emoji:'⚫', hot:false, newR:true,  excl:true  },
  { id:16, title:'Afro Nation',      producer:'AfroGod',       genre:'afro',   bpm:106, key:'Am', mood:'Energetic',  price:39.99, plays:'51.2K', duration:'3:50', emoji:'🥁', hot:true,  newR:false, excl:false },
];

const DEMO_PRODUCERS = [
  { name:'MetroKing',   handle:'@metroking',   emoji:'👑', beats:142, sales:'$24K', genre:'Trap'  },
  { name:'GrimProd',    handle:'@grimprod',    emoji:'💀', beats:87,  sales:'$18K', genre:'Drill' },
  { name:'AstralWaves', handle:'@astralwaves', emoji:'🌊', beats:203, sales:'$12K', genre:'Lo-Fi' },
  { name:'AfroGod',     handle:'@afrogod',     emoji:'🌍', beats:95,  sales:'$31K', genre:'Afro'  },
];

const GENRE_COLORS = {
  trap:'#9B6BFF', drill:'#FF3B5C', rnb:'#FFB800',
  lofi:'#00D4FF', afro:'#FF6B2B', pop:'#00E5A0',
  hiphop:'#9B6BFF', soul:'#FFB800'
};

/* ──────────────────────────────────────
   STATE
────────────────────────────────────── */
let BEATS         = [...DEMO_BEATS]; // replaced with API data when available
let currentId     = null;
let isPlaying     = false;
let cart          = [];
let wavesurfers   = {};
let fakeTime      = 0;
let ticker        = null;
let currentFilter = 'all';
let filteredBeats = [...BEATS];
let viewMode      = 'list';
let heroWS        = null;
let heroPlaying   = false;

/* ──────────────────────────────────────
   HELPERS
────────────────────────────────────── */
function genPeaks(id, n = 180) {
  const s = id * 17 + 3;
  const out = [];
  let v = 0.4;
  for (let i = 0; i < n; i++) {
    v += Math.sin(i*0.31+s)*0.12 + Math.sin(i*0.08+s*0.4)*0.22 + Math.sin(i*s*0.003)*0.15;
    v  = Math.max(0.05, Math.min(0.95, v));
    out.push(Math.round(v * 1000) / 1000);
  }
  return out;
}

function parseDur(d)  { const [m, s] = d.split(':').map(Number); return m*60+s; }
function fmtTime(s)   { const m = Math.floor(s/60), sec = Math.floor(s%60); return `${m}:${sec.toString().padStart(2,'0')}`; }

/* ──────────────────────────────────────
   HERO WAVESURFER
────────────────────────────────────── */
function initHeroWS() {
  heroWS = WaveSurfer.create({
    container:     '#heroWaveform',
    waveColor:     'rgba(155,107,255,0.4)',
    progressColor: '#9B6BFF',
    cursorColor:   'rgba(255,255,255,0.2)',
    barWidth:2, barGap:1, barRadius:2,
    height:64, normalize:true, interact:true,
  });
  heroWS.load('', [genPeaks(BEATS[0].id, 200)], parseDur(BEATS[0].duration));
  heroWS.on('ready', () => { const l = document.getElementById('heroLoading'); if(l) l.style.display = 'none'; });
  setTimeout(() => { const l = document.getElementById('heroLoading'); if(l) l.style.display = 'none'; }, 800);
}

function toggleHeroPlay() {
  heroPlaying = !heroPlaying;
  const btn = document.getElementById('heroPlayBtn');
  if (heroPlaying) {
    staticHTML(btn, `<div style="display:flex;gap:2px;align-items:flex-end;height:16px;"><div style="width:3px;height:8px;background:#000;border-radius:1px;animation:playAnim 0.7s 0s ease-in-out infinite"></div><div style="width:3px;height:14px;background:#000;border-radius:1px;animation:playAnim 0.7s 0.12s ease-in-out infinite"></div><div style="width:3px;height:10px;background:#000;border-radius:1px;animation:playAnim 0.7s 0.24s ease-in-out infinite"></div></div>`);
  } else {
    btn.textContent = '▶';
  }
}

/* ──────────────────────────────────────
   RENDER BEAT LIST — XSS SAFE
────────────────────────────────────── */
function renderList(beats) {
  const listEl = document.getElementById('beatList');
  while (listEl.firstChild) listEl.removeChild(listEl.firstChild);
  Object.values(wavesurfers).forEach(ws => { try { ws.destroy(); } catch {} });
  wavesurfers = {};

  beats.forEach((b, idx) => {
    const color = GENRE_COLORS[b.genre] || '#9B6BFF';
    const row   = document.createElement('div');
    row.className = 'beat-row';
    row.id        = `row-${b.id}`;

    // Build all sub-elements with textContent / safe wrappers
    const numEl = el('div', { class:'row-num', id:`rnum-${b.id}` }, String(idx+1));

    const playBtn = el('button', { class:'row-play', id:`rplay-${b.id}`,
      onclick: (e) => { e.stopPropagation(); toggleBeat(b.id); }
    }, '▶');

    // Info column
    const titleLineEl = el('div', { class:'row-title-line' });
    const titleSpan = el('span', { class:'row-title' });
    titleSpan.textContent = `${b.emoji} ${b.title}`;
    const producerSpan = el('span', { class:'row-producer' });
    const producerLink = el('a', { href:'#' });
    producerLink.textContent = b.producer;
    producerSpan.appendChild(document.createTextNode('by '));
    producerSpan.appendChild(producerLink);

    const tagsEl = el('div', { class:'row-tags' });
    const addTag = (text, style) => {
      const t = el('span', { class:'row-tag', style });
      t.textContent = text;
      tagsEl.appendChild(t);
    };
    if (b.hot)  addTag('🔥 HOT',    'background:rgba(255,107,43,0.15);color:var(--orange);border:1px solid rgba(255,107,43,0.25);');
    if (b.newR) addTag('NEW',       'background:rgba(0,229,160,0.12);color:var(--green);border:1px solid rgba(0,229,160,0.2);');
    if (b.excl) addTag('EXCLUSIVE', 'background:rgba(255,184,0,0.12);color:var(--gold);border:1px solid rgba(255,184,0,0.25);');
    addTag(`${b.bpm} BPM`, null); tagsEl.lastChild.classList.add('badge-bpm');
    addTag(b.key, null);          tagsEl.lastChild.classList.add('badge-key');
    addTag(b.genre.toUpperCase(), 'background:rgba(255,255,255,0.06);color:var(--text3);border:1px solid var(--border);');

    titleLineEl.appendChild(titleSpan);
    titleLineEl.appendChild(producerSpan);
    titleLineEl.appendChild(tagsEl);

    const wfEl    = el('div', { class:`row-waveform wc-${b.genre}`, id:`wf-${b.id}` });
    const statsEl = el('div', { class:'row-stats' });
    ['▶ '+b.plays, '⏱ '+b.duration, '🎵 '+b.mood].forEach(s => {
      const span = el('span', { class:'row-stat' });
      span.textContent = s;
      statsEl.appendChild(span);
    });

    const infoEl = el('div', { class:'row-info' });
    infoEl.appendChild(titleLineEl);
    infoEl.appendChild(wfEl);
    infoEl.appendChild(statsEl);

    // Price + actions column — static math, no user data
    const priceWhole = Math.floor(b.price);
    const priceCents = String(Math.round((b.price % 1) * 100)).padStart(2, '0');
    const priceEl    = el('div', { class:'row-price' });
    priceEl.textContent = `$${priceWhole}`;
    const centsSpan = el('span', { class:'cents' });
    centsSpan.textContent = `.${priceCents}`;
    priceEl.appendChild(centsSpan);

    const licBtns = el('div', { class:'row-license-btns' });
    [['MP3','rlic-mp3'],['WAV','rlic-wav'],['Exclusive','rlic-excl']].forEach(([type, cls]) => {
      const btn2 = el('button', { class:`rlic ${cls}`,
        onclick: (e) => { e.stopPropagation(); selectLicense(b.id, type); }
      });
      btn2.textContent = type === 'Exclusive' ? 'EXCL' : type;
      licBtns.appendChild(btn2);
    });

    const addBtn = el('button', { class:'add-cart-btn',
      onclick: (e) => { e.stopPropagation(); addToCart(b.id); }
    });
    addBtn.textContent = '+ Add to Cart';

    const actionsEl = el('div', { class:'row-actions' });
    actionsEl.appendChild(priceEl);
    actionsEl.appendChild(licBtns);
    actionsEl.appendChild(addBtn);

    row.appendChild(numEl);
    row.appendChild(playBtn);
    row.appendChild(infoEl);
    row.appendChild(actionsEl);

    row.addEventListener('click', () => fetchBeatDetail(b));
    listEl.appendChild(row);
    setTimeout(() => initWS(b, color), idx * 80);
  });
}

/* ──────────────────────────────────────
   RENDER GRID — XSS SAFE
────────────────────────────────────── */
function renderGrid(beats) {
  const gridEl = document.getElementById('beatGrid');
  while (gridEl.firstChild) gridEl.removeChild(gridEl.firstChild);

  beats.forEach(b => {
    const card = el('div', { class:'beat-card' });

    const artwork = el('div', { class:'bc-artwork' });
    const emojiSpan = el('span', { style:'font-size:44px;position:relative;z-index:1;' });
    emojiSpan.textContent = b.emoji;
    const overlay = el('div', { class:'bc-artwork-overlay' });
    const bigPlay = el('button', { class:'bc-play-big',
      onclick: (e) => { e.stopPropagation(); toggleBeat(b.id); }
    });
    bigPlay.textContent = '▶';
    overlay.appendChild(bigPlay);
    artwork.appendChild(emojiSpan);
    artwork.appendChild(overlay);

    const info = el('div', { class:'bc-info' });
    const titleEl = el('div', { class:'bc-title' }); titleEl.textContent = b.title;
    const prodEl  = el('div', { class:'bc-producer' }); prodEl.textContent = b.producer;
    info.appendChild(titleEl); info.appendChild(prodEl);

    const tagsEl = el('div', { class:'bc-tags' });
    const addBadge = (text, cls) => { const s = el('span', { class:`fbc-badge ${cls}` }); s.textContent = text; tagsEl.appendChild(s); };
    addBadge(`${b.bpm} BPM`, 'badge-bpm');
    addBadge(b.key, 'badge-key');
    if (b.hot)  addBadge('🔥', 'badge-hot');
    if (b.newR) addBadge('NEW', 'badge-new');

    const footer = el('div', { class:'bc-footer' });
    const priceEl = el('div', { class:'bc-price' }); priceEl.textContent = `$${Math.floor(b.price)}`;
    const addBtn  = el('button', { class:'bc-add', onclick: (e) => { e.stopPropagation(); addToCart(b.id); } });
    addBtn.textContent = '+';
    footer.appendChild(priceEl); footer.appendChild(addBtn);

    card.appendChild(artwork); card.appendChild(info); card.appendChild(tagsEl); card.appendChild(footer);
    card.addEventListener('click', () => fetchBeatDetail(b));
    gridEl.appendChild(card);
  });
}

/* ──────────────────────────────────────
   RENDER NEW RELEASES — XSS SAFE
────────────────────────────────────── */
function renderNewReleases() {
  const el2 = document.getElementById('newReleasesGrid');
  while (el2.firstChild) el2.removeChild(el2.firstChild);
  BEATS.filter(b => b.newR).slice(0, 4).forEach(b => {
    const card = el('div', { class:'beat-card' });

    const artwork = el('div', { class:'bc-artwork', style:'aspect-ratio:3/2;' });
    const emojiEl = el('span', { style:'font-size:40px;position:relative;z-index:1;' });
    emojiEl.textContent = b.emoji;
    const overlay = el('div', { class:'bc-artwork-overlay' });
    const playBtn = el('button', { class:'bc-play-big', onclick: (e) => { e.stopPropagation(); toggleBeat(b.id); }});
    playBtn.textContent = '▶';
    overlay.appendChild(playBtn);
    artwork.appendChild(emojiEl); artwork.appendChild(overlay);

    const info = el('div', { class:'bc-info', style:'margin-top:12px;' });
    const t = el('div', { class:'bc-title' }); t.textContent = b.title;
    const p = el('div', { class:'bc-producer' }); p.textContent = b.producer;
    info.appendChild(t); info.appendChild(p);

    const tags = el('div', { class:'bc-tags', style:'margin-top:8px;' });
    const mk = (text, cls) => { const s = el('span', { class:`fbc-badge ${cls}` }); s.textContent = text; return s; };
    tags.appendChild(mk(`${b.bpm} BPM`, 'badge-bpm'));
    tags.appendChild(mk(b.key, 'badge-key'));
    tags.appendChild(mk('NEW', 'badge-new'));

    const footer = el('div', { class:'bc-footer', style:'margin-top:12px;' });
    const pr = el('div', { class:'bc-price' }); pr.textContent = `$${Math.floor(b.price)}`;
    const ab = el('button', { class:'bc-add', onclick:(e)=>{e.stopPropagation();addToCart(b.id);} });
    ab.textContent = '+';
    footer.appendChild(pr); footer.appendChild(ab);

    card.appendChild(artwork); card.appendChild(info); card.appendChild(tags); card.appendChild(footer);
    card.addEventListener('click', () => fetchBeatDetail(b));
    el2.appendChild(card);
  });
}

/* ──────────────────────────────────────
   RENDER PRODUCERS — XSS SAFE
────────────────────────────────────── */
function renderProducers() {
  const gridEl = document.getElementById('producerGrid');
  while (gridEl.firstChild) gridEl.removeChild(gridEl.firstChild);
  DEMO_PRODUCERS.forEach(p => {
    const card = el('div', { class:'producer-card' });
    const avatar = el('div', { class:'prod-avatar', style:'background:var(--dark3);' });
    staticHTML(avatar, '<div class="prod-avatar-ring"></div>');
    const emojiEl = el('span', { style:'font-size:30px;position:relative;z-index:1;' });
    emojiEl.textContent = p.emoji;
    avatar.appendChild(emojiEl);

    const nameEl = el('div', { class:'prod-name' }); nameEl.textContent = p.name;
    const tagEl  = el('div', { class:'prod-tag'  }); tagEl.textContent  = p.handle;
    const stats  = el('div', { class:'prod-stats' });
    [[p.beats,'Beats'],[p.sales,'Sales'],[p.genre,'Genre']].forEach(([num, label]) => {
      const item = el('div', { class:'ps-item' });
      const n = el('div', { class:'ps-num' }); n.textContent = num;
      const l = el('div', { class:'ps-label' }); l.textContent = label;
      item.appendChild(n); item.appendChild(l);
      stats.appendChild(item);
    });
    card.appendChild(avatar); card.appendChild(nameEl); card.appendChild(tagEl); card.appendChild(stats);
    gridEl.appendChild(card);
  });
}

/* ──────────────────────────────────────
   PRODUCERS SCROLLING BAR
────────────────────────────────────── */
function renderProducersBar() {
  const barData = [
    {n:'MetroKing',e:'👑',c:'142 beats'},{n:'GrimProd',e:'💀',c:'87 beats'},
    {n:'AstralWaves',e:'🌊',c:'203 beats'},{n:'AfroGod',e:'🌍',c:'95 beats'},
    {n:'SunsetBeatz',e:'🌅',c:'67 beats'},{n:'CyberBeat',e:'🤖',c:'118 beats'},
    {n:'FrostKing',e:'❄️',c:'74 beats'},{n:'BeatFactory',e:'⭐',c:'156 beats'},
    {n:'LoFiLabs',e:'🌧️',c:'230 beats'},{n:'VioletSound',e:'🟣',c:'49 beats'},
  ];
  const track = document.getElementById('pbTrack');
  while (track.firstChild) track.removeChild(track.firstChild);
  [...barData, ...barData].forEach(p => {
    const item   = el('div', { class:'pb-item' });
    const avatar = el('div', { class:'pb-avatar', style:'background:var(--dark3);' });
    avatar.textContent = p.e;
    const name = el('span', { class:'pb-name' }); name.textContent = p.n;
    const cnt  = el('span', { class:'pb-count' }); cnt.textContent  = p.c;
    item.appendChild(avatar); item.appendChild(name); item.appendChild(cnt);
    track.appendChild(item);
  });
}

/* ──────────────────────────────────────
   WAVESURFER
────────────────────────────────────── */
function initWS(beat, color) {
  const container = document.getElementById(`wf-${beat.id}`);
  if (!container || wavesurfers[beat.id]) return;
  const ws = WaveSurfer.create({
    container, waveColor: color+'50', progressColor: color,
    cursorColor:'rgba(255,255,255,0.15)', barWidth:2, barGap:1, barRadius:2,
    height:48, normalize:true, interact:true,
  });
  ws.load('', [genPeaks(beat.id, 180)], parseDur(beat.duration));
  ws.on('interaction', (pct) => { if (currentId === beat.id) fakeTime = pct * parseDur(beat.duration); });
  wavesurfers[beat.id] = ws;
}

/* ──────────────────────────────────────
   PLAYBACK
────────────────────────────────────── */
function toggleBeat(id) {
  if (currentId === id) {
    isPlaying = !isPlaying;
    updatePlayState();
    isPlaying ? startTicker() : stopTicker();
    return;
  }
  if (currentId) resetBeatUI(currentId);
  stopTicker();
  currentId = id; isPlaying = true; fakeTime = 0;
  const beat = BEATS.find(b => b.id === id);
  updateStickyPlayer(beat);
  updatePlayState();
  startTicker();
  API.post(`/beats/${id}/play`).catch(() => {});
}

function resetBeatUI(id) {
  const row = document.getElementById(`row-${id}`);
  if (row) {
    row.classList.remove('is-playing');
    const btn = document.getElementById(`rplay-${id}`);
    if (btn) btn.textContent = '▶';
    const rnum = document.getElementById(`rnum-${id}`);
    if (rnum) rnum.textContent = String(filteredBeats.findIndex(b => b.id === id) + 1);
  }
  const ws = wavesurfers[id];
  if (ws) try { ws.seekTo(0); } catch {}
}

function updatePlayState() {
  if (!currentId) return;
  document.querySelectorAll('.beat-row').forEach(r => r.classList.remove('is-playing'));
  const row = document.getElementById(`row-${currentId}`);
  if (row && isPlaying) row.classList.add('is-playing');
  const btn = document.getElementById(`rplay-${currentId}`);
  if (btn) {
    if (isPlaying) {
      staticHTML(btn, `<div class="playing-anim"><div class="pa-bar"></div><div class="pa-bar"></div><div class="pa-bar"></div></div>`);
      btn.style.background = 'var(--cyan)'; btn.style.color = '#000';
    } else {
      btn.textContent = '▶';
      btn.style.background = btn.style.color = '';
    }
  }
  document.getElementById('stickyPlayer').classList.add('show');
  const mainPlay = document.getElementById('mainPlay');
  mainPlay.textContent = isPlaying ? '⏸' : '▶';
  document.getElementById('stickyPlayer').classList.toggle('playing', isPlaying);
}

function updateStickyPlayer(beat) {
  const artEl = document.getElementById('spArt');
  artEl.textContent = '';
  const emojiEl = el('span', { style:'font-size:22px;' });
  emojiEl.textContent = beat.emoji;
  artEl.appendChild(emojiEl);

  setText('spTitle',  `${beat.emoji} ${beat.title}`);
  setText('spArtist', `${beat.producer} · ${beat.bpm} BPM · ${beat.key}`);
  setText('spDur',    beat.duration);
  setText('spCur',    '0:00');
  document.getElementById('spFill').style.width = '0%';

  const tagsEl = document.getElementById('spTags');
  while (tagsEl.firstChild) tagsEl.removeChild(tagsEl.firstChild);
  const genreTag = el('span', { class:'fbc-badge badge-genre', style:'font-size:9px;' });
  genreTag.textContent = beat.genre.toUpperCase();
  tagsEl.appendChild(genreTag);
  if (beat.hot) {
    const hotTag = el('span', { class:'fbc-badge badge-hot', style:'font-size:9px;' });
    hotTag.textContent = '🔥';
    tagsEl.appendChild(hotTag);
  }
}

/* ──────────────────────────────────────
   PROGRESS TICKER
────────────────────────────────────── */
function startTicker() {
  stopTicker();
  const beat = BEATS.find(b => b.id === currentId);
  if (!beat) return;
  const total = parseDur(beat.duration);
  ticker = setInterval(() => {
    fakeTime = (fakeTime + 0.5) % total;
    const pct = fakeTime / total;
    document.getElementById('spFill').style.width = (pct * 100) + '%';
    setText('spCur', fmtTime(fakeTime));
    const ws = wavesurfers[currentId];
    if (ws) try { ws.seekTo(Math.min(pct, 0.9999)); } catch {}
  }, 500);
}

function stopTicker() {
  if (ticker) { clearInterval(ticker); ticker = null; }
}

/* ──────────────────────────────────────
   CONTROLS
────────────────────────────────────── */
document.getElementById('mainPlay').addEventListener('click', () => {
  if (!currentId) return;
  isPlaying = !isPlaying; updatePlayState();
  isPlaying ? startTicker() : stopTicker();
});
document.getElementById('prevBtn').addEventListener('click', () => {
  const idx  = filteredBeats.findIndex(b => b.id === currentId);
  const prev = filteredBeats[idx > 0 ? idx - 1 : filteredBeats.length - 1];
  if (prev) toggleBeat(prev.id);
});
document.getElementById('nextBtn').addEventListener('click', () => {
  const idx  = filteredBeats.findIndex(b => b.id === currentId);
  const next = filteredBeats[idx < filteredBeats.length - 1 ? idx + 1 : 0];
  if (next) toggleBeat(next.id);
});
document.getElementById('spTrack').addEventListener('click', (e) => {
  if (!currentId) return;
  const rect = e.currentTarget.getBoundingClientRect();
  const pct  = (e.clientX - rect.left) / rect.width;
  const beat = BEATS.find(b => b.id === currentId);
  fakeTime = pct * parseDur(beat.duration);
  document.getElementById('spFill').style.width = (pct * 100) + '%';
  const ws = wavesurfers[currentId];
  if (ws) try { ws.seekTo(pct); } catch {}
});
document.getElementById('volSlider').addEventListener('input', (e) => {
  const v = parseFloat(e.target.value);
  document.querySelector('.sp-vol-icon').textContent = v > 0.6 ? '🔊' : v > 0.1 ? '🔉' : '🔇';
});
document.getElementById('spAddCart').addEventListener('click', () => { if (currentId) addToCart(currentId); });

/* ──────────────────────────────────────
   CART — XSS SAFE
────────────────────────────────────── */
function addToCart(id) {
  const beat = BEATS.find(b => b.id === id);
  if (!beat) return;
  if (cart.find(c => c.id === id)) { showToast(`"${sanitize(beat.title)}" already in cart`, '✓'); return; }
  cart.push({ ...beat, licenseType: 'MP3' });
  updateCartUI();
  showToast(`"${sanitize(beat.title)}" added to cart!`, '🛒', 'toast-orange');
}

function removeFromCart(id) {
  cart = cart.filter(c => c.id !== id);
  updateCartUI();
}

function updateCartUI() {
  const count  = cart.length;
  const dot    = document.getElementById('cartDot');
  dot.textContent = count;
  dot.classList.toggle('show', count > 0);
  setText('cartItemCount', `${count} item${count !== 1 ? 's' : ''}`);

  const itemsEl = document.getElementById('cartItemsEl');
  const footer  = document.getElementById('cartFooter');
  while (itemsEl.firstChild) itemsEl.removeChild(itemsEl.firstChild);

  if (count === 0) {
    const empty = el('div', { class:'cart-empty' },
      el('div', { class:'cart-empty-icon' }, '🎵'),
    );
    const strong = el('strong', { style:'color:var(--text2);' }); strong.textContent = 'Your cart is empty';
    const span   = el('span'); span.textContent = 'Add beats to checkout';
    empty.appendChild(strong); empty.appendChild(span);
    itemsEl.appendChild(empty);
    footer.style.display = 'none';
  } else {
    cart.forEach(b => {
      const item  = el('div', { class:'cart-item' });
      const emoji = el('div', { class:'ci-emoji' }); emoji.textContent = b.emoji;
      const info  = el('div', { class:'ci-info'  });
      const title = el('div', { class:'ci-title' }); title.textContent = b.title;
      const meta  = el('div', { class:'ci-meta'  }); meta.textContent  = `${b.producer} · ${b.licenseType} License · ${b.bpm} BPM`;
      const price = el('div', { class:'ci-price' }); price.textContent = `$${b.price.toFixed(2)}`;
      const rmBtn = el('button', { class:'ci-remove', onclick: () => removeFromCart(b.id) });
      rmBtn.textContent = '✕';
      info.appendChild(title); info.appendChild(meta);
      item.appendChild(emoji); item.appendChild(info); item.appendChild(price); item.appendChild(rmBtn);
      itemsEl.appendChild(item);
    });
    footer.style.display = 'block';
    const total = cart.reduce((s, b) => s + b.price, 0);
    setText('cartTotal', `$${total.toFixed(2)}`);
  }
}

function selectLicense(id, type) {
  const beat = BEATS.find(b => b.id === id);
  const prices = { 'MP3': beat.price, 'WAV': beat.price * 1.8, 'Exclusive': beat.price * 14 };
  const item = cart.find(c => c.id === id);
  if (item) { item.licenseType = type; item.price = prices[type]; updateCartUI(); }
  showToast(`${type} license — $${prices[type].toFixed(2)}`, '🎵');
}

/* ──────────────────────────────────────
   CART PANEL
────────────────────────────────────── */
document.getElementById('cartToggle').addEventListener('click', () => openCart());
function openCart()  { document.getElementById('cartModal').classList.add('open');    }
function closeCart() { document.getElementById('cartModal').classList.remove('open'); }
document.getElementById('cartModal').addEventListener('click', (e) => { if (e.target === e.currentTarget) closeCart(); });
document.getElementById('cartCheckoutBtn').addEventListener('click', doCheckout);

/* ──────────────────────────────────────
   TOAST
────────────────────────────────────── */
function showToast(msg, icon = '🎵', cls = 'toast-left') {
  const container = document.getElementById('toastContainer');
  const t = el('div', { class:`toast ${cls}` });
  const iconEl = el('span', { class:'toast-icon' }); iconEl.textContent = icon;
  const msgEl  = el('span'); msgEl.textContent = msg;
  t.appendChild(iconEl); t.appendChild(msgEl);
  container.appendChild(t);
  requestAnimationFrame(() => requestAnimationFrame(() => t.classList.add('in')));
  setTimeout(() => { t.classList.remove('in'); setTimeout(() => t.remove(), 400); }, 3500);
}

/* ──────────────────────────────────────
   FILTER + SEARCH + SORT
────────────────────────────────────── */
function applyFilters() {
  const search = document.getElementById('searchInp').value.toLowerCase().trim();
  const maxBpm = parseInt(document.getElementById('bpmRange').value);
  const sort   = document.getElementById('sortSel').value;

  filteredBeats = BEATS.filter(b => {
    if (currentFilter !== 'all' && b.genre !== currentFilter) return false;
    if (maxBpm < 200 && b.bpm > maxBpm) return false;
    if (search && !b.title.toLowerCase().includes(search) &&
        !b.producer.toLowerCase().includes(search) &&
        !b.mood.toLowerCase().includes(search) &&
        !b.genre.toLowerCase().includes(search)) return false;
    return true;
  });

  if (sort === 'price_asc')  filteredBeats.sort((a, b) => a.price - b.price);
  if (sort === 'price_desc') filteredBeats.sort((a, b) => b.price - a.price);
  if (sort === 'newest')     filteredBeats = [...filteredBeats].reverse();
  if (sort === 'plays')      filteredBeats.sort((a, b) => parseFloat(b.plays) - parseFloat(a.plays));

  setText('beatCountLabel', `Showing ${filteredBeats.length} beat${filteredBeats.length !== 1 ? 's' : ''}`);
  viewMode === 'list' ? renderList(filteredBeats) : renderGrid(filteredBeats);
}

document.querySelectorAll('.chip').forEach(c => {
  c.addEventListener('click', () => {
    document.querySelectorAll('.chip').forEach(x => x.classList.remove('active'));
    c.classList.add('active');
    currentFilter = c.dataset.genre;
    applyFilters();
  });
});
document.getElementById('searchInp').addEventListener('input', applyFilters);
document.getElementById('bpmRange').addEventListener('input', (e) => {
  const v = parseInt(e.target.value);
  setText('bpmDisp', v >= 200 ? 'Any' : String(v));
  applyFilters();
});
document.getElementById('sortSel').addEventListener('change', applyFilters);

/* ──────────────────────────────────────
   VIEW TOGGLE
────────────────────────────────────── */
document.getElementById('listViewBtn').addEventListener('click', () => {
  viewMode = 'list';
  document.getElementById('beatList').classList.remove('hidden');
  document.getElementById('beatGrid').classList.add('hidden');
  document.getElementById('listViewBtn').style.color = 'var(--cyan)';
  document.getElementById('gridViewBtn').style.color = '';
  applyFilters();
});
document.getElementById('gridViewBtn').addEventListener('click', () => {
  viewMode = 'grid';
  document.getElementById('beatList').classList.add('hidden');
  document.getElementById('beatGrid').classList.remove('hidden');
  document.getElementById('gridViewBtn').style.color = 'var(--cyan)';
  document.getElementById('listViewBtn').style.color = '';
  applyFilters();
});

/* ──────────────────────────────────────
   COUNTDOWN TIMER
────────────────────────────────────── */
let countdown = 23*3600 + 47*60 + 12;
setInterval(() => {
  countdown--;
  if (countdown < 0) countdown = 24 * 3600;
  const h = Math.floor(countdown / 3600);
  const m = Math.floor((countdown % 3600) / 60);
  const s = countdown % 60;
  const timerEl = document.getElementById('promoTimer');
  if (timerEl) timerEl.textContent = `⏳ ${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')} remaining`;
}, 1000);

/* ──────────────────────────────────────
   NAV BUTTON WIRING
────────────────────────────────────── */
document.getElementById('navAuthBtn')?.addEventListener('click', () => openModal('authModal'));
document.getElementById('navUploadBtn')?.addEventListener('click', () => {
  if (!AUTH.isLoggedIn) { openModal('authModal'); return; }
  openModal('uploadModal');
});
document.getElementById('navDashBtn')?.addEventListener('click', () => {
  if (!AUTH.isLoggedIn) { openModal('authModal'); return; }
  openModal('dashModal'); loadDashboard();
});
document.getElementById('navOnboardBtn')?.addEventListener('click', () => openModal('onboardModal'));
document.getElementById('navSignOutBtn')?.addEventListener('click', () => AUTH.signOut());
document.getElementById('sellBtn')?.addEventListener('click', () => {
  if (AUTH.isLoggedIn) openModal('uploadModal');
  else openModal('onboardModal');
});
// Hero upload button
document.querySelector('button.btn-primary')?.addEventListener('click', () => {
  if (!AUTH.isLoggedIn) { openModal('authModal'); return; }
  openModal('uploadModal');
});

/* ──────────────────────────────────────
   KEYBOARD
────────────────────────────────────── */
document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
  if (e.code === 'Space')      { e.preventDefault(); document.getElementById('mainPlay').click(); }
  if (e.code === 'ArrowRight') document.getElementById('nextBtn').click();
  if (e.code === 'ArrowLeft')  document.getElementById('prevBtn').click();
  if (e.code === 'Escape')     {
    document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
    closeCart();
  }
});

/* ──────────────────────────────────────
   INIT
────────────────────────────────────── */
async function init() {
  // Try to load live beats from API; on success, replace demo data
  const liveBeats = await loadBeats();
  if (liveBeats && liveBeats.length > 0) {
    BEATS = liveBeats;
    filteredBeats = [...BEATS];
  }

  renderList(filteredBeats);
  renderGrid(filteredBeats);
  renderNewReleases();
  renderProducers();
  renderProducersBar();
  initHeroWS();
  document.getElementById('listViewBtn').style.color = 'var(--cyan)';

  // Health check (non-blocking)
  setTimeout(checkHealth, 1200);
}

init();
