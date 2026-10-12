/**
 * Snake MITM — Client-side JavaScript
 * Real-time packet visualization, credential display, stats
 */

/* ── MITM State ─────────────────────────────────────────────── */
const mitm = {
  active:        false,
  session_id:    null,
  packets:       [],          // all captured packets (rolling)
  creds:         [],
  stats:         {},
  hosts:         [],          // discovered hosts
  selectedIPs:   new Set(),
  streamCount:   0,
  MAX_STREAM:    2000,
  statsInterval: null,
  filterType:    '',
};

/* ── SocketIO MITM events ────────────────────────────────────── */
// These are wired from snake.js socket — we augment here
document.addEventListener('DOMContentLoaded', () => {
  _initMITMFromSocket();
  _loadMITMStatus();
});

function _initMITMFromSocket() {
  // Wait for socket to be ready (snake.js defines `socket`)
  const poll = setInterval(() => {
    if (typeof socket !== 'undefined') {
      clearInterval(poll);
      _bindMITMEvents();
    }
  }, 200);
}

function _bindMITMEvents() {
  socket.on('mitm_packet', (pkt) => {
    mitm.packets.push(pkt);
    if (mitm.packets.length > mitm.MAX_STREAM) {
      mitm.packets = mitm.packets.slice(-mitm.MAX_STREAM);
    }
    appendPacketRow(pkt);
    mitm.streamCount++;
    setText('stream-count', `${mitm.streamCount} packets`);
  });

  socket.on('mitm_cred', (pkt) => {
    mitm.creds.push(pkt);
    renderCredCard(pkt);
    updateCredCount();
    toast(`Sensitive HTTP data detected for ${pkt.host || 'a selected target'}`, 'warn', 8000);
    // Flash the MITM nav badge
    const badge = document.getElementById('nav-badge-mitm');
    if (badge) {
      badge.textContent = mitm.creds.length;
      badge.style.background = 'rgba(255,193,7,0.3)';
      badge.style.color       = '#ffc107';
    }
  });

  socket.on('mitm_hosts', (data) => {
    mitm.hosts = data.hosts || [];
    renderTargetList(mitm.hosts);
    toast(`🔍 Found ${mitm.hosts.length} hosts`, 'info');
  });

  socket.on('mitm_log', (entry) => {
    // Also forward to main console
    appendLog(entry);
  });
}

/* ── Init: load status & auto-fill ─────────────────────────── */
async function _loadMITMStatus() {
  const resp = await api('/api/mitm/status');
  if (!resp) return;

  // Auto-fill interface and gateway
  if (resp.iface)   document.getElementById('mitm-iface').value   = resp.iface;
  if (resp.gateway) document.getElementById('mitm-gateway').value = resp.gateway;
  const warn = document.getElementById('mitm-ready-warn');
  if (warn) {
    const notes = [...(resp.readiness?.notes || [])];
    if (resp.readiness?.monitor_warning) {
      notes.unshift(`${resp.iface || 'This interface'} is monitor — Snake restores managed for MITM`);
    }
    warn.style.display = notes.length ? 'block' : 'none';
    warn.textContent = notes.join(' ');
  }

  // Restore active sessions
  const sessions = Object.values(resp.sessions || {});
  if (sessions.length > 0) {
    const s = sessions[0];
    mitm.active     = s.running;
    mitm.session_id = s.session_id;
    _setMITMActive(s.running, s.session_id);
    mitm.packets = s.packets || [];
    _rebuildStream();
  }

  // Start stats polling if active
  if (mitm.active) _startStatsPoll();
}

/* ── Discover Hosts ─────────────────────────────────────────── */
async function discoverHosts() {
  const iface   = document.getElementById('mitm-iface').value.trim();
  const gateway = document.getElementById('mitm-gateway').value.trim();

  toast('🔍 Discovering hosts...', 'info');

  const resp = await api('/api/mitm/discover', 'POST', { iface, gateway });
  if (resp?.ok) {
    toast('Discovery started — results appear below', 'info');
  } else {
    toast(resp?.error || 'Discovery failed', 'error');
  }
}

/* ── Render Target List ─────────────────────────────────────── */
function renderTargetList(hosts) {
  const list = document.getElementById('target-list');
  if (!list) return;

  if (!hosts.length) {
    list.innerHTML = '<div class="empty-state" style="padding:20px">No hosts found</div>';
    return;
  }

  list.innerHTML = hosts.map(h => `
    <div class="target-item" id="target-${h.ip.replace(/\./g, '_')}">
      <input type="checkbox" class="target-checkbox" data-ip="${h.ip}"
             onchange="setTarget('${h.ip}', this.checked, this.closest('.target-item'))"
             ${mitm.selectedIPs.has(h.ip) ? 'checked' : ''}/>
      <span class="target-ip">${h.ip}</span>
      <span class="target-mac">${h.mac || '??:??:??:??:??:??'}</span>
    </div>
  `).join('');
}

function setTarget(ip, selected, el) {
  const cb = el?.querySelector?.('input[type=checkbox]');
  if (selected) {
    mitm.selectedIPs.add(ip);
    el?.classList?.add('selected');
    if (cb) cb.checked = true;
  } else {
    mitm.selectedIPs.delete(ip);
    el?.classList?.remove('selected');
    if (cb) cb.checked = false;
  }
}

function selectAllTargets() {
  mitm.hosts.forEach(h => {
    mitm.selectedIPs.add(h.ip);
    const el = document.getElementById(`target-${h.ip.replace(/\./g, '_')}`);
    el?.classList?.add('selected');
    const cb = el?.querySelector?.('input[type=checkbox]');
    if (cb) cb.checked = true;
  });
}

function clearTargets() {
  mitm.selectedIPs.clear();
  document.querySelectorAll('.target-item').forEach(el => {
    el.classList.remove('selected');
    const cb = el.querySelector('input[type=checkbox]');
    if (cb) cb.checked = false;
  });
}

/* ── Start MITM ─────────────────────────────────────────────── */
async function startMITM() {
  const iface      = document.getElementById('mitm-iface').value.trim();
  const gateway    = document.getElementById('mitm-gateway').value.trim();
  const dns_spoof  = document.getElementById('mitm-dns-spoof').checked;
  const sslstrip   = document.getElementById('mitm-sslstrip').checked;
  const use_bc     = document.getElementById('mitm-use-bc').checked;
  const mitm_profile = document.getElementById('mitm-profile')?.value || 'harvest';
  const targets    = [...mitm.selectedIPs];

  if (!iface)   return toast('Enter interface name', 'warn');
  if (!gateway) return toast('Enter gateway IP', 'warn');
  if (!targets.length) return toast('Select at least one discovered target', 'warn');
  if (!confirm(`Confirm authorization to inspect traffic for ${targets.length} selected target(s).`)) return;

  toast('🎯 Launching MITM attack...', 'warn');

  const resp = await api('/api/mitm/start', 'POST', {
    iface, gateway, targets, dns_spoof, sslstrip,
    use_bettercap: use_bc, mitm_profile, authorized: true
  });

  if (resp?.ok) {
    mitm.active     = true;
    mitm.session_id = resp.session_id;
    _setMITMActive(true, resp.session_id);
    _startStatsPoll();
    toast(`🎯 MITM active! Session: ${resp.session_id}`, 'warn');
    clearStream();
  } else {
    toast(resp?.error || 'Failed to start MITM', 'error');
  }
}

/* ── Stop MITM ──────────────────────────────────────────────── */
async function stopMITM() {
  const resp = await api('/api/mitm/stop', 'POST', { session_id: mitm.session_id });
  if (!resp?.ok) return;
  mitm.active     = false;
  mitm.session_id = null;
  _setMITMActive(false);
  if (mitm.statsInterval) { clearInterval(mitm.statsInterval); mitm.statsInterval = null; }
  toast('[*] MITM stopped. ARP tables restored.', 'info');
}

function _setMITMActive(active, sid = null) {
  const banner  = document.getElementById('mitm-banner');
  const dot     = document.getElementById('mitm-dot');
  const statusT = document.getElementById('mitm-status-text');
  const sidEl   = document.getElementById('mitm-session-id');
  const stopBtn = document.getElementById('btn-mitm-stop');
  const startBtn= document.getElementById('btn-mitm-start');
  const badge   = document.getElementById('nav-badge-mitm');

  if (active) {
    banner?.classList?.add('active');
    if (dot)     dot.style.cssText = '';
    if (statusT) statusT.textContent = `🎯 MITM ACTIVE — ARP Poison Running`;
    if (sidEl)   sidEl.textContent  = sid ? `SID: ${sid}` : '';
    if (stopBtn) stopBtn.style.display = '';
    if (startBtn) startBtn.disabled = true;
    if (badge)  { badge.textContent = 'ON'; badge.style.background = 'rgba(255,45,85,0.3)'; badge.style.color = '#ff2d55'; }
  } else {
    banner?.classList?.remove('active');
    if (statusT) statusT.textContent = 'MITM Inactive';
    if (sidEl)   sidEl.textContent  = '';
    if (stopBtn) stopBtn.style.display = 'none';
    if (startBtn) startBtn.disabled = false;
    if (badge)  { badge.textContent = 'OFF'; badge.style.background = 'rgba(255,45,85,0.2)'; badge.style.color = '#ff2d55'; }
  }
}

/* ── Stats Polling ──────────────────────────────────────────── */
function _startStatsPoll() {
  if (mitm.statsInterval) clearInterval(mitm.statsInterval);
  mitm.statsInterval = setInterval(_fetchStats, 3000);
  _fetchStats();
}

async function _fetchStats() {
  if (!mitm.active) return;
  const resp = await api('/api/mitm/stats');
  if (!resp?.stats) return;

  const stats = Object.values(resp.stats)[0];
  if (!stats) return;
  mitm.stats = stats;

  // Update stat cards
  setText('ms-packets', fmtNum(stats.packets_total || 0));
  setText('ms-bytes',   fmtBytes(stats.bytes_total || 0));
  setText('ms-http',    fmtNum(stats.http_reqs || 0));
  setText('ms-dns',     fmtNum(stats.dns_queries || 0));
  setText('ms-creds',   fmtNum(stats.creds_found || 0));
  setText('ms-cookies', fmtNum(stats.cookies_found || 0));

  // Protocol bars
  renderProtoBars(stats.protocols || {});

  // Top hosts
  renderTopHosts(stats.top_hosts || {});

  // Timeline sparkline
  renderTimeline(stats.timeline || []);
}

/* ── Packet Stream ──────────────────────────────────────────── */
function appendPacketRow(pkt) {
  const stream = document.getElementById('packet-stream');
  if (!stream) return;

  // Filter check
  const filter = mitm.filterType;
  if (filter && pkt.ptype !== filter) return;

  // Remove empty state placeholder
  const placeholder = stream.querySelector('div[style*="padding:40px"]');
  if (placeholder) placeholder.remove();

  const dangerClass = `d${Math.min(10, Math.floor(pkt.danger || 0))}`;
  const credBadge   = pkt.credential ? '<span class="pkt-cred-badge">CRED</span>' : '';

  const row = document.createElement('div');
  row.className = `packet-row ${dangerClass}`;
  row.dataset.ptype = pkt.ptype;
  row.title = JSON.stringify(pkt.credential || {}, null, 2);
  row.onclick = () => showPacketDetail(pkt);
  row.innerHTML = `
    <span class="pkt-ts">${pkt.ts_fmt || '--:--:--'}</span>
    <span class="pkt-type pkt-type-${pkt.ptype || 'OTHER'}">${pkt.ptype || '?'}</span>
    <span class="pkt-src">${pkt.src_ip || '?'}${pkt.src_port ? ':'+pkt.src_port : ''}</span>
    <span class="pkt-dst">${pkt.dst_ip || '?'}${pkt.dst_port ? ':'+pkt.dst_port : ''}</span>
    <span class="pkt-size">${pkt.size || 0}B</span>
    <span class="pkt-info">${esc(pkt.raw_summary || pkt.host || '...')}${credBadge}</span>
  `;
  stream.appendChild(row);

  // Limit DOM rows
  while (stream.children.length > mitm.MAX_STREAM) {
    stream.removeChild(stream.firstChild);
  }

  // Auto-scroll
  const auto = document.getElementById('stream-autoscroll');
  if (auto?.checked) stream.scrollTop = stream.scrollHeight;
}

function _rebuildStream() {
  clearStream();
  const filter = mitm.filterType;
  const toShow = filter
    ? mitm.packets.filter(p => p.ptype === filter)
    : mitm.packets;
  toShow.slice(-500).forEach(appendPacketRow);
}

function filterPackets() {
  mitm.filterType = document.getElementById('pkt-filter')?.value || '';
  _rebuildStream();
}

function clearStream() {
  const stream = document.getElementById('packet-stream');
  if (stream) stream.innerHTML = '';
  mitm.streamCount = 0;
  setText('stream-count', '0 packets');
}

/* ── Credential Card ─────────────────────────────────────────── */
function renderCredCard(pkt) {
  const list = document.getElementById('cred-list');
  if (!list) return;

  // Remove empty state
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  const cred = pkt.credential || {};
  const card = document.createElement('div');
  card.className = 'cred-card-item';
  card.innerHTML = `
    <div class="cred-host">🌐 ${esc(pkt.host || cred.host || pkt.dst_ip || '?')}</div>
    <div class="cred-fields">
      ${cred.username ? `<div class="cred-field"><span class="cred-label">Username</span><span class="cred-value secret-value">${esc(cred.username)}</span></div>` : ''}
      ${cred.password ? `<div class="cred-field"><span class="cred-label">Password</span><span class="cred-value secret-value">${esc(cred.password)}</span></div>` : ''}
      ${cred.token    ? `<div class="cred-field"><span class="cred-label">Token</span><span class="cred-value secret-value">${esc(cred.token.slice(0,40))}…</span></div>` : ''}
      <div class="cred-field"><span class="cred-label">Time</span><span class="cred-value" style="color:var(--text-muted)">${pkt.ts_fmt || '--:--'}</span></div>
    </div>
    <button class="btn btn-sm btn-ghost reveal-credential">Reveal sensitive values</button>
    ${pkt.url ? `<div style="font-size:0.68rem;color:var(--text-muted);margin-top:6px">URL: ${esc(pkt.url.slice(0, 80))}</div>` : ''}
  `;
  card.querySelector('.reveal-credential')?.addEventListener('click', event => {
    const values = card.querySelectorAll('.secret-value');
    values.forEach(value => value.classList.toggle('revealed'));
    event.currentTarget.textContent = values[0]?.classList.contains('revealed')
      ? 'Hide sensitive values'
      : 'Reveal sensitive values';
  });
  // Insert at top
  list.insertBefore(card, list.firstChild);
}

function updateCredCount() {
  const n = mitm.creds.length;
  setText('cred-count-badge', `${n} found`);
  setText('ms-creds', n);
}

/* ── Protocol Bars ──────────────────────────────────────────── */
function renderProtoBars(protos) {
  const el = document.getElementById('proto-bars');
  if (!el || !Object.keys(protos).length) return;

  const max   = Math.max(...Object.values(protos), 1);
  const order = ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP', 'ARP'];
  const sorted= [...order.filter(p => protos[p]),
                  ...Object.keys(protos).filter(p => !order.includes(p))];

  el.innerHTML = sorted.map(proto => {
    const count = protos[proto] || 0;
    const pct   = Math.round((count / max) * 100);
    return `
      <div class="proto-bar-row">
        <span class="proto-name">${proto}</span>
        <div class="proto-track">
          <div class="proto-fill proto-fill-${proto}" style="width:${pct}%"></div>
        </div>
        <span class="proto-count">${count}</span>
      </div>
    `;
  }).join('');
}

/* ── Top Hosts ──────────────────────────────────────────────── */
function renderTopHosts(hosts) {
  const el = document.getElementById('top-hosts');
  if (!el) return;

  const entries = Object.entries(hosts);
  if (!entries.length) return;

  const max = Math.max(...entries.map(([,c]) => c), 1);

  el.innerHTML = entries.slice(0, 10).map(([host, count]) => {
    const pct = Math.round((count / max) * 100);
    const isSensitive = /facebook|twitter|gmail|paypal|amazon|bank|login|signin|auth|account/i.test(host);
    return `
      <div class="host-row">
        <span class="host-name" style="${isSensitive ? 'color:var(--accent-red)' : ''}"
              title="${esc(host)}">${esc(host)}</span>
        <span class="host-count">${count}</span>
        <div class="host-bar-mini">
          <div class="host-bar-fill" style="width:${pct}%;${isSensitive ? 'background:var(--accent-red)' : ''}"></div>
        </div>
      </div>
    `;
  }).join('');
}

/* ── Timeline Sparkline ─────────────────────────────────────── */
function renderTimeline(timeline) {
  const wrap = document.getElementById('timeline-wrap');
  if (!wrap || !timeline.length) return;

  const max   = Math.max(...timeline.map(t => t.count), 1);
  const last  = timeline.slice(-60); // last 60 seconds

  wrap.innerHTML = last.map((bucket, i) => {
    const h = Math.max(2, Math.round((bucket.count / max) * 56));
    const isLast = i === last.length - 1;
    const color  = bucket.count > (max * 0.7) ? 'var(--accent-red)' : 'rgba(0,255,65,0.3)';
    return `<div class="timeline-bar" style="height:${h}px;background:${isLast ? 'var(--accent-green)' : color}"
              title="${bucket.count} pkts"></div>`;
  }).join('');
}

/* ── Packet Detail Modal ────────────────────────────────────── */
function showPacketDetail(pkt) {
  // Reuse the attack modal for detail
  const modal = document.getElementById('modal-attack');
  if (!modal) return;

  document.getElementById('modal-attack-title').textContent = `📦 Packet: ${pkt.ptype}`;
  document.getElementById('modal-attack-body').innerHTML = `
    <div class="pkt-detail-grid">
      <div class="pkt-detail-field"><span class="pkt-detail-label">Type</span>
        <span class="pkt-detail-val"><span class="pkt-type pkt-type-${pkt.ptype}">${pkt.ptype}</span></span></div>
      <div class="pkt-detail-field"><span class="pkt-detail-label">Time</span>
        <span class="pkt-detail-val">${pkt.ts_fmt || '?'}</span></div>
      <div class="pkt-detail-field"><span class="pkt-detail-label">Source</span>
        <span class="pkt-detail-val">${pkt.src_ip}:${pkt.src_port || 0}</span></div>
      <div class="pkt-detail-field"><span class="pkt-detail-label">Destination</span>
        <span class="pkt-detail-val">${pkt.dst_ip}:${pkt.dst_port || 0}</span></div>
      ${pkt.host ? `<div class="pkt-detail-field pkt-detail-body"><span class="pkt-detail-label">Host</span>
        <span class="pkt-detail-val" style="color:var(--accent-cyan)">${esc(pkt.host)}</span></div>` : ''}
      ${pkt.url  ? `<div class="pkt-detail-field pkt-detail-body"><span class="pkt-detail-label">URL</span>
        <span class="pkt-detail-val">${esc(pkt.url)}</span></div>` : ''}
      ${pkt.method ? `<div class="pkt-detail-field"><span class="pkt-detail-label">Method</span>
        <span class="pkt-detail-val" style="color:var(--accent-yellow)">${pkt.method}</span></div>` : ''}
      <div class="pkt-detail-field"><span class="pkt-detail-label">Size</span>
        <span class="pkt-detail-val">${pkt.size} bytes</span></div>
      ${pkt.credential && Object.keys(pkt.credential).length ? `
        <div class="pkt-detail-field pkt-detail-body">
          <span class="pkt-detail-label" style="color:var(--accent-gold)">⚡ CREDENTIALS</span>
          <div style="background:rgba(255,193,7,0.08);border:1px solid rgba(255,193,7,0.3);border-radius:6px;padding:10px;margin-top:4px;font-family:var(--font-mono)">
            ${Object.entries(pkt.credential).filter(([k]) => k !== 'raw').map(([k,v]) =>
              `<div><span style="color:var(--text-muted)">${k}:</span> <span style="color:var(--accent-gold)">${esc(v)}</span></div>`
            ).join('')}
          </div>
        </div>` : ''}
      ${pkt.body ? `<div class="pkt-detail-field pkt-detail-body"><span class="pkt-detail-label">Body</span>
        <div style="background:#000;padding:8px;border-radius:4px;font-size:0.72rem;font-family:var(--font-mono);max-height:100px;overflow-y:auto;word-break:break-all">${esc(pkt.body)}</div></div>` : ''}
    </div>
  `;

  // Override footer: no attack button
  document.getElementById('modal-attack-btn').style.display = 'none';
  modal.style.display = 'flex';
}

/* ── Formatting helpers ─────────────────────────────────────── */
function fmtBytes(bytes) {
  if (bytes < 1024)        return bytes + 'B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'K';
  return (bytes / (1024 * 1024)).toFixed(1) + 'M';
}

function fmtNum(n) {
  if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
  if (n >= 1000)    return (n/1000).toFixed(1) + 'K';
  return String(n);
}
