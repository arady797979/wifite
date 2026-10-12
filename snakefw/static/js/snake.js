/**
 * Snake Framework — Main Client JavaScript
 * Real-time SocketIO control panel logic
 */

/* ── State ─────────────────────────────────────────────────── */
const state = {
  networks:   [],
  jobs:       {},
  cracked:    [],
  onlineQueue: [],
  stats:      {},
  interface:  '',
  mode:       '',
  appState:   'IDLE',
  connected:  false,
  scanActive: false,
  startTime:  Date.now(),
  modalTarget: null,
  selectedNetwork: null,
};

/* ── Socket ────────────────────────────────────────────────── */
const socket = io({ transports: ['websocket', 'polling'] });

socket.on('connect', () => {
  state.connected = true;
  setConnStatus(true);
  toast('Connected to Snake 🐍', 'success');
  loadCracked();
  loadTools();
  loadWordlists();
  loadOnlineQueue();
});

socket.on('disconnect', () => {
  state.connected = false;
  setConnStatus(false);
  toast('Connection lost. Reconnecting...', 'error');
});

socket.on('init', (data) => {
  applySnapshot(data);
  populateInterfaces(data.interfaces || []);
  if (data.tool_entries) {
    renderTools({ entries: data.tool_entries, tools: data.tools });
  } else {
    loadTools();
  }
});

socket.on('log', (entry) => appendLog(entry));

socket.on('networks_update', (data) => {
  state.networks = data.networks || [];
  if (state.selectedNetwork?.bssid) {
    const fresh = state.networks.find(
      n => n.bssid === state.selectedNetwork.bssid
    );
    state.selectedNetwork = fresh || null;
    if (fresh) applyTargetToAttackForm(fresh);
  }
  renderNetworksTable();
  updateDashboardStats();
});

socket.on('job_update', (job) => {
  if (job && job.id) state.jobs[job.id] = job;
  renderJobsList();
  updateDashboardStats();
});

function hasCrackedPassword(entry) {
  if (!entry || typeof entry !== 'object') return false;
  const fields = ['key', 'psk', 'password', 'passphrase', 'ascii_key', 'pin', 'hex_key'];
  return fields.some(f => String(entry[f] || '').trim());
}

function filterValidCracked(list) {
  return (list || []).filter(hasCrackedPassword);
}

socket.on('cracked', (entry) => {
  if (!hasCrackedPassword(entry)) return;
  state.cracked.push(entry);
  renderCrackedTable();
  updateDashboardStats();
  toast(`🏆 CRACKED: ${entry.essid} → ${entry.key}`, 'success', 8000);
  // Flash cracked tab badge
  shakeElement('#nav-badge-cracked');
});

socket.on('pivot_ready', (data) => {
  toast(`PSK ready for ${data?.essid || 'target'} — Pivot from Cracked if authorized`, 'info', 7000);
});

socket.on('pivot_phase', (data) => {
  if (data?.phase) toast(`Pivot: ${data.phase}`, 'info', 2200);
});

socket.on('pivot_complete', (data) => {
  if (data?.error) toast(`Pivot failed: ${data.error}`, 'error', 6000);
  else toast(`Joined ${data?.essid || 'LAN'} as ${data?.ipv4 || 'ok'}`, 'success', 6000);
  if (data?.launch_strike && !data?.error) switchTab('strike');
});

socket.on('cracked_update', (data) => {
  state.cracked = filterValidCracked(data.cracked);
  renderCrackedTable();
  updateDashboardStats();
});

socket.on('interface_update', (data) => {
  applyInterfaceState(data);
  toast(`Mode: ${(data.mode || '').toUpperCase()} on ${data.interface}`, 'info');
});

socket.on('heartbeat', (data) => {
  state.stats    = data.stats || state.stats;
  state.appState = data.state || state.appState;
  updateSidebarStatus();
});

socket.on('scan_stopped', () => setScanUi(false, 'Scan preset complete'));

socket.on('online_queued', (item) => {
  toast(`☁ ${item?.essid || 'Handshake'} saved for online crack`, 'warn', 7000);
  loadOnlineQueue();
});

socket.on('online_update', () => loadOnlineQueue());

/* ── Snapshot apply ─────────────────────────────────────────── */
function applySnapshot(data) {
  state.networks  = data.networks  || [];
  state.jobs      = data.jobs      || {};
  state.cracked   = filterValidCracked(data.cracked);
  state.stats     = data.stats     || {};
  state.interface = data.interface || data.monitor || '';
  state.appState  = data.state     || 'IDLE';
  state.mode      = data.monitor ? 'monitor' : state.mode;
  state.scanActive = state.appState === 'SCANNING';

  renderNetworksTable();
  renderJobsList();
  renderCrackedTable();
  updateDashboardStats();
  updateSidebarStatus();
  setScanUi(state.scanActive, state.scanActive ? 'Scanning…' : 'Ready to scan');

  // Load recent logs
  (data.logs || []).forEach(l => appendLog(l, false));
}

/* ── Status helpers ─────────────────────────────────────────── */
function setConnStatus(ok) {
  const dot   = document.getElementById('conn-dot');
  const label = document.getElementById('conn-label');
  if (dot)   dot.classList.toggle('connected', ok);
  if (label) label.textContent = ok ? 'Connected' : 'Disconnected';
}

function updateSidebarStatus() {
  setText('iface-label', state.interface || '—');
  setText('mode-label',  state.mode     || '—');
  const sl = document.getElementById('state-label');
  if (sl) {
    sl.textContent = state.appState;
    sl.className   = `mono state-${state.appState}`;
  }
  const info = document.getElementById('iface-info');
  if (info) {
    info.textContent = state.interface
      ? `Interface: ${state.interface}  |  Mode: ${state.mode || 'unknown'}`
      : 'No interface selected.';
  }
}

function applyInterfaceState(data) {
  if (!data) return;
  state.interface = data.interface || state.interface;
  state.mode = data.mode || state.mode;
  updateSidebarStatus();
  if (data.interfaces) populateInterfaces(data.interfaces);
  else refreshInterfaces();
}

function setIfaceBusy(busy, label) {
  ['btn-monitor', 'btn-managed', 'btn-monitor-panel', 'btn-managed-panel'].forEach(id => {
    document.getElementById(id)?.toggleAttribute('disabled', busy);
  });
  if (label) setText('iface-info', label);
}

async function ensureSelectedInterface() {
  if (state.interface) return state.interface;
  const selected = document.getElementById('iface-select')?.value;
  if (!selected) {
    toast('Select an interface first', 'warn');
    return '';
  }
  const resp = await api('/api/interface/select', 'POST', { interface: selected });
  if (!resp?.ok) return '';
  state.interface = selected;
  state.mode = resp.mode || '';
  updateSidebarStatus();
  return selected;
}

function setScanUi(active, label) {
  state.scanActive = active;
  setPulse(active);
  setText('scan-status-text', label);
  document.getElementById('btn-scan-start')?.toggleAttribute('disabled', active);
  document.getElementById('btn-scan-stop')?.toggleAttribute('disabled', !active);
}

/* ── Tab switching ─────────────────────────────────────────── */
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    const tab = item.dataset.tab;
    if (!tab) return;
    switchTab(tab);
    if (tab === 'arsenal' && typeof loadArsenal === 'function') loadArsenal();
    if (tab === 'agent' && typeof loadAgentStatus === 'function') loadAgentStatus();
    // Mobile: close sidebar
    if (window.innerWidth <= 768) {
      document.body.classList.remove('sidebar-open');
    }
  });
});

function switchTab(tab) {
  document.querySelectorAll('.nav-item').forEach(i => {
    const active = i.dataset.tab === tab;
    i.classList.toggle('active', active);
    i.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('.tab-content').forEach(s =>
    s.classList.toggle('active', s.id === `tab-${tab}`)
  );
}

document.getElementById('sidebar-toggle')?.addEventListener('click', () => {
  if (window.innerWidth <= 768) {
    document.body.classList.toggle('sidebar-open');
  } else {
    document.body.classList.toggle('sidebar-collapsed');
  }
});

/* ── Uptime counter ─────────────────────────────────────────── */
setInterval(() => {
  const diff = Number.isFinite(state.stats.uptime)
    ? state.stats.uptime++
    : Math.floor((Date.now() - state.startTime) / 1000);
  const h = String(Math.floor(diff/3600)).padStart(2,'0');
  const m = String(Math.floor((diff%3600)/60)).padStart(2,'0');
  const s = String(diff%60).padStart(2,'0');
  setText('uptime-val', `${h}:${m}:${s}`);
}, 1000);

/* ── Interface functions ─────────────────────────────────────── */
async function refreshInterfaces() {
  const resp = await api('/api/interfaces');
  if (resp?.interfaces) populateInterfaces(resp.interfaces);
}

function populateInterfaces(ifaces) {
  const sel = document.getElementById('iface-select');
  if (!sel) return;
  sel.innerHTML = '<option value="">── Select Interface ──</option>';
  ifaces.map(i => typeof i === 'string' ? { name: i, mode: 'unknown' } : i).forEach(i => {
    const opt = document.createElement('option');
    opt.value       = i.name;
    opt.textContent = `${i.name}  [${i.mode}]`;
    if (state.interface && i.name === state.interface) opt.selected = true;
    sel.appendChild(opt);
  });
}

async function selectInterface() {
  const sel   = document.getElementById('iface-select');
  const iface = sel?.value;
  if (!iface) return toast('Select an interface first', 'warn');

  const resp = await api('/api/interface/select', 'POST', { interface: iface });
  if (resp?.ok) {
    state.interface = iface;
    state.mode      = resp.mode || '';
    updateSidebarStatus();
    document.getElementById('iface-info').textContent =
      `Interface: ${iface}  |  Mode: ${resp.mode}`;
    toast(`Interface set: ${iface}`, 'success');
    loadHealth();
  } else {
    toast(resp?.error || 'Failed to set interface', 'error');
  }
}

async function enableMonitor() {
  const iface = await ensureSelectedInterface();
  if (!iface) return;
  setIfaceBusy(true, `Enabling monitor mode on ${iface}…`);
  const resp = await api('/api/interface/monitor', 'POST', { interface: iface });
  setIfaceBusy(false);
  if (resp?.ok) {
    applyInterfaceState(resp);
    toast(`Monitor mode on ${resp.interface}`, 'success');
  }
}

async function enableManaged() {
  const iface = await ensureSelectedInterface();
  if (!iface) return;
  setIfaceBusy(true, `Switching ${iface} to managed mode…`);
  const resp = await api('/api/interface/managed', 'POST', { interface: iface });
  setIfaceBusy(false);
  if (resp?.ok) {
    applyInterfaceState(resp);
    toast(`Managed mode on ${resp.interface}`, 'success');
  }
}

/* ── Scanner ─────────────────────────────────────────────────── */
async function startScan() {
  const channel = parseInt(document.getElementById('scan-channel')?.value || '0');
  const band    = document.getElementById('scan-band')?.value || 'bg';
  const duration = parseInt(document.getElementById('scan-duration')?.value || '0');
  const resp    = await api('/api/scan/start', 'POST', { channel, band, duration });

  if (resp?.ok) {
    setScanUi(true, `Scanning (${band})${duration ? ` for ${duration}s` : ''}…`);
    toast('Scan started! Detecting networks...', 'success');
  } else {
    toast(resp?.error || 'Failed to start scan', 'error');
  }
}

async function stopScan() {
  const resp = await api('/api/scan/stop', 'POST');
  if (resp?.ok) {
    setScanUi(false, 'Scan stopped');
    toast('Scan stopped.', 'info');
  }
}

function setPulse(active) {
  document.getElementById('scan-pulse')?.classList.toggle('active', active);
}

function quickScan() {
  switchTab('scanner');
  const duration = document.getElementById('scan-duration');
  if (duration) duration.value = '30';
  setTimeout(startScan, 300);
}

/* ── Attack functions ─────────────────────────────────────────── */
function applyTargetToAttackForm(network) {
  if (!network) return;
  const bssidEl = document.getElementById('atk-bssid');
  const essidEl = document.getElementById('atk-essid');
  const channelEl = document.getElementById('atk-channel');
  const vectorEl = document.getElementById('atk-vector');
  if (bssidEl) bssidEl.value = network.bssid || '';
  if (essidEl) essidEl.value = network.essid || '';
  if (channelEl && network.channel) channelEl.value = String(network.channel);
  if (vectorEl && network.attack_vector && network.attack_vector !== 'NONE') {
    vectorEl.value = network.attack_vector;
  }
  const rfBssid = document.getElementById('rf-bssid');
  const rfEssid = document.getElementById('rf-essid');
  const rfChannel = document.getElementById('rf-channel');
  const rfClient = document.getElementById('rf-client');
  if (rfBssid) rfBssid.value = network.bssid || '';
  if (rfEssid) rfEssid.value = network.essid || '';
  if (rfChannel && network.channel) rfChannel.value = String(network.channel);
  if (rfClient && Array.isArray(network.client_macs) && network.client_macs.length === 1) {
    rfClient.value = network.client_macs[0];
  }
  if (typeof applyTwinTarget === 'function') applyTwinTarget(network);
  updateAttackTargetHint(network);
  updateRfTargetHint(network);
}

function updateAttackTargetHint(network) {
  const hint = document.getElementById('attack-target-hint');
  if (!hint) return;
  if (network?.bssid) {
    hint.textContent = `Selected: ${network.essid || 'hidden'} (${network.bssid}) on channel ${network.channel || '?'}`;
  } else {
    hint.textContent = 'Click a network in Scanner to auto-fill BSSID, ESSID, and channel.';
  }
}

function updateRfTargetHint(network) {
  const hint = document.getElementById('rf-target-hint');
  if (!hint) return;
  if (network?.bssid) {
    const clients = (network.client_macs || []).length;
    hint.textContent = `Selected: ${network.essid || 'hidden'} (${network.bssid}) · ${clients} client MAC${clients === 1 ? '' : 's'}`;
  } else {
    hint.textContent = 'Uses the Scanner target. Prefer mdk4, then mdk3, then aireplay-ng for deauth.';
  }
}

async function launchRf() {
  const payload = {
    mode: document.getElementById('rf-mode')?.value || 'deauth',
    bssid: document.getElementById('rf-bssid')?.value?.trim() || '',
    essid: document.getElementById('rf-essid')?.value?.trim() || '',
    channel: parseInt(document.getElementById('rf-channel')?.value || '0', 10),
    client: document.getElementById('rf-client')?.value?.trim() || '',
    duration: parseInt(document.getElementById('rf-duration')?.value || '30', 10),
    stealth: !!document.getElementById('rf-stealth')?.checked,
    rotate_mac: !!document.getElementById('rf-rotate-mac')?.checked,
    authorized: true,
  };
  if (payload.mode !== 'beacon' && !payload.bssid) {
    return toast('Select a network in Scanner or enter a BSSID', 'warn');
  }
  if (!confirm('Only continue if you are authorized to run this RF preset. Start now?')) return;
  const resp = await api('/api/rf/start', 'POST', payload);
  if (resp?.ok) {
    toast(`RF ${payload.mode} started (${resp.tool || 'tool'})`, 'success');
    setTimeout(loadJobs, 400);
  }
}

async function stopRf() {
  const resp = await api('/api/rf/stop', 'POST', {});
  if (resp?.ok) toast('RF jobs stopped', 'warn');
}

async function loadRfStatus() {
  const resp = await api('/api/rf/status');
  if (!resp?.readiness) return;
  const label = document.getElementById('rf-tool-label');
  if (label) {
    label.textContent = resp.readiness.tool
      ? `using ${resp.readiness.tool}`
      : 'mdk4 / mdk3 missing';
  }
}

function selectScannedNetwork(index, options = {}) {
  const network = state.networks[index];
  if (!network) return;
  if (!network.bssid) {
    toast('This row has no BSSID yet — wait for the scan to refresh', 'warn');
    return;
  }
  state.selectedNetwork = network;
  applyTargetToAttackForm(network);
  renderNetworksTable();
  if (options.openModal) {
    openAttackModal(network);
  } else if (options.switchTab) {
    switchTab('attacks');
  }
  if (!options.silent) {
    toast(`Target set: ${network.essid} (${network.bssid})`, 'info', 2500);
  }
}

function resolveAttackPayload(extra = {}) {
  let bssid = document.getElementById('atk-bssid')?.value?.trim() || '';
  let essid = document.getElementById('atk-essid')?.value?.trim() || '';
  let channel = parseInt(document.getElementById('atk-channel')?.value || '0', 10);
  const attack = document.getElementById('atk-vector')?.value;
  let networkIndex = null;

  if (!bssid && state.selectedNetwork?.bssid) {
    applyTargetToAttackForm(state.selectedNetwork);
    bssid = state.selectedNetwork.bssid;
    essid = essid || state.selectedNetwork.essid || '';
    if (!channel) channel = state.selectedNetwork.channel || 6;
    networkIndex = state.networks.indexOf(state.selectedNetwork);
  }
  if (!bssid && essid) {
    const match = state.networks.find(n => (n.essid || '').toLowerCase() === essid.toLowerCase());
    if (match?.bssid) {
      bssid = match.bssid;
      if (!channel) channel = match.channel || 6;
      networkIndex = state.networks.indexOf(match);
      state.selectedNetwork = match;
      applyTargetToAttackForm(match);
    }
  }
  if (!channel) channel = 6;
  return {
    bssid,
    essid,
    attack,
    channel,
    wordlist: document.getElementById('atk-wordlist')?.value || '',
    network_index: networkIndex != null && networkIndex >= 0 ? networkIndex : undefined,
    ...extra,
  };
}

async function launchAttack() {
  const payload = resolveAttackPayload({ authorized: true });
  if (!payload.bssid && payload.essid) {
    payload.network_index = undefined;
  }
  if (!payload.bssid && !payload.essid) {
    return toast('Select a network in Scanner or enter BSSID / ESSID', 'warn');
  }

  if (!confirm('Only continue if you are authorized to test this network. Start now?')) return;
  const resp = await api('/api/attack', 'POST', payload);
  if (resp?.ok) {
    toast(`⚔️ Job ${resp.job_id} launched: ${attack}`, 'success');
    switchTab('attacks');
    setTimeout(loadJobs, 500);
  } else {
    toast(resp?.error || 'Attack failed to start', 'error');
  }
}

async function autoAttack() {
  const bssids = [...document.querySelectorAll('.network-select:checked')]
    .map(input => input.value)
    .filter(Boolean);
  if (!bssids.length) {
    if (state.selectedNetwork?.bssid) {
      selectScannedNetwork(state.networks.indexOf(state.selectedNetwork), { silent: true });
      return autoAttackFromNetwork(state.selectedNetwork);
    }
    return toast('Check targets in Scanner or click a row to select one', 'warn');
  }
  if (!confirm(`Run recommended actions sequentially on ${bssids.length} authorized target(s)?`)) return;
  const resp = await api('/api/attack/auto', 'POST', {
    bssids, authorized: true
  });
  if (resp?.ok) {
    toast(`🤖 Auto-attack: ${resp.count} targets queued`, 'success');
    switchTab('attacks');
  } else {
    toast(resp?.error || 'No selected targets — run a scan first', 'warn');
  }
}

async function autoAttackFromNetwork(network) {
  if (!network?.bssid) return;
  const resp = await api('/api/attack/auto', 'POST', {
    bssids: [network.bssid],
    authorized: true,
  });
  if (resp?.ok) {
    toast(`🤖 Queued ${network.essid}`, 'success');
    switchTab('attacks');
  } else {
    toast(resp?.error || 'Could not queue target', 'warn');
  }
}

async function launchWifite() {
  if (!confirm('Run Wifite2 only on networks you are authorized to test. Continue?')) return;
  const resp = await api('/api/wifite/run', 'POST', {
    timeout: 300, authorized: true
  });
  if (resp?.ok) {
    toast(`🐍 Wifite2 launched! Job: ${resp.job_id}`, 'success');
    switchTab('console');
  } else {
    toast(resp?.error || 'Failed to launch wifite', 'error');
  }
}

/* Attack modal (from network table) */
let _modalTarget = null;

function openAttackModal(networkOrBssid, essid, channel, defaultVector) {
  const network = typeof networkOrBssid === 'object'
    ? networkOrBssid
    : {
        bssid: networkOrBssid,
        essid,
        channel,
        attack_vector: defaultVector,
      };
  if (!network?.bssid) {
    return toast('Missing BSSID — re-run scan and select the network again', 'warn');
  }
  if (network.attack_vector === 'NONE') {
    return toast('Open network detected; no cracking action is recommended', 'info');
  }
  _modalTarget = network;
  state.selectedNetwork = network;
  applyTargetToAttackForm(network);
  setText('modal-attack-title', `⚔️ Attack: ${network.essid || network.bssid}`);
  setText('modal-target-essid', network.essid || '<hidden>');
  setText('modal-target-bssid', network.bssid);
  setText('modal-target-channel', String(network.channel || '?'));
  const sel = document.getElementById('modal-atk-vector');
  if (sel && network.attack_vector) sel.value = network.attack_vector;
  document.getElementById('modal-attack').style.display = 'flex';
  sel?.focus();
}

async function confirmAttack() {
  const attack = document.getElementById('modal-atk-vector')?.value;
  closeModal('modal-attack');
  if (!_modalTarget?.bssid) {
    return toast('No target selected', 'warn');
  }
  if (!confirm('Confirm you are authorized to test this network.')) return;
  const index = state.networks.indexOf(_modalTarget);
  const resp = await api('/api/attack', 'POST', {
    bssid: _modalTarget.bssid,
    essid: _modalTarget.essid || '',
    channel: _modalTarget.channel || 6,
    attack,
    network_index: index >= 0 ? index : undefined,
    authorized: true,
  });
  if (resp?.ok) {
    toast(`⚔️ Job ${resp.job_id}: ${attack} on ${_modalTarget.essid || _modalTarget.bssid}`, 'success');
    switchTab('attacks');
    setTimeout(loadJobs, 500);
  } else {
    toast(resp?.error || 'Attack failed', 'error');
  }
}

function closeModal(id) {
  document.getElementById(id).style.display = 'none';
  const attackButton = document.getElementById('modal-attack-btn');
  attackButton?.removeAttribute('hidden');
  if (attackButton) attackButton.style.display = '';
}

async function previewAttack() {
  const payload = {
    ...resolveAttackPayload(),
    dry_run: true,
  };
  const resp = await api('/api/attack', 'POST', payload);
  if (resp?.ok) {
    toast(`Requires: ${resp.requirements.join(', ') || 'no additional tools'}`, 'info', 7000);
  }
}

/* ── Render: Networks Table ─────────────────────────────────── */
function renderNetworksTable() {
  const tbody = document.getElementById('networks-tbody');
  if (!tbody) return;

  setText('scan-count', `${state.networks.length} networks`);
  setText('nav-badge-networks', state.networks.length);

  if (!state.networks.length) {
    tbody.innerHTML = '<tr><td colspan="11" class="empty-cell">No networks found yet</td></tr>';
    return;
  }

  tbody.innerHTML = state.networks.map((n, index) => {
    const signalBars = signalToBars(n.signal);
    const encColor   = encToColor(n.encryption);
    const wpsLabel   = n.wps
      ? `<span style="color:${n.wps_locked?'#ff6b35':'#00ff41'}">${n.wps_locked?'🔒':'✓'}</span>`
      : '<span style="color:#3a5040">✗</span>';
    const clientsBadge = n.clients > 0
      ? `<span style="color:var(--accent-cyan)">${n.clients}</span>`
      : '<span style="color:#3a5040">0</span>';

    const selected = state.selectedNetwork?.bssid === n.bssid;
    return `<tr class="network-row${selected ? ' network-row-selected' : ''}" data-network-index="${index}">
      <td><span class="threat-badge threat-${n.threat_level}">${n.threat_level}</span></td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${esc(n.essid)}">${esc(n.essid)}</td>
      <td style="color:var(--text-muted)">${n.bssid}</td>
      <td>${n.channel}</td>
      <td>
        <div class="signal-bar">
          ${signalBars}
          <span style="font-size:0.7rem;color:var(--text-muted)">${n.signal}dBm</span>
        </div>
      </td>
      <td><span style="color:${encColor}">${n.encryption||'OPN'}</span></td>
      <td>${wpsLabel}</td>
      <td>${clientsBadge}</td>
      <td style="color:var(--accent-cyan);font-size:0.72rem">${n.attack_vector||'—'}</td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <div class="progress-bar" style="width:50px">
            <div class="progress-fill" style="width:${n.confidence}%"></div>
          </div>
          <span style="font-size:0.7rem;color:var(--text-muted)">${n.confidence}%</span>
        </div>
      </td>
      <td>
        <input class="network-select" type="checkbox" value="${esc(n.bssid || '')}"
          data-network-index="${index}"
          aria-label="Select ${esc(n.essid)} for automated action"
          ${!n.bssid || n.attack_vector === 'NONE' ? 'disabled' : ''}>
        <button class="btn btn-sm btn-primary network-action" style="padding:3px 10px"
          data-network-index="${index}" aria-label="Review action for ${esc(n.essid)}"
          ${n.attack_vector === 'NONE' ? 'disabled' : ''}>
          Review
        </button>
        <button class="btn btn-sm btn-ghost network-twin" style="padding:3px 10px"
          data-network-index="${index}" aria-label="Use ${esc(n.essid)} as Evil Twin">
          Twin
        </button>
      </td>
    </tr>`;
  }).join('');
}

function signalToBars(sig) {
  const level = sig >= -50 ? 4 : sig >= -65 ? 3 : sig >= -75 ? 2 : 1;
  return `<div class="signal-dots">
    ${[1,2,3,4].map(i => `<div class="signal-dot${i<=level?' active':''}"></div>`).join('')}
  </div>`;
}

function encToColor(enc) {
  if (!enc || enc === 'OPN') return '#ff6b35';
  if (enc.includes('WEP'))   return '#ffd60a';
  if (enc.includes('WPA3'))  return '#bf5af2';
  return '#00d4ff';
}

/* ── Render: Jobs ─────────────────────────────────────────────── */
async function loadJobs() {
  const resp = await api('/api/jobs');
  if (resp?.jobs) {
    state.jobs = resp.jobs;
    renderJobsList();
  }
}

function renderJobsList() {
  const list = document.getElementById('jobs-list');
  if (!list) return;

  const jobs = Object.values(state.jobs).reverse();
  setText('jobs-count', `${jobs.length} jobs`);
  setText('nav-badge-jobs', jobs.filter(j => j.state === 'RUNNING').length);

  if (!jobs.length) {
    list.innerHTML = '<div class="empty-state">No jobs yet.</div>';
    return;
  }

  list.innerHTML = jobs.map(j => {
    const dur = j.ended_at
      ? `${((j.ended_at - j.started_at)|0)}s`
      : `${((Date.now()/1000 - j.started_at)|0)}s`;

    return `<div class="job-card ${j.state}">
      <div class="job-header">
        <span class="job-title">${esc(j.essid||'Unknown')} <span style="color:var(--text-muted);font-size:0.72rem">${j.bssid}</span></span>
        <span class="job-state job-state-${j.state}">${j.state}</span>
      </div>
      ${j.key ? `<div class="job-key">🔑 ${esc(j.key)}</div>` : ''}
      <div class="progress-bar"><div class="progress-fill" style="width:${j.progress}%"></div></div>
      <div class="job-meta">
        <span>⚔️ ${j.attack}</span>
        <span>🆔 ${j.id}</span>
        <span>⏱ ${dur}</span>
        ${j.state==='RUNNING' ? `<button class="btn btn-sm btn-danger" style="padding:2px 8px" onclick="killJob('${j.id}')">✕ Kill</button>` : ''}
        ${j.state==='FAILED' && (j.online_id || j.capture || j.hash_file)
          ? `<button class="btn btn-sm btn-primary" style="padding:2px 8px" onclick="submitOnlineFromJob('${j.id}', '${j.online_id || ''}')">☁ Online crack</button>`
          : ''}
      </div>
    </div>`;
  }).join('');
}

async function killJob(jid) {
  const resp = await api(`/api/job/${jid}/kill`, 'POST');
  if (resp?.ok) {
    toast(`Job ${jid} stopped`, 'warn');
    loadJobs();
  }
}

/* ── Render: Cracked Table ──────────────────────────────────── */
async function loadCracked() {
  const resp = await api('/api/cracked');
  if (resp) {
    state.cracked = filterValidCracked(resp.cracked);
    renderCrackedTable();
    updateDashboardStats();
  }
}

function renderCrackedTable() {
  const tbody = document.getElementById('cracked-tbody');
  if (!tbody) return;

  const rows = filterValidCracked(state.cracked);
  setText('nav-badge-cracked', rows.length);
  setText('cracked-count-label', `${rows.length} found`);

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">No cracked passwords yet</td></tr>';
    renderCrackedMini();
    return;
  }

  tbody.innerHTML = rows.slice().reverse().map((c, i) => `
    <tr>
      <td style="color:var(--text-muted)">${i+1}</td>
      <td style="font-weight:600">${esc(c.essid||'?')}</td>
      <td style="color:var(--text-muted)">${c.bssid||'?'}</td>
      <td>
        <span class="job-key secret-value">${esc(c.key||'—')}</span>
        <button class="btn btn-sm btn-ghost reveal-secret" data-key="${esc(c.key||'')}">Reveal</button>
      </td>
      <td><span class="threat-badge threat-EASY">${c.type||c.attack||'WPA'}</span></td>
      <td style="color:var(--text-muted);font-size:0.75rem">${fmtDate(c.date)}</td>
      <td><button class="btn btn-sm btn-primary pivot-ready" data-index="${i}">Pivot</button></td>
    </tr>
  `).join('');

  renderCrackedMini();
}

function renderCrackedMini() {
  const list = document.getElementById('recent-cracked-list');
  if (!list) return;

  const recent = filterValidCracked(state.cracked).slice(-5).reverse();
  if (!recent.length) {
    list.innerHTML = '<div class="empty-state">No cracks yet. Run an attack!</div>';
    return;
  }
  list.innerHTML = recent.map(c => `
    <div class="cracked-mini-item">
      <span class="cracked-mini-essid">${esc(c.essid||'?')}</span>
      <span class="cracked-mini-key">🔑 ${esc(c.key||'—')}</span>
    </div>
  `).join('');
}

/* ── Dashboard Stats ────────────────────────────────────────── */
function updateDashboardStats() {
  const easy       = state.networks.filter(n => n.threat_level === 'EASY').length;
  const suspicious = state.networks.filter(n => n.threat_level === 'SUSPICIOUS').length;
  const activeJobs = Object.values(state.jobs).filter(j => j.state === 'RUNNING').length;

  setText('stat-networks',   state.networks.length);
  setText('stat-easy',       easy);
  setText('stat-suspicious', suspicious);
  setText('stat-jobs',       activeJobs);
  setText('stat-cracked',    filterValidCracked(state.cracked).length);
  setText('nav-badge-jobs',  activeJobs);
}

/* ── Tools ──────────────────────────────────────────────────── */
async function loadTools() {
  const resp = await api('/api/tools');
  if (resp) renderTools(resp);
}

function renderTools(payload) {
  const grid = document.getElementById('tools-grid');
  if (!grid) return;

  const icons = {
    'airmon-ng':     '📻', 'airodump-ng':   '📡', 'aireplay-ng': '💥',
    'aircrack-ng':   '🔑', 'hashcat':       '⚡', 'hcxdumptool': '📦',
    'hcxtools':      '🛠️',  'hcxpcapngtool': '🔄', 'wifite':      '🐍',
    'reaver':        '🔨', 'bully':         '🐂', 'macchanger':  '🎭',
    'tshark':        '🦈', 'nmap':          '🗺️',  'cowpatty':    '🐄',
    'nxc':           '🔍', 'msfconsole':    '💣',
    'arp-scan':      '🖧', 'bettercap':     '🎯', 'tcpdump':     '📼',
    'hostapd':       '📡', 'dnsmasq':       '🌐', 'mdk4':        '📶',
    'mdk3':          '📶', 'wpa_supplicant': '🌉', 'dhclient':   '🌐',
    'wash':          '📻', 'ncrack':        '🔓', 'wifiphisher': '🎣',
    'wifipumpkin3':  '🎃', 'eaphammer':     '🏢', 'hydra':       '🐉',
  };

  const entries = payload.entries || Object.entries(payload.tools || {}).map(([name, ok]) => ({
    name, ready: ok, required: false, install: '',
  }));

  grid.innerHTML = entries.map(entry => {
    const ok = entry.ready;
    const optional = entry.optional || !entry.required;
    const hint = !ok && entry.install
      ? `<span class="tool-install" title="${esc(entry.install)}">${esc(entry.install)}</span>`
      : '';
    const tag = optional ? '<span class="tool-tag">optional</span>' : '';
    return `<div class="tool-chip ${ok ? 'ok' : optional ? 'miss-optional' : 'miss'}">
      <span class="tool-icon">${icons[entry.name] || '🔧'}</span>
      <span class="tool-name">${entry.name}${tag}</span>
      <span class="tool-status">${ok ? '✓ Ready' : optional ? '· Optional' : '✗ Missing'}</span>
      ${hint}
    </div>`;
  }).join('');
}

async function loadOnlineQueue() {
  const list = document.getElementById('online-queue-list');
  const resp = await api('/api/online-queue');
  if (!resp?.ok) return;
  state.onlineQueue = resp.items || [];
  setText('online-count-label', `${state.onlineQueue.length} saved`);
  if (!list) return;
  if (!state.onlineQueue.length) {
    list.innerHTML = '<div class="empty-state">No saved hashes yet. Failed handshake jobs land here.</div>';
    return;
  }
  list.innerHTML = state.onlineQueue.slice().reverse().map(item => {
    const tried = (item.lists_tried || []).join(' → ') || 'local lists';
    const canSend = item.status === 'queued' || item.status === 'error';
    const key = item.key ? `<div class="job-key">🔑 ${esc(item.key)}</div>` : '';
    return `<div class="online-card ${esc(item.status || '')}">
      <div class="job-header">
        <span class="job-title">${esc(item.essid || '?')} <span style="color:var(--text-muted);font-size:0.72rem">${esc(item.bssid || '')}</span></span>
        <span class="job-state job-state-${esc(item.status || 'queued')}">${esc(item.status || 'queued')}</span>
      </div>
      <div class="label-muted">${esc(item.message || '')}</div>
      <div class="mono">${esc(tried)}</div>
      ${key}
      <div class="form-actions">
        ${canSend ? `<button class="btn btn-sm btn-primary" onclick="submitOnlineItem('${esc(item.id)}')">☁ Send to wpa-sec</button>` : ''}
        <a class="btn btn-sm btn-ghost" href="/api/online-queue/${esc(item.id)}/download">⬇ Hash</a>
      </div>
    </div>`;
  }).join('');
}

async function saveOnlineKey() {
  const key = document.getElementById('online-api-key')?.value?.trim() || '';
  const resp = await api('/api/online-queue/key', 'POST', { api_key: key });
  if (resp?.ok) {
    toast(key ? 'wpa-sec API key saved' : 'wpa-sec API key cleared', 'success');
    document.getElementById('online-api-key').value = '';
  }
}

async function submitOnlineItem(itemId) {
  if (!itemId) return toast('Nothing queued for online crack', 'warn');
  if (!confirm('Upload this handshake hash to wpa-sec? The file leaves this machine.')) return;
  const resp = await api(`/api/online-queue/${itemId}/submit`, 'POST', { authorized: true });
  if (resp?.ok) {
    toast(resp.item?.message || 'Submitted', 'success', 6000);
    loadOnlineQueue();
  } else {
    toast(resp?.error || 'Submit failed', 'error');
  }
}

async function submitOnlineFromJob(jobId, onlineId) {
  let itemId = onlineId;
  if (!itemId) {
    const queued = await api(`/api/online-queue/from-job/${jobId}`, 'POST', { authorized: true });
    if (!queued?.ok) return toast(queued?.error || 'No saved handshake on this job', 'error');
    itemId = queued.item?.id;
  }
  return submitOnlineItem(itemId);
}

async function checkOnlineQueue() {
  const resp = await api('/api/online-queue/check', 'POST', {});
  if (!resp?.ok) return toast(resp?.error || 'Check failed', 'error');
  if ((resp.hits || []).length) {
    toast(`🏆 ${resp.hits.length} online hit(s)`, 'success', 8000);
    loadCracked();
  } else {
    toast('No new online results yet', 'info');
  }
  loadOnlineQueue();
}

async function loadWordlists() {
  const info = document.getElementById('wordlist-info');
  if (!info) return;
  const resp = await api('/api/wordlists');
  if (!resp) return;
  const select = document.getElementById('atk-wordlist');
  if (select && resp.active_tier && !select.value) {
    select.value = resp.active_tier;
  }
  info.innerHTML = (resp.wordlists || []).map(item => {
    const count = item.count ? `${item.count.toLocaleString()} keys` : 'not built';
    const active = item.active ? ' active' : '';
    const ready = item.exists ? 'ok' : 'miss';
    return `<div class="wordlist-card${active}">
      <div>
        <strong>${esc(item.label || item.tier)}</strong>
        <div class="label-muted">${esc(item.hint || '')}</div>
        <div class="mono">${esc(item.path || '')}</div>
      </div>
      <div>
        <span class="twin-chip ${ready}">${esc(count)}</span>
        ${item.exists && item.tier && item.tier !== 'builtin'
          ? `<button class="btn btn-sm btn-ghost" onclick="selectWordlist('${esc(item.tier)}')">${item.active ? 'Active' : 'Use'}</button>`
          : ''}
      </div>
    </div>`;
  }).join('');
}

async function selectWordlist(tier) {
  const resp = await api('/api/wordlists/select', 'POST', { tier });
  if (resp?.ok) {
    toast(`Wordlist: ${resp.label}`, 'success');
    const select = document.getElementById('atk-wordlist');
    if (select) select.value = tier;
    loadWordlists();
    loadHealth();
  }
}

async function rebuildWordlists() {
  if (!confirm('Rebuild Fast/Smart/Deep from SecLists and local rockyou? This stays on disk under snakefw/wordlists/.')) return;
  toast('Rebuilding wordlists…', 'info', 5000);
  const resp = await api('/api/wordlists/build', 'POST', {});
  if (resp?.ok) {
    toast('Wordlists rebuilt. Smart is active.', 'success', 6000);
    loadWordlists();
    loadHealth();
  }
}

async function changeMac(mode) {
  const iface = document.getElementById('mac-iface')?.value?.trim();
  if (!iface) return toast('Enter interface name', 'warn');

  if (!confirm(`${mode === 'random' ? 'Randomize' : 'Restore'} the MAC on ${iface}? The link will briefly go down.`)) return;
  const resp = await api('/api/mac', 'POST', { interface: iface, mode });
  if (resp?.ok) {
    setText('mac-result', resp.output || 'MAC updated');
    toast(`MAC updated on ${iface}`, 'success');
  }
}

async function loadHealth() {
  const summary = document.getElementById('health-summary');
  const resp = await api('/api/health');
  if (!summary || !resp) return;
  const requiredMissing = resp.required_missing || [];
  const optionalMissing = resp.optional_missing || [];
  summary.className = `health-summary ${resp.ok ? 'ready' : 'warning'}`;
  if (resp.ok) {
    const opt = optionalMissing.length
      ? ` Optional not installed: ${optionalMissing.join(', ')}.`
      : '';
    summary.textContent = `Ready. ${resp.interfaces.length} interface(s); wordlist: ${resp.active_wordlist || 'none'}.${opt}`;
  } else {
    summary.textContent = `Missing required tools: ${requiredMissing.join(', ') || 'unknown'}. Run snake.py doctor.`;
  }
  renderRadioPlan(resp.radios);
}

function renderRadioPlan(plan) {
  const chips = document.getElementById('radio-plan-chips');
  if (!chips) return;
  if (!plan) {
    chips.textContent = 'No radio plan yet.';
    return;
  }
  const rows = [
    ['Scan', plan.scan_iface],
    ['Attack', plan.attack_iface],
    ['Twin AP', plan.ap_iface],
    ['Pivot', plan.client_iface],
  ];
  chips.innerHTML = rows.map(([label, name]) =>
    `<span class="radio-chip ${name ? 'ok' : 'miss'}">${esc(label)} · ${esc(name || '—')}</span>`
  ).join('') + `<span class="radio-chip">${plan.dual_radio ? 'Dual radio' : 'Single radio'}</span>`;
}

function openReport() {
  window.open('/api/report/html', '_blank', 'noopener');
}

async function startPivotFromCracked(entry) {
  const essid = entry?.essid || '';
  const key = entry?.key || entry?.password || entry?.psk || '';
  if (!essid || !key) return toast('That row has no ESSID or key', 'warn');
  if (!confirm(`Join ${essid} and run Strike? Only continue if you are authorized.`)) return;
  const resp = await api('/api/pivot/start', 'POST', {
    essid,
    bssid: entry.bssid || '',
    psk: key,
    launch_strike: true,
    stop_wireless: true,
    authorized: true,
  });
  if (resp?.ok) {
    toast(`Pivoting onto ${essid}…`, 'success');
    switchTab('strike');
  }
}

/* ── Console ─────────────────────────────────────────────────── */
function appendLog(entry, scroll = true) {
  const body = document.getElementById('console-body');
  if (!body) return;

  const ts  = new Date(entry.ts * 1000).toLocaleTimeString('en-US', { hour12: false });
  const lvl = (entry.level || 'INFO').toUpperCase();

  const div = document.createElement('div');
  div.className = `console-line ${lvl}`;
  div.innerHTML = `<span class="log-ts">${ts}</span><span class="log-msg">${esc(entry.msg||'')}</span>`;
  body.appendChild(div);

  // Keep at max 2000 lines
  while (body.children.length > 2000) {
    body.removeChild(body.firstChild);
  }

  const autoScroll = document.getElementById('console-autoscroll');
  if (scroll && autoScroll?.checked) {
    body.scrollTop = body.scrollHeight;
  }
}

function clearConsole() {
  const body = document.getElementById('console-body');
  if (body) body.innerHTML = '';
}

function scrollConsole() {
  const body = document.getElementById('console-body');
  if (body) body.scrollTop = body.scrollHeight;
}

/* ── Export ──────────────────────────────────────────────────── */
function exportCracked() {
  window.open('/api/results/export', '_blank');
}

/* ── Utility ─────────────────────────────────────────────────── */
async function api(url, method = 'GET', body = null) {
  try {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(url, opts);
    const contentType = resp.headers.get('content-type') || '';
    const data = contentType.includes('application/json')
      ? await resp.json()
      : { ok: false, error: await resp.text() || `HTTP ${resp.status}` };
    if (!resp.ok) {
      toast(data.error || `Request failed (${resp.status})`, 'error');
    }
    return data;
  } catch (e) {
    console.error('API error:', e);
    toast('Cannot reach Snake. Check the server connection.', 'error');
    return null;
  }
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function fmtDate(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString();
}

function copyText(text) {
  navigator.clipboard?.writeText(text).then(() => toast(`Copied: ${text}`, 'success'));
}

function shakeElement(sel) {
  const el = document.querySelector(sel);
  if (!el) return;
  el.style.animation = 'none';
  el.offsetHeight;
  el.style.animation = 'shake 0.4s ease';
  el.style.setProperty('--tw-shadow-color', 'var(--accent-gold)');
}

function toast(msg, type = 'info', duration = 3500) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const t = document.createElement('div');
  t.className = `toast ${type}`;
  const icons = { success: '✓', error: '✗', info: 'ℹ', warn: '⚠' };
  const icon = document.createElement('span');
  const message = document.createElement('span');
  icon.textContent = icons[type] || '•';
  message.textContent = String(msg);
  t.append(icon, message);
  container.appendChild(t);

  setTimeout(() => {
    t.style.animation = 'slideIn 0.3s ease reverse';
    setTimeout(() => t.remove(), 300);
  }, duration);
}

/* ── Init ─────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  refreshInterfaces();
  loadCracked();
  loadTools();
  loadWordlists();
  loadOnlineQueue();
  loadHealth();
  loadRfStatus();

  const networksBody = document.getElementById('networks-tbody');
  networksBody?.addEventListener('click', event => {
    const checkbox = event.target.closest('.network-select');
    if (checkbox) {
      selectScannedNetwork(Number(checkbox.dataset.networkIndex), { silent: true });
      return;
    }
    const button = event.target.closest('.network-action');
    if (button) {
      selectScannedNetwork(Number(button.dataset.networkIndex), { openModal: true });
      return;
    }
    const twinBtn = event.target.closest('.network-twin');
    if (twinBtn) {
      useNetworkAsTwin(Number(twinBtn.dataset.networkIndex));
      return;
    }
    const row = event.target.closest('tr[data-network-index]');
    if (row) {
      selectScannedNetwork(Number(row.dataset.networkIndex), { switchTab: false });
    }
  });

  document.getElementById('cracked-tbody')?.addEventListener('click', event => {
    const pivotBtn = event.target.closest('.pivot-ready');
    if (pivotBtn) {
      const rows = filterValidCracked(state.cracked).slice().reverse();
      startPivotFromCracked(rows[Number(pivotBtn.dataset.index)]);
      return;
    }
    const button = event.target.closest('.reveal-secret');
    if (!button) return;
    const secret = button.previousElementSibling;
    secret?.classList.toggle('revealed');
    button.textContent = secret?.classList.contains('revealed') ? 'Hide' : 'Reveal';
  });

  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeModal('modal-attack');
  });

  // Topbar mode buttons
  document.getElementById('btn-monitor')?.addEventListener('click', enableMonitor);
  document.getElementById('btn-managed')?.addEventListener('click', enableManaged);

  // Periodic job refresh
  setInterval(loadJobs, 8000);

  // Cracked refresh
  setInterval(loadCracked, 30000);
  setInterval(loadOnlineQueue, 30000);

  toast('🐍 Snake loaded. Select an interface to begin.', 'info', 5000);
});
