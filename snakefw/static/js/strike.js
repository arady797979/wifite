/**
 * Snake Strike — Nmap → NetExec → Metasploit chain UI
 */

const strike = {
  running: false,
  phase: 'idle',
  progress: 0,
  hosts: [],
  findings: [],
  msfQueue: [],
  msfResults: [],
  recommended: null,
  selectedIp: null,
  tools: {},
  filter: 'all',
  nxcProfiles: {},
  nxcProtocols: ['smb', 'ssh', 'winrm', 'ldap', 'rdp', 'ftp', 'mssql', 'wmi', 'nfs', 'vnc', 'http'],
};

const STRIKE_PHASES = ['discover', 'nmap', 'netexec', 'analyze', 'done'];
const STRIKE_PHASE_LABEL = {
  idle: 'Ready',
  starting: 'Starting',
  discover: 'Finding live hosts',
  nmap: 'Scanning services',
  netexec: 'Checking with NetExec',
  analyze: 'Building the plan',
  stopping: 'Stopping',
  done: 'Ready — pick a device to nmap, NetExec, or check',
  failed: 'Failed',
  stopped: 'Stopped',
};

document.addEventListener('DOMContentLoaded', () => {
  _initStrikeSocket();
  loadStrikeStatus();
});

function _initStrikeSocket() {
  const poll = setInterval(() => {
    if (typeof socket !== 'undefined') {
      clearInterval(poll);
      _bindStrikeEvents();
    }
  }, 200);
}

function _bindStrikeEvents() {
  socket.on('strike_phase', (data) => {
    strike.phase = data.phase || strike.phase;
    strike.progress = data.progress ?? strike.progress;
    _updateStrikePipeline();
    _setProgress(strike.progress);
    _setStrikeStatus();
  });

  socket.on('strike_log', (entry) => {
    if (typeof appendLog === 'function') appendLog(entry);
  });

  socket.on('strike_hosts', (data) => {
    strike.hosts = data.hosts || [];
    renderStrikeHosts();
    _refreshStrikeCounts();
  });

  socket.on('strike_host_update', (data) => {
    if (!data.host) return;
    const idx = strike.hosts.findIndex(h => h.ip === data.host.ip);
    if (idx >= 0) strike.hosts[idx] = data.host;
    else strike.hosts.push(data.host);
    renderStrikeHosts();
    _refreshStrikeCounts();
  });

  socket.on('strike_findings', (data) => {
    strike.findings = data.findings || [];
    renderStrikeFindings();
    _refreshStrikeCounts();
  });

  socket.on('strike_msf', (data) => {
    strike.msfQueue = data.queue || [];
    strike.recommended = data.recommended || null;
    renderStrikeMsf();
    renderStrikeRecommended();
  });

  socket.on('strike_msf_result', (result) => {
    strike.msfResults = [...(strike.msfResults || []), result].slice(-20);
    _showMsfOutput(result);
    renderStrikeMsf();
    const verdict = result.verdict || '';
    if (result.likely_vulnerable) {
      toast(`Vulnerable: ${result.module} on ${result.rhosts || result.ip}`, 'warn', 9000);
    } else if (verdict === 'safe') {
      toast(`Not vulnerable: ${result.rhosts || result.ip}`, 'success');
    } else if (result.ok) {
      toast(`Metasploit ${verdict || 'done'}`, 'info');
    } else {
      toast(`Metasploit: ${result.error || 'check console'}`, 'error');
    }
  });

  socket.on('strike_msf_batch', (data) => {
    if (data.error) toast(data.error, 'error');
    const hits = (data.results || []).filter(r => r.likely_vulnerable).length;
    if (!data.error) toast(`Auto-check done — ${hits} likely hit(s)`, hits ? 'warn' : 'success');
  });

  socket.on('strike_complete', (data) => {
    strike.running = false;
    strike.phase = data.phase || 'done';
    strike.progress = data.progress ?? 100;
    if (data.hosts) strike.hosts = data.hosts;
    if (data.top_findings) strike.findings = data.top_findings;
    if (data.msf_queue) strike.msfQueue = data.msf_queue;
    if (data.recommended) strike.recommended = data.recommended;
    if (data.msf_results) strike.msfResults = data.msf_results;
    _setStrikeRunning(false);
    _updateStrikePipeline();
    renderStrikeHosts();
    renderStrikeFindings();
    renderStrikeMsf();
    renderStrikeRecommended();
    _refreshStrikeCounts();
    if (data.error) toast(`Strike: ${data.error}`, 'warn');
    else if (data.phase === 'done') {
      toast(`Strike complete — ${strike.hosts.length} host(s)`, 'success');
      if (strike.hosts[0]) selectStrikeHost(strike.hosts[0].ip);
    }
  });
}

async function loadStrikeStatus() {
  const resp = await api('/api/strike/status');
  if (!resp) return;

  strike.tools = resp.tools || {};
  strike.nxcProfiles = resp.nxc_profiles || strike.nxcProfiles;
  strike.nxcProtocols = resp.nxc_protocols || strike.nxcProtocols;
  _renderStrikeTools();

  const ifaceSel = document.getElementById('strike-iface');
  if (ifaceSel) {
    const ifaces = resp.ifaces || [];
    if (ifaceSel.tagName === 'SELECT') {
      ifaceSel.innerHTML = ifaces.map(name =>
        `<option value="${escHtml(name)}"${name === resp.iface ? ' selected' : ''}>${escHtml(name)}</option>`
      ).join('') || `<option value="${escHtml(resp.iface || '')}">${escHtml(resp.iface || 'none')}</option>`;
    } else if (resp.iface) {
      ifaceSel.value = resp.iface;
    }
  }
  if (resp.gateway) setVal('strike-gateway', resp.gateway);
  if (resp.subnet) setVal('strike-subnet', resp.subnet);

  const report = resp.last_report || {};
  const sess = resp.session;
  if (sess && sess.running) {
    strike.running = true;
    strike.phase = sess.phase;
    strike.progress = sess.progress;
    strike.hosts = sess.hosts || [];
    strike.findings = sess.top_findings || [];
    strike.msfQueue = sess.msf_queue || [];
    strike.recommended = sess.recommended || null;
    _setStrikeRunning(true);
  } else if (report.hosts && !strike.hosts.length) {
    strike.hosts = report.hosts;
    strike.findings = report.top_findings || [];
    strike.msfQueue = report.msf_queue || [];
    strike.recommended = report.recommended || null;
    strike.msfResults = report.msf_results || [];
    strike.phase = 'done';
  }
  _updateStrikePipeline();
  _setProgress(strike.progress);
  renderStrikeHosts();
  renderStrikeFindings();
  renderStrikeMsf();
  renderStrikeRecommended();
  _refreshStrikeCounts();
}

function setVal(id, v) {
  const el = document.getElementById(id);
  if (el) el.value = v;
}

function _renderStrikeTools() {
  const el = document.getElementById('strike-tool-chips');
  if (!el) return;
  el.innerHTML = [
    ['nmap', 'Nmap'],
    ['nxc', 'NetExec'],
    ['msfconsole', 'Metasploit'],
    ['ncrack', 'Ncrack'],
  ].map(([key, label]) => {
    const ok = strike.tools[key];
    return `<span class="strike-tool-chip ${ok ? 'ok' : 'miss'}">${ok ? '✓' : '○'} ${label}</span>`;
  }).join('');
}

function _setStrikeRunning(on) {
  strike.running = on;
  const start = document.getElementById('btn-strike-start');
  const discover = document.getElementById('btn-strike-discover');
  const selected = document.getElementById('btn-strike-scan-selected');
  const stop = document.getElementById('btn-strike-stop');
  const auto = document.getElementById('btn-strike-autocheck');
  if (start) start.disabled = on;
  if (discover) discover.disabled = on;
  if (selected) selected.disabled = on;
  if (stop) stop.style.display = on ? 'inline-flex' : 'none';
  if (auto) auto.disabled = on;
  const dot = document.getElementById('strike-dot');
  if (dot) dot.classList.toggle('active', on);
  _setStrikeStatus();
}

function _setStrikeStatus() {
  const label = STRIKE_PHASE_LABEL[strike.phase] || strike.phase;
  setText('strike-status-text', strike.running ? label : (label.startsWith('Ready') ? label : `Idle — ${label}`));
}

function _setProgress(pct) {
  const bar = document.getElementById('strike-progress-bar');
  if (bar) bar.style.width = `${Math.min(100, pct)}%`;
}

function _updateStrikePipeline() {
  const phase = (strike.phase || 'idle').toLowerCase();
  STRIKE_PHASES.forEach(name => {
    const step = document.getElementById(`strike-step-${name}`);
    if (!step) return;
    step.classList.remove('active', 'done');
    const order = STRIKE_PHASES.indexOf(name);
    const cur = STRIKE_PHASES.indexOf(phase);
    if (phase === name || (phase === 'starting' && name === 'discover')) {
      step.classList.add('active');
    } else if (cur > order || phase === 'done') {
      step.classList.add('done');
    }
  });
}

function riskClass(score) {
  if (score >= 60) return 'high';
  if (score >= 30) return 'med';
  return 'low';
}

function roleLabel(role) {
  return ({ dc: 'DC', file: 'File', windows: 'Win', linux: 'Linux', web: 'Web', host: 'Host' })[role] || 'Host';
}

function _filteredHosts() {
  const f = strike.filter;
  return strike.hosts.filter(h => {
    if (f === 'high') return (h.risk_score || 0) >= 40;
    if (f === 'windows') return ['dc', 'file', 'windows'].includes(h.role);
    if (f === 'linux') return h.role === 'linux';
    if (f === 'web') return h.role === 'web';
    return true;
  });
}

function _refreshStrikeCounts() {
  setText('strike-host-count', String(strike.hosts.length));
  const highs = strike.findings.filter(f => (f.severity || 0) >= 7).length;
  setText('strike-findings-count', String(highs || strike.findings.length || 0));
  const rec = strike.msfQueue.filter(q => (q.severity || 0) >= 7).length;
  setText('strike-plan-count', String(rec || strike.msfQueue.length || 0));
}

function renderStrikeHosts() {
  const list = document.getElementById('strike-host-list');
  if (!list) return;
  const rows = _filteredHosts();
  if (!strike.hosts.length) {
    list.innerHTML = '<div class="empty-state">Discover LAN to list every connected device</div>';
    return;
  }
  if (!rows.length) {
    list.innerHTML = '<div class="empty-state">No hosts match this filter</div>';
    return;
  }
  list.innerHTML = rows.map(h => {
    const sel = strike.selectedIp === h.ip ? ' selected' : '';
    const rc = riskClass(h.risk_score || 0);
    const ports = (h.ports || []).length;
    return `<div class="strike-host-card${sel}" data-ip="${h.ip}" onclick="selectStrikeHost('${h.ip}')">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
        <span class="mono accent">${escHtml(h.ip)}</span>
        <span class="strike-risk ${rc}">${h.risk_score || 0}</span>
      </div>
      <div class="strike-host-meta">
        <span class="strike-role">${escHtml(roleLabel(h.role))}</span>
        ${escHtml(h.hostname || h.vendor || '—')} · ${ports} ports
      </div>
      ${h.next_action ? `<div class="strike-next-mini">${escHtml(h.next_action)}</div>` : ''}
      <div class="strike-host-actions">
        <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); scanStrikeHosts(['${h.ip}'])">Nmap</button>
        <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); nxcStrikeHost('${h.ip}')">NetExec</button>
      </div>
    </div>`;
  }).join('');
  if (strike.selectedIp) renderStrikeDetail(strike.selectedIp);
}

function setStrikeFilter(f) {
  strike.filter = f;
  document.querySelectorAll('.strike-filter').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === f);
  });
  renderStrikeHosts();
}

function selectStrikeHost(ip) {
  strike.selectedIp = ip;
  renderStrikeHosts();
  renderStrikeDetail(ip);
}

function _msfVerdict(ip, module) {
  const hit = [...(strike.msfResults || [])].reverse().find(
    r => (r.rhosts === ip || r.ip === ip) && r.module === module
  );
  return hit ? (hit.verdict || (hit.likely_vulnerable ? 'vulnerable' : 'done')) : '';
}

function renderStrikeDetail(ip) {
  const host = strike.hosts.find(h => h.ip === ip);
  const el = document.getElementById('strike-host-detail');
  if (!el || !host) return;

  const ports = (host.ports || []).map(p =>
    `<span class="strike-port-chip">${p.port}/${p.proto || 'tcp'} ${escHtml(p.service || '')}${p.banner ? ' — ' + escHtml(p.banner).slice(0, 36) : ''}</span>`
  ).join('');

  const findings = (host.findings || []).filter(f => (f.severity || 0) >= 4).slice(0, 8).map(f => {
    const sev = (f.severity || 0) >= 8 ? 'sev-high' : 'sev-med';
    return `<div class="strike-finding ${sev}"><strong>${escHtml(f.title || 'Finding')}</strong><div class="strike-finding-src">${escHtml(f.source || '')}</div>${escHtml(f.detail || '')}</div>`;
  }).join('') || '<div class="empty-state">No sharp findings yet</div>';

  const msf = (host.msf_modules || []).slice(0, 8).map(m => {
    const verdict = _msfVerdict(host.ip, m.module);
    const star = m.recommended ? ' ★' : '';
    const showExploit = m.can_exploit && (verdict === 'vulnerable' || verdict === 'session' || verdict === 'unknown' || verdict === 'no-check');
    const exploitBtn = m.can_exploit
      ? `<button class="btn btn-sm btn-danger"${showExploit ? '' : ' title="Run Check first"'} onclick="runStrikeMsf('${escHtml(m.module)}','${host.ip}','exploit')">Exploit</button>`
      : '';
    return `<div class="strike-msf-row ${m.recommended ? 'recommended' : ''}">
      <div>
        <strong>${escHtml(m.title)}${star}</strong>
        ${verdict ? `<span class="strike-verdict ${verdict}">${escHtml(verdict)}</span>` : ''}
        <div class="strike-why">${escHtml(m.why || '')}</div>
        <span class="mono strike-mod">${escHtml(m.module)}</span>
      </div>
      <div class="strike-msf-actions">
        <button class="btn btn-sm btn-primary" onclick="runStrikeMsf('${escHtml(m.module)}','${host.ip}','check')">Check</button>
        ${exploitBtn}
      </div>
    </div>`;
  }).join('') || '<p class="form-hint">Nmap this device first — Metasploit suggestions appear from open ports</p>';

  const protos = ['auto', ...(host.ports && host.ports.length
    ? [...new Set((host.ports || []).map(p => {
        const port = Number(p.port);
        if ([139, 445].includes(port)) return 'smb';
        if (port === 22) return 'ssh';
        if ([5985, 5986].includes(port)) return 'winrm';
        if ([88, 389, 636].includes(port)) return 'ldap';
        if (port === 3389) return 'rdp';
        if (port === 21) return 'ftp';
        if (port === 1433) return 'mssql';
        if (port === 135) return 'wmi';
        if (port === 2049) return 'nfs';
        if (port === 5900) return 'vnc';
        if ([80, 443, 8080, 8443].includes(port)) return 'http';
        return '';
      }).filter(Boolean))]
    : strike.nxcProtocols)];
  const protoOpts = protos.map(p => `<option value="${p === 'auto' ? '' : p}">${p}</option>`).join('');
  const profileOpts = Object.entries(strike.nxcProfiles || {
    probe: { label: 'Identify' }, enum: { label: 'Enumerate' }, vuln: { label: 'Vuln modules' },
  }).map(([key, meta]) => `<option value="${key}"${key === 'enum' ? ' selected' : ''}>${escHtml(meta.label || key)}</option>`).join('');

  el.innerHTML = `
    <div class="strike-next-card">
      <div class="strike-next-label">Do this next</div>
      <div>${escHtml(host.next_action || 'Nmap this device')}</div>
    </div>
    <h3 class="mono accent" style="margin:12px 0 6px">${escHtml(host.ip)} ${host.hostname ? '· ' + escHtml(host.hostname) : ''}</h3>
    <p class="form-hint">
      ${escHtml(roleLabel(host.role))} · ${escHtml(host.os_guess || host.vendor || 'unknown OS')} · risk ${host.risk_score || 0}/100
    </p>
    <div class="strike-host-toolbar">
      <button class="btn btn-sm btn-primary" onclick="scanStrikeHosts(['${host.ip}'])">Nmap this device</button>
      <label class="toggle-label"><input type="checkbox" id="strike-host-nxc-after"/> <span>then NetExec</span></label>
      <button class="btn btn-sm btn-ghost" onclick="autoCheckStrike('${host.ip}')">Check this host</button>
    </div>
    <div class="strike-nxc-bar">
      <select id="strike-nxc-proto" class="select-styled">${protoOpts}</select>
      <select id="strike-nxc-profile" class="select-styled">${profileOpts}</select>
      <button class="btn btn-sm btn-primary" onclick="nxcStrikeHost('${host.ip}')">Run NetExec</button>
    </div>
    <div style="margin:10px 0">${ports || '<span class="form-hint">No open ports yet — run Nmap on this device</span>'}</div>
    <h4 style="margin:12px 0 6px">Key findings</h4>
    ${findings}
    <h4 style="margin:12px 0 6px">Metasploit for this host</h4>
    ${msf}
  `;
}

function renderStrikeFindings() {
  const el = document.getElementById('strike-findings-list');
  if (!el) return;
  const rows = (strike.findings || []).filter(f => (f.severity || 0) >= 4);
  if (!rows.length) {
    el.innerHTML = '<div class="empty-state">Key vulns appear after Nmap / NetExec</div>';
    return;
  }
  el.innerHTML = rows.slice(0, 16).map(f => {
    const sev = (f.severity || 0) >= 8 ? 'sev-high' : 'sev-med';
    const ip = f.ip || '';
    return `<div class="strike-finding ${sev}" ${ip ? `onclick="selectStrikeHost('${escHtml(ip)}')" style="cursor:pointer"` : ''}>
      <span class="mono accent">${escHtml(ip)}</span>
      ${escHtml(f.title || f.detail || '').slice(0, 160)}
    </div>`;
  }).join('');
}

function renderStrikeMsf() {
  const el = document.getElementById('strike-msf-queue');
  if (!el) return;
  if (!strike.msfQueue.length) {
    el.innerHTML = '<div class="empty-state">Queue fills after Analyze</div>';
    return;
  }
  el.innerHTML = strike.msfQueue.slice(0, 10).map(q => {
    const verdict = _msfVerdict(q.ip, q.module);
    return `<div class="strike-msf-row ${q.recommended ? 'recommended' : ''}">
      <div>
        <span class="mono accent">${escHtml(q.ip)}</span> — ${escHtml(q.title)}
        ${verdict ? `<span class="strike-verdict ${verdict}">${escHtml(verdict)}</span>` : ''}
        <div class="strike-why">${escHtml(q.why || '')}</div>
      </div>
      <div class="strike-msf-actions">
        <button class="btn btn-sm btn-primary" onclick="runStrikeMsf('${escHtml(q.module)}','${escHtml(q.ip)}','check')">Check</button>
      </div>
    </div>`;
  }).join('');
}

function renderStrikeRecommended() {
  const el = document.getElementById('strike-recommended');
  if (!el) return;
  const rec = strike.recommended;
  if (!rec || !rec.ip) {
    el.style.display = 'none';
    el.innerHTML = '';
    return;
  }
  el.style.display = 'flex';
  el.innerHTML = `
    <div>
      <div class="strike-next-label">Best next check</div>
      <strong>${escHtml(rec.title)}</strong> on <span class="mono accent">${escHtml(rec.ip)}</span>
      <div class="strike-why">${escHtml(rec.why || '')}</div>
    </div>
    <button class="btn btn-primary" onclick="runStrikeMsf('${escHtml(rec.module)}','${escHtml(rec.ip)}','check')">Check now</button>
  `;
}

function _showMsfOutput(result) {
  const el = document.getElementById('strike-msf-output');
  if (!el) return;
  const head = `${result.action || 'check'} ${result.module || ''} → ${result.rhosts || result.ip || ''} [${result.verdict || result.error || 'done'}]\n`;
  el.textContent = (head + (result.log || result.error || '')).slice(-4000);
}

function escHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function toggleStrikeAdvanced() {
  const box = document.getElementById('strike-advanced');
  if (!box) return;
  box.style.display = box.style.display === 'none' ? 'flex' : 'none';
}

function pickStrikePreset(name) {
  const input = document.getElementById('strike-preset');
  if (input) input.value = name;
  document.querySelectorAll('.strike-preset-card').forEach(card => {
    card.classList.toggle('active', card.dataset.preset === name);
  });
}

function _strikeLan() {
  return {
    iface: document.getElementById('strike-iface')?.value || '',
    gateway: document.getElementById('strike-gateway')?.value || '',
    subnet: document.getElementById('strike-subnet')?.value || '',
  };
}

function _resetStrikeView(keepHosts) {
  if (!keepHosts) {
    strike.hosts = [];
    strike.selectedIp = null;
  }
  strike.findings = keepHosts ? strike.findings : [];
  strike.msfQueue = keepHosts ? strike.msfQueue : [];
  if (!keepHosts) {
    strike.msfResults = [];
    strike.recommended = null;
  }
  strike.phase = 'starting';
  renderStrikeHosts();
  renderStrikeFindings();
  renderStrikeMsf();
  renderStrikeRecommended();
  _refreshStrikeCounts();
  _setStrikeRunning(true);
}

async function discoverStrikeLan() {
  if (!confirm('Authorized lab only. Discover every live host on this subnet?')) return;
  const resp = await api('/api/strike/start', 'POST', {
    ..._strikeLan(),
    preset: 'discover',
    stop_after: 'discover',
    authorized: true,
  });
  if (!resp || !resp.ok) return;
  _resetStrikeView(false);
  toast('Discovering connected devices…', 'info');
}

async function startStrikeChain() {
  if (!confirm('Authorized lab only. Discover the LAN and nmap + NetExec every live host?')) return;
  const preset = document.getElementById('strike-preset')?.value || 'smart';
  const resp = await api('/api/strike/start', 'POST', {
    ..._strikeLan(),
    preset,
    authorized: true,
  });
  if (!resp || !resp.ok) return;
  _resetStrikeView(false);
  toast('Full Strike chain started', 'info');
}

async function scanStrikeHosts(ips, runNxc) {
  const targets = (ips || []).filter(Boolean);
  if (!targets.length) return toast('Select a host first', 'warn');
  const after = runNxc ?? document.getElementById('strike-host-nxc-after')?.checked;
  const resp = await api('/api/strike/scan-host', 'POST', {
    ..._strikeLan(),
    ips: targets,
    preset: document.getElementById('strike-preset')?.value || 'smart',
    run_nxc: Boolean(after),
    authorized: true,
  });
  if (!resp || !resp.ok) return;
  _resetStrikeView(true);
  toast(`Nmap ${targets.length} host(s)…`, 'info');
}

async function scanSelectedStrikeHosts() {
  if (strike.selectedIp) return scanStrikeHosts([strike.selectedIp]);
  const unscanned = strike.hosts.filter(h => !(h.ports || []).length).map(h => h.ip);
  if (!unscanned.length) return toast('Select a host, or discover first', 'warn');
  if (!confirm(`Nmap ${unscanned.length} host(s) that have no port scan yet?`)) return;
  return scanStrikeHosts(unscanned);
}

async function nxcStrikeHost(ip) {
  const target = ip || strike.selectedIp;
  if (!target) return toast('Select a host first', 'warn');
  const resp = await api('/api/strike/nxc', 'POST', {
    ..._strikeLan(),
    ip: target,
    protocol: document.getElementById('strike-nxc-proto')?.value || '',
    profile: document.getElementById('strike-nxc-profile')?.value || 'enum',
    authorized: true,
  });
  if (!resp || !resp.ok) return;
  _resetStrikeView(true);
  toast(`NetExec on ${target}…`, 'info');
}

async function stopStrikeChain() {
  await api('/api/strike/stop', 'POST', {});
  toast('Stopping Strike…', 'warn');
}

async function runStrikeMsf(module, ip, action) {
  if (action === 'exploit') {
    if (!confirm(`Authorized exploit only.\n\n${module}\n→ ${ip}\n\nContinue?`)) return;
  }
  const body = {
    module,
    rhosts: ip,
    ip,
    action,
    authorized: action === 'exploit',
    iface: document.getElementById('strike-iface')?.value || '',
  };
  const resp = await api('/api/strike/msf', 'POST', body);
  if (resp?.ok) toast(`Metasploit ${action} running…`, 'info');
}

async function autoCheckStrike(ip) {
  const target = typeof ip === 'string' ? ip : '';
  const msg = target
    ? `Run Metasploit CHECKS only on ${target}?`
    : 'Run the top Metasploit CHECKS only (no exploit) on this lab?';
  if (!confirm(msg)) return;
  const resp = await api('/api/strike/msf/auto-check', 'POST', {
    authorized: true,
    ip: target,
    ..._strikeLan(),
  });
  if (resp?.ok) toast(target ? `Checking ${target}…` : 'Auto-check started — Check only', 'info');
}
