/**
 * Snake Evil Twin — three-step setup and live portal status
 */

const twin = {
  active: false,
  session_id: null,
  readiness: {},
  clients: [],
  creds: [],
  statsTimer: null,
};

document.addEventListener('DOMContentLoaded', () => {
  const poll = setInterval(() => {
    if (typeof socket !== 'undefined') {
      clearInterval(poll);
      socket.on('twin_status', (data) => applyTwinStatus(data));
      socket.on('twin_cred', (cred) => {
        twin.creds.push(cred);
        renderTwinCreds();
        updateTwinStats(twin.lastSnapshot || {});
        toast('Twin captured a portal submission', 'warn', 6000);
        const badge = document.getElementById('nav-badge-twin');
        if (badge) {
          badge.textContent = String(twin.creds.length);
          badge.style.background = 'rgba(255,193,7,0.3)';
          badge.style.color = '#ffc107';
        }
      });
      socket.on('twin_clients', (data) => {
        twin.clients = data.clients || [];
        renderTwinClients();
        setText('ts-clients', String(twin.clients.length));
      });
      socket.on('twin_log', (entry) => {
        if (typeof appendLog === 'function') appendLog(entry);
      });
    }
  }, 200);
  loadTwinStatus();
  document.getElementById('twin-channel')?.addEventListener('change', loadTwinStatus);
  document.getElementById('twin-ap-iface')?.addEventListener('change', loadTwinStatus);
  document.getElementById('twin-creds')?.addEventListener('click', (event) => {
    const button = event.target.closest('.reveal-secret');
    if (!button) return;
    const secret = button.previousElementSibling;
    secret?.classList.toggle('revealed');
    button.textContent = secret?.classList.contains('revealed') ? 'Hide' : 'Reveal';
  });
});

function applyTwinTarget(network) {
  if (!network) return;
  const bssid = document.getElementById('twin-bssid');
  const essid = document.getElementById('twin-essid');
  const channel = document.getElementById('twin-channel');
  if (bssid) bssid.value = network.bssid || '';
  if (essid) essid.value = network.essid || '';
  if (channel && network.channel) channel.value = String(network.channel);
  markTwinStep(document.getElementById('twin-ap-iface')?.value ? 2 : 1);
  loadTwinStatus();
}

function useNetworkAsTwin(index) {
  const network = state.networks[index];
  if (!network?.bssid && !network?.essid) {
    return toast('This row has no target yet', 'warn');
  }
  state.selectedNetwork = network;
  if (typeof applyTargetToAttackForm === 'function') applyTargetToAttackForm(network);
  applyTwinTarget(network);
  switchTab('twin');
  toast(`Twin target: ${network.essid || network.bssid}`, 'info', 2500);
}

async function loadTwinStatus() {
  const channel = document.getElementById('twin-channel')?.value || '';
  const ap = document.getElementById('twin-ap-iface')?.value || '';
  const qs = new URLSearchParams();
  if (channel) qs.set('channel', channel);
  if (ap) qs.set('ap_iface', ap);
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  const resp = await api(`/api/twin/status${suffix}`);
  if (!resp) return;
  twin.readiness = resp.readiness || {};
  applyTwinReadiness(twin.readiness);
  if (resp.session && resp.session.running) {
    applyTwinStatus(resp.session);
  } else if (!resp.active) {
    setTwinBanner(false, 'Twin inactive — pick a target and launch');
  }
}

function applyTwinReadiness(ready) {
  const ap = document.getElementById('twin-ap-iface');
  const deauth = document.getElementById('twin-deauth-iface');
  if (ap && !ap.value) ap.value = ready.ap_iface || '';
  if (deauth && !deauth.value) deauth.value = ready.deauth_iface || '';
  fillIfaceSelect('twin-ap-iface', ready.ap_choices || ready.managed || ready.monitor || [], ready.ap_iface);
  fillIfaceSelect('twin-deauth-iface', ready.monitor || [], ready.deauth_iface);
  const chips = document.getElementById('twin-chips');
  if (chips) {
    const items = [
      ['root', ready.root],
      ['hostapd', ready.hostapd],
      ['dnsmasq', ready.dnsmasq],
      ['AP radio', Boolean(ready.ap_iface)],
      ['AP TX', Boolean(ready.ap_plan?.supports_ap !== false && (ready.ap_plan?.channel || ready.ap_iface))],
      ['deauth RF', ready.deauth_ready],
    ];
    chips.innerHTML = items.map(([label, ok]) =>
      `<span class="twin-chip ${ok ? 'ok' : 'miss'}">${label}</span>`
    ).join('');
  }
  const warn = document.getElementById('twin-radio-warn');
  if (warn) {
    const notes = [];
    if (ready.will_switch_to_managed && ready.ap_iface) {
      notes.push(`${ready.ap_iface} is in ${ready.ap_mode || 'monitor'} mode and will be switched to managed for hostapd.`);
    }
    if (ready.single_radio) {
      notes.push('One radio: hostapd takes the managed iface (wlan0 after wlan0mon). NetworkManager is held off that radio. Live deauth stays off so the AP does not flap.');
    }
    const plan = ready.ap_plan || {};
    if (plan.note) notes.push(plan.note);
    if (plan.channel && plan.requested && Number(plan.channel) !== Number(plan.requested)) {
      notes.push(`Launch will AP on channel ${plan.channel} (target is ${plan.requested}).`);
    }
    warn.style.display = notes.length ? 'block' : 'none';
    warn.textContent = notes.join(' ');
  }
  const hint = document.getElementById('twin-channel-hint');
  if (hint) {
    const plan = ready.ap_plan || {};
    if (plan.channel && plan.requested && Number(plan.channel) !== Number(plan.requested)) {
      hint.textContent = `→ AP ch${plan.channel}`;
    } else if (plan.channel) {
      hint.textContent = 'TX-ok';
    } else {
      hint.textContent = '';
    }
  }
  markTwinStep(ready.ap_iface ? 2 : 1);
}

function fillIfaceSelect(id, names, selected) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = el.value || selected || '';
  const options = names.length ? names : (current ? [current] : []);
  el.innerHTML = `<option value="">—</option>` + options.map(name =>
    `<option value="${esc(name)}"${name === current ? ' selected' : ''}>${esc(name)}</option>`
  ).join('');
  if (current) el.value = current;
}

function markTwinStep(step) {
  document.querySelectorAll('.twin-step').forEach((el, index) => {
    el.classList.toggle('active', index + 1 === step);
    el.classList.toggle('done', index + 1 < step);
  });
}

function applyTwinStatus(snap) {
  snap = snap || {};
  twin.lastSnapshot = snap;
  twin.active = !!snap.running;
  twin.session_id = snap.session_id || null;
  twin.clients = snap.clients || twin.clients;
  twin.creds = snap.creds || twin.creds;
  setTwinBanner(twin.active, twin.active
    ? `Twin live — ${snap.essid || 'portal'} on ${snap.ap_iface || '?'}`
    : (snap.error || 'Twin inactive — pick a target and launch'));
  updateTwinStats(snap);
  renderTwinClients();
  renderTwinCreds();
  markTwinStep(twin.active ? 3 : 2);
  const ap = document.getElementById('twin-ap-iface');
  if (ap && snap.ap_iface) {
    const exists = [...ap.options].some((option) => option.value === snap.ap_iface);
    if (!exists) ap.add(new Option(snap.ap_iface, snap.ap_iface));
    ap.value = snap.ap_iface;
  }
  const badge = document.getElementById('nav-badge-twin');
  if (badge) badge.textContent = twin.active ? 'ON' : 'OFF';
  if (twin.active && !twin.statsTimer) {
    twin.statsTimer = setInterval(loadTwinStatus, 4000);
  }
  if (!twin.active && twin.statsTimer) {
    clearInterval(twin.statsTimer);
    twin.statsTimer = null;
  }
}

function setTwinBanner(active, text) {
  setText('twin-status-text', text);
  document.getElementById('twin-dot')?.classList.toggle('active', active);
  const stop = document.getElementById('btn-twin-stop');
  const start = document.getElementById('btn-twin-start');
  if (stop) stop.style.display = active ? '' : 'none';
  if (start) start.toggleAttribute('disabled', active);
  document.getElementById('twin-banner')?.classList.toggle('active', active);
}

function updateTwinStats(snap) {
  setText('ts-clients', String((snap.client_count != null ? snap.client_count : twin.clients.length)));
  setText('ts-creds', String((snap.cred_count != null ? snap.cred_count : twin.creds.length)));
  setText('ts-hits', String(snap.portal_hits || 0));
  setText('ts-deauth', snap.deauth_enabled ? 'ON' : 'OFF');
  const uptime = snap.uptime || 0;
  const m = String(Math.floor(uptime / 60)).padStart(2, '0');
  const s = String(uptime % 60).padStart(2, '0');
  setText('ts-uptime', `${m}:${s}`);
}

function renderTwinClients() {
  const list = document.getElementById('twin-clients');
  if (!list) return;
  if (!twin.clients.length) {
    list.innerHTML = '<div class="empty-state">Waiting for clients to join the twin…</div>';
    return;
  }
  list.innerHTML = twin.clients.map(client => `
    <div class="twin-client">
      <span>${esc(client.mac || '?')}</span>
      <span>${client.signal ? `${client.signal} dBm` : ''}</span>
    </div>
  `).join('');
}

function renderTwinCreds() {
  const list = document.getElementById('twin-creds');
  if (!list) return;
  setText('twin-cred-count', `${twin.creds.length} captured`);
  if (!twin.creds.length) {
    list.innerHTML = '<div class="empty-state">No portal submissions yet</div>';
    return;
  }
  list.innerHTML = twin.creds.slice().reverse().map(cred => {
    const tag = cred.verified ? 'verified' : (cred.pending ? 'unverified' : 'rejected');
    return `<div class="twin-cred">
      <div>
        <span class="secret-value">${esc(cred.password || '—')}</span>
        <button class="btn btn-sm btn-ghost reveal-secret">Reveal</button>
      </div>
      <span>${esc(tag)} · ${esc(cred.client_ip || '')}</span>
    </div>`;
  }).join('');
}

async function startTwin() {
  const payload = {
    essid: document.getElementById('twin-essid')?.value?.trim() || '',
    bssid: document.getElementById('twin-bssid')?.value?.trim() || '',
    channel: parseInt(document.getElementById('twin-channel')?.value || '6', 10),
    ap_iface: document.getElementById('twin-ap-iface')?.value || '',
    deauth_iface: document.getElementById('twin-deauth-iface')?.value || '',
    stealth: !!document.getElementById('twin-stealth')?.checked,
    rotate_mac: !!document.getElementById('twin-rotate-mac')?.checked,
    authorized: true,
  };
  if (!payload.essid && !payload.bssid) {
    return toast('Select a network in Scanner, then open Twin', 'warn');
  }
  if (!confirm('Only continue if you are authorized to host this lab Twin. Start now?')) return;
  const resp = await api('/api/twin/start', 'POST', payload);
  if (resp?.ok) {
    twin.active = true;
    twin.session_id = resp.session_id;
    setTwinBanner(true, 'Twin starting…');
    toast('Evil Twin launching', 'success');
    if (resp.single_radio) toast('Single radio: AP only, no live deauth', 'warn', 5000);
    if (resp.readiness?.ap_plan?.channel && resp.readiness.ap_plan.channel !== payload.channel) {
      toast(`AP channel ${resp.readiness.ap_plan.channel} (target ${payload.channel} is not TX-ok)`, 'warn', 6000);
    }
  }
}

async function stopTwin() {
  const resp = await api('/api/twin/stop', 'POST', {});
  if (resp?.ok) {
    twin.active = false;
    applyTwinStatus({ running: false });
    toast('Twin stopped', 'warn');
  }
}
