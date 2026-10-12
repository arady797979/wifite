/**
 * Snake Arsenal — social playbooks, apt bundles, ncrack helpers
 */

async function loadArsenal() {
  const resp = await api('/api/arsenal/catalog');
  if (!resp?.ok) return;
  renderArsenalBundles(resp.bundles || []);
  renderArsenalPlaybooks(resp.playbooks || []);
}

function renderArsenalBundles(bundles) {
  const el = document.getElementById('arsenal-bundles');
  if (!el) return;
  if (!bundles.length) {
    el.innerHTML = '<div class="empty-state">No bundles defined</div>';
    return;
  }
  el.innerHTML = bundles.map(b => `
    <div class="arsenal-bundle-card">
      <strong>${esc(b.label)}</strong>
      <p class="form-hint">${esc(b.hint || '')}</p>
      <code class="mono arsenal-cmd">${esc(b.install)}</code>
      <button class="btn btn-sm btn-ghost" onclick="copyArsenalCmd(this)">Copy install</button>
    </div>
  `).join('');
}

function renderArsenalPlaybooks(books) {
  const el = document.getElementById('arsenal-playbooks');
  if (!el) return;
  if (!books.length) {
    el.innerHTML = '<div class="empty-state">No playbooks</div>';
    return;
  }
  const sel = state.selectedNetwork || {};
  el.innerHTML = books.map(b => {
    const miss = (b.missing || []).length
      ? `<span class="form-hint">Missing: ${esc(b.missing.join(', '))}</span>` : '';
    const ready = b.ready ? 'ok' : 'miss';
    const actions = b.builtin && b.tab
      ? `<button class="btn btn-sm btn-primary" onclick="switchTab('${esc(b.tab)}')">Open ${esc(b.tab)}</button>`
      : `<button class="btn btn-sm btn-primary" onclick="preparePlaybook('${esc(b.id)}')">Prepare command</button>`;
    return `<div class="arsenal-playbook ${ready}">
      <div class="arsenal-playbook-head">
        <span>${esc(b.title)}</span>
        <span class="badge">${esc(b.category || 'lab')}</span>
      </div>
      <p class="form-hint">${esc(b.summary || '')}</p>
      ${miss}
      <div class="form-actions">${actions}</div>
      <pre class="arsenal-cmd-out mono" id="pb-cmd-${esc(b.id)}" style="display:none"></pre>
    </div>`;
  }).join('');
}

function copyArsenalCmd(btn) {
  const code = btn?.previousElementSibling;
  if (!code) return;
  navigator.clipboard.writeText(code.textContent || '').then(() => {
    toast('Install command copied', 'success');
  }).catch(() => toast('Copy failed', 'error'));
}

async function preparePlaybook(playbookId) {
  const sel = state.selectedNetwork || {};
  const resp = await api('/api/arsenal/command', 'POST', {
    playbook: playbookId,
    essid: sel.essid || document.getElementById('twin-essid')?.value || '',
    bssid: sel.bssid || document.getElementById('twin-bssid')?.value || '',
    channel: sel.channel || parseInt(document.getElementById('twin-channel')?.value, 10) || 6,
    ap_iface: document.getElementById('iface-select')?.value || 'wlan0',
    lan_iface: document.getElementById('mitm-iface')?.value || 'eth0',
  });
  if (!resp?.ok) return toast(resp?.error || 'Prepare failed', 'error');
  const out = document.getElementById(`pb-cmd-${playbookId}`);
  if (out) {
    out.style.display = 'block';
    out.textContent = resp.command;
  }
  try {
    await navigator.clipboard.writeText(resp.command);
    toast('Command copied — run in a root terminal', 'success', 8000);
  } catch {
    toast('Command ready below (copy manually)', 'info');
  }
  appendLog({ level: 'INFO', msg: `[Arsenal] ${playbookId}:\n${resp.command}` });
}

async function runArsenalNcrack(useAll) {
  if (!confirm('Confirm authorization to run ncrack login audit on LAN hosts.')) return;
  const resp = await api('/api/arsenal/ncrack', 'POST', {
    authorized: true,
    use_strike_hosts: useAll,
  });
  if (resp?.ok) toast(`ncrack started on ${(resp.targets || []).length} host(s)`, 'warn');
  else toast(resp?.error || 'ncrack failed', 'error');
}

async function runStrikeNcrack() {
  const ip = strike.selectedIp;
  if (!ip && !strike.hosts.length) {
    return toast('Discover LAN in Strike first', 'warn');
  }
  if (!confirm('Confirm authorization to run ncrack on selected / discovered hosts.')) return;
  const ips = ip ? [ip] : strike.hosts.slice(0, 8).map(h => h.ip).filter(Boolean);
  const resp = await api('/api/strike/ncrack', 'POST', { authorized: true, ips });
  if (resp?.ok) toast(`ncrack → ${ips.join(', ')}`, 'warn');
  else toast(resp?.error || 'ncrack failed', 'error');
}

document.addEventListener('DOMContentLoaded', () => {
  if (typeof socket !== 'undefined') {
    socket.on('arsenal_ncrack_done', (data) => {
      if (data.creds?.length) toast(`ncrack: ${data.creds.length} credential hint(s)`, 'success', 10000);
    });
    socket.on('strike_ncrack_done', (data) => {
      if (data.creds?.length) toast(`Strike ncrack: ${data.creds.length} hit(s)`, 'success', 10000);
    });
  }
});
