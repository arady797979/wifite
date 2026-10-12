/** Snake Gemini Agent chat UI */

async function loadAgentStatus() {
  const el = document.getElementById('agent-status-line');
  const resp = typeof api === 'function' ? await api('/api/agent/status') : null;
  if (!resp || !el) return;
  if (resp.ok) {
    el.textContent = `Ready — ${resp.tool_count} tools · model ${resp.model}`;
    el.style.color = 'var(--accent-green)';
  } else if (resp.google_genai_installed && !resp.gemini_api_key_set) {
    el.textContent = 'Set GEMINI_API_KEY in the environment to enable the agent.';
    el.style.color = 'var(--accent-yellow)';
  } else if (!resp.google_genai_installed) {
    el.textContent = 'Install google-genai: pip install google-genai';
    el.style.color = 'var(--accent-yellow)';
  } else {
    el.textContent = 'Agent not configured.';
    el.style.color = 'var(--text-muted)';
  }
}

async function sendToAgent() {
  const inputField = document.getElementById('agent-input');
  const message = inputField?.value?.trim();
  if (!message) return;

  inputField.value = '';
  appendAgentMessage(message, 'user');
  appendAgentMessage('…', 'typing');

  try {
    const resp = typeof api === 'function'
      ? await api('/api/agent/chat', 'POST', { message, session_id: 'default' })
      : null;

    _removeAgentTyping();

    if (!resp) {
      appendAgentMessage('API unavailable', 'error');
      return;
    }
    if (resp.error || !resp.ok) {
      appendAgentMessage(`Error: ${resp.error || 'request failed'}`, 'error');
      return;
    }
    appendAgentMessage(resp.response || '(empty)', 'agent');
  } catch (err) {
    _removeAgentTyping();
    appendAgentMessage(`Connection error: ${err.message}`, 'error');
  }
}

function _removeAgentTyping() {
  document.querySelectorAll('.agent-typing').forEach(n => n.remove());
}

function appendAgentMessage(text, sender) {
  const history = document.getElementById('agent-chat-history');
  if (!history) return;

  const msgDiv = document.createElement('div');
  msgDiv.style.padding = '10px';
  msgDiv.style.borderRadius = '8px';
  msgDiv.style.maxWidth = '80%';
  msgDiv.style.marginBottom = '10px';
  msgDiv.style.whiteSpace = 'pre-wrap';

  if (sender === 'user') {
    msgDiv.style.alignSelf = 'flex-end';
    msgDiv.style.background = '#2a4d69';
    msgDiv.style.borderRight = '3px solid var(--accent-cyan)';
  } else if (sender === 'error') {
    msgDiv.style.alignSelf = 'flex-start';
    msgDiv.style.background = '#4a1a1a';
    msgDiv.style.borderLeft = '3px solid #ff4444';
  } else if (sender === 'typing') {
    msgDiv.className = 'agent-typing';
    msgDiv.style.alignSelf = 'flex-start';
    msgDiv.style.background = '#2d2d2d';
    msgDiv.style.borderLeft = '3px solid var(--text-muted)';
    msgDiv.style.fontStyle = 'italic';
    msgDiv.style.color = 'var(--text-muted)';
  } else {
    msgDiv.style.alignSelf = 'flex-start';
    msgDiv.style.background = '#2d2d2d';
    msgDiv.style.borderLeft = '3px solid var(--accent-cyan)';
  }

  msgDiv.textContent = text;
  history.appendChild(msgDiv);
  history.scrollTop = history.scrollHeight;
}

async function clearAgentChat() {
  await api('/api/agent/reset', 'POST', { session_id: 'default' });
  const history = document.getElementById('agent-chat-history');
  if (!history) return;
  history.innerHTML = `
    <div class="agent-msg sys-msg" style="align-self:flex-start;background:#2d2d2d;padding:10px;border-radius:8px;border-left:3px solid var(--accent-cyan);max-width:80%;">
      Chat reset. Ask me to check status, scan, plan an attack, or run Strike/MITM/Twin — authorized lab only.
    </div>`;
}

document.addEventListener('DOMContentLoaded', () => {
  loadAgentStatus();
});
