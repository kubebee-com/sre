// Kubebee SRE Agent Frontend Application

let currentTab = 'approvals';
let activeIssues = [];
let cleanablePods = [];

document.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  loadProposals();
  loadIssues();
  loadAnalyzers();
  loadCleanablePods();
  loadConfig();
  setInterval(refreshActiveTab, 15000);
});

function switchTab(tab) {
  currentTab = tab;
  ['approvals', 'anomalies', 'analyzers', 'hygiene', 'chat', 'settings'].forEach(t => {
    const el = document.getElementById(`section-${t}`);
    const tabBtn = document.getElementById(`tab-${t}`);
    if (t === tab) {
      if (el) el.classList.remove('hidden');
      if (tabBtn) tabBtn.classList.add('active');
    } else {
      if (el) el.classList.add('hidden');
      if (tabBtn) tabBtn.classList.remove('active');
    }
  });

  refreshActiveTab();
}

function refreshActiveTab() {
  loadStatus();
  if (currentTab === 'approvals') loadProposals();
  if (currentTab === 'anomalies') loadIssues();
  if (currentTab === 'analyzers') loadAnalyzers();
  if (currentTab === 'hygiene') loadCleanablePods();
}

async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('stat-issues').textContent = data.active_issues_count;
    document.getElementById('stat-pending').textContent = data.pending_proposals_count;
    document.getElementById('stat-completed').textContent = data.completed_proposals_count;
    document.getElementById('llm-provider-label').textContent = data.llm_provider;

    const pendingBadge = document.getElementById('tab-badge-pending');
    if (data.pending_proposals_count > 0) {
      pendingBadge.textContent = data.pending_proposals_count;
      pendingBadge.classList.remove('hidden');
    } else {
      pendingBadge.classList.add('hidden');
    }
  } catch (err) {
    console.error('Failed to load status:', err);
  }
}

async function loadProposals() {
  try {
    const res = await fetch('/api/proposals');
    const proposals = await res.json();
    const container = document.getElementById('proposals-container');

    const pending = proposals.filter(p => p.status === 'PENDING_APPROVAL');

    if (pending.length === 0) {
      container.innerHTML = `
        <div class="card p-8 text-center space-y-2">
          <div class="w-10 h-10 rounded-full bg-emerald-500/20 text-emerald-400 mx-auto flex items-center justify-center">
            <i class="fa-solid fa-check text-lg"></i>
          </div>
          <div class="text-sm font-semibold text-white">All Clear! No Pending Approvals</div>
          <div class="text-xs text-gray-400">Cluster telemetry is stable or all remediation proposals have been reviewed.</div>
        </div>
      `;
      return;
    }

    container.innerHTML = pending.map(p => `
      <div class="card p-5 space-y-4 border-l-4 border-l-amber-500" id="proposal-${p.id}">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="text-xs px-2 py-0.5 rounded font-mono ${getSeverityBadge(p.diagnosis.severity)}">${p.diagnosis.severity}</span>
            <span class="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">${p.kind}</span>
            <span class="text-sm font-bold text-white">${p.namespace}/${p.name}</span>
          </div>
          <div class="text-xs text-gray-400">Proposed by <span class="text-gray-200">${p.diagnosis.provider_name}</span></div>
        </div>

        <div class="space-y-1">
          <div class="text-sm font-semibold text-gray-200">${escapeHtml(p.diagnosis.summary)}</div>
          <div class="text-xs text-gray-400 leading-relaxed">${escapeHtml(p.diagnosis.root_cause)}</div>
        </div>

        <div class="p-3 bg-[#0d1117] rounded-md border border-[#30363d] space-y-2">
          <div class="flex items-center justify-between text-xs">
            <span class="text-gray-400 font-semibold">Action Plan (${p.diagnosis.action_type}):</span>
            <span class="text-gray-500">Confidence: ${(p.diagnosis.confidence_score * 100).toFixed(0)}%</span>
          </div>
          <div class="text-xs text-emerald-400 font-mono bg-black/40 p-2 rounded">${escapeHtml(p.diagnosis.proposed_command)}</div>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-[#30363d]">
          <span class="text-xs text-amber-400 flex items-center gap-1.5">
            <i class="fa-solid fa-lock"></i>
            <span>Permission Required</span>
          </span>
          <div class="flex items-center gap-2">
            <button onclick="rejectProposal('${p.id}')" class="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-semibold transition">
              Reject
            </button>
            <button onclick="approveProposal('${p.id}')" class="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition">
              <i class="fa-solid fa-play"></i>
              <span>Approve & Execute</span>
            </button>
          </div>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load proposals:', err);
  }
}

async function approveProposal(id) {
  if (!confirm(`Are you sure you want to authorize and execute proposal ${id}?`)) return;

  try {
    const res = await fetch(`/api/proposals/${id}/approve`, { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      alert(`Remediation proposal approved and queued for execution!`);
      loadProposals();
      loadStatus();
    } else {
      alert(`Approval error: ${data.error}`);
    }
  } catch (err) {
    alert(`Request failed: ${err.message}`);
  }
}

async function rejectProposal(id) {
  const reason = prompt('Please specify a rejection reason:', 'False positive / manual fix preferred');
  if (!reason) return;

  try {
    const res = await fetch(`/api/proposals/${id}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason })
    });
    if (res.ok) {
      loadProposals();
      loadStatus();
    }
  } catch (err) {
    alert(`Request failed: ${err.message}`);
  }
}

async function loadIssues() {
  try {
    const res = await fetch('/api/issues');
    activeIssues = await res.json();
    applyAnomalyFilters();
  } catch (err) {
    console.error('Failed to load issues:', err);
  }
}

function applyAnomalyFilters() {
  const search = document.getElementById('filter-search')?.value.toLowerCase() || '';
  const severity = document.getElementById('filter-severity')?.value || '';

  const filtered = activeIssues.filter(i => {
    const matchesSearch = !search || i.name.toLowerCase().includes(search) || i.namespace.toLowerCase().includes(search);
    const matchesSeverity = !severity || i.severity === severity;
    return matchesSearch && matchesSeverity;
  });

  const container = document.getElementById('issues-container');
  if (filtered.length === 0) {
    container.innerHTML = `<div class="card p-6 text-center text-gray-500 text-sm">No anomalies matching current filter.</div>`;
    return;
  }

  container.innerHTML = filtered.map(i => `
    <div class="card p-4 space-y-2">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <span class="text-xs px-2 py-0.5 rounded font-mono ${getSeverityBadge(i.severity)}">${i.severity}</span>
          <span class="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">${i.kind}</span>
          <span class="text-xs font-bold text-white">${i.namespace ? i.namespace + '/' : ''}${i.name}</span>
          <span class="text-xs text-gray-400 font-mono">(${i.category})</span>
        </div>
        <div class="flex items-center gap-2">
          ${i.logs_snippet ? `<button onclick="showLogsModal('${escapeHtml(i.name)}', '${escapeHtml(i.logs_snippet)}')" class="px-2 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs"><i class="fa-solid fa-file-lines mr-1"></i>Logs</button>` : ''}
          <button onclick="askAIAboutIssue('${i.id}')" class="px-2 py-1 bg-blue-600/30 hover:bg-blue-600/50 text-blue-400 border border-blue-500/50 rounded text-xs"><i class="fa-solid fa-robot mr-1"></i>Ask AI</button>
        </div>
      </div>
      <div class="text-xs text-gray-300 font-medium">${escapeHtml(i.summary)}</div>
      <div class="text-xs text-gray-400">${escapeHtml(i.details)}</div>
    </div>
  `).join('');
}

async function loadAnalyzers() {
  try {
    const res = await fetch('/api/analyzers');
    const analyzers = await res.json();
    document.getElementById('stat-analyzers').textContent = analyzers.length;
    const grid = document.getElementById('analyzers-grid');

    grid.innerHTML = analyzers.map(a => `
      <div class="card p-4 space-y-2">
        <div class="flex items-center justify-between">
          <div class="text-sm font-bold text-white">${a.name}</div>
          ${a.issue_count > 0 
            ? `<span class="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-400 border border-red-500/30 font-mono">${a.issue_count} Issues</span>` 
            : `<span class="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono">Healthy</span>`}
        </div>
        <div class="text-xs text-blue-400 font-mono">Target: ${a.resource}</div>
        <div class="text-xs text-gray-400 leading-relaxed">${a.description}</div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load analyzers:', err);
  }
}

async function loadCleanablePods() {
  try {
    const res = await fetch('/api/clean/pods');
    cleanablePods = await res.json();
    const tbody = document.getElementById('cleanable-pods-tbody');

    if (!cleanablePods || cleanablePods.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-gray-500">No cleanable or failed pods found. Cluster hygiene is optimal!</td></tr>`;
      return;
    }

    tbody.innerHTML = cleanablePods.map((p, idx) => `
      <tr class="hover:bg-gray-800/40 transition">
        <td class="p-3"><input type="checkbox" class="pod-select-checkbox" data-index="${idx}"></td>
        <td class="p-3 font-mono text-gray-300">${p.namespace}</td>
        <td class="p-3 font-bold text-white">${p.name}</td>
        <td class="p-3">
          <span class="px-2 py-0.5 rounded text-xs ${p.is_stuck ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-gray-800 text-gray-300'} font-mono">
            ${p.reason || p.phase}
          </span>
        </td>
        <td class="p-3 font-mono text-gray-400">${p.restart_count}</td>
        <td class="p-3 text-gray-400">${p.age}</td>
        <td class="p-3 text-right">
          <button onclick="cleanSinglePod('${p.namespace}', '${p.name}')" class="px-2 py-1 bg-red-800/30 hover:bg-red-800 text-red-300 hover:text-white rounded transition">
            Delete
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load cleanable pods:', err);
  }
}

function toggleSelectAllPods() {
  const master = document.getElementById('check-all-pods');
  document.querySelectorAll('.pod-select-checkbox').forEach(cb => {
    cb.checked = master.checked;
  });
}

async function cleanSinglePod(namespace, name) {
  if (!confirm(`Delete pod ${namespace}/${name}?`)) return;
  try {
    const res = await fetch('/api/clean/pods', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ namespace, pod_names: [name], dry_run: false })
    });
    const data = await res.json();
    if (res.ok) {
      loadCleanablePods();
      loadStatus();
    } else {
      alert(`Clean failed: ${data.error}`);
    }
  } catch (err) {
    alert(`Request error: ${err.message}`);
  }
}

async function cleanSelectedPods(dryRun) {
  const selected = [];
  document.querySelectorAll('.pod-select-checkbox:checked').forEach(cb => {
    const idx = parseInt(cb.dataset.index);
    if (cleanablePods[idx]) {
      selected.push(cleanablePods[idx].name);
    }
  });

  if (selected.length === 0) {
    alert('Please select at least one pod to clean.');
    return;
  }

  if (!confirm(`Are you sure you want to clean ${selected.length} selected pods?`)) return;

  try {
    const res = await fetch('/api/clean/pods', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pod_names: selected, dry_run: dryRun })
    });
    const data = await res.json();
    if (res.ok) {
      alert(`Cleaned ${data.deleted_count} pods successfully!`);
      loadCleanablePods();
      loadStatus();
    } else {
      alert(`Clean failed: ${data.error}`);
    }
  } catch (err) {
    alert(`Request error: ${err.message}`);
  }
}

// Chat Assistant
async function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text) return;

  input.value = '';
  appendChatMessage('User', text, false);

  const sendBtn = document.getElementById('btn-chat-send');
  sendBtn.disabled = true;

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text })
    });
    const data = await res.json();
    if (res.ok) {
      appendChatMessage(data.provider || 'SRE AI', data.reply, true);
    } else {
      appendChatMessage('Error', data.error || 'Failed to get response', true);
    }
  } catch (err) {
    appendChatMessage('Error', err.message, true);
  } finally {
    sendBtn.disabled = false;
  }
}

function askAIAboutIssue(issueId) {
  switchTab('chat');
  const issue = activeIssues.find(i => i.id === issueId);
  const prompt = issue 
    ? `Please explain the root cause and step-by-step fix for ${issue.kind} '${issue.name}' in namespace '${issue.namespace}'.`
    : `Please analyze issue ${issueId}.`;

  const input = document.getElementById('chat-input');
  input.value = prompt;
  sendChatMessage();
}

function appendChatMessage(sender, text, isAI) {
  const container = document.getElementById('chat-messages');
  const msgEl = document.createElement('div');
  msgEl.className = 'flex gap-2';

  const avatar = isAI 
    ? `<div class="w-6 h-6 rounded bg-blue-600/30 text-blue-400 flex items-center justify-center flex-shrink-0 font-bold">AI</div>`
    : `<div class="w-6 h-6 rounded bg-emerald-600/30 text-emerald-400 flex items-center justify-center flex-shrink-0 font-bold">U</div>`;

  msgEl.innerHTML = `
    ${avatar}
    <div class="bg-[#21262d] p-3 rounded-lg max-w-2xl space-y-1 text-gray-300 leading-relaxed whitespace-pre-wrap">
      <div class="text-[10px] text-gray-400 font-semibold">${escapeHtml(sender)}</div>
      <div>${escapeHtml(text)}</div>
    </div>
  `;
  container.appendChild(msgEl);
  container.scrollTop = container.scrollHeight;
}

// Config & Webhook Testing
async function loadConfig() {
  try {
    const res = await fetch('/api/config');
    const data = await res.json();
    if (data.webhook_url) {
      document.getElementById('settings-webhook-url').value = data.webhook_url;
    }
  } catch (err) {
    console.error('Failed to load config:', err);
  }
}

async function saveWebhookConfig() {
  const url = document.getElementById('settings-webhook-url').value.trim();
  try {
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhook_url: url })
    });
    if (res.ok) alert('Webhook URL saved!');
  } catch (err) {
    alert(`Save error: ${err.message}`);
  }
}

async function testWebhookAlert() {
  const url = document.getElementById('settings-webhook-url').value.trim();
  const statusEl = document.getElementById('test-alert-status');
  statusEl.textContent = 'Dispatching test alert...';
  statusEl.className = 'mt-2 text-xs text-blue-400';

  try {
    const res = await fetch('/api/notify/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhook_url: url })
    });
    const data = await res.json();
    if (res.ok) {
      statusEl.textContent = '✅ Alert sent successfully!';
      statusEl.className = 'mt-2 text-xs text-emerald-400';
    } else {
      statusEl.textContent = `❌ Delivery failed: ${data.error}`;
      statusEl.className = 'mt-2 text-xs text-red-400';
    }
  } catch (err) {
    statusEl.textContent = `❌ Error: ${err.message}`;
    statusEl.className = 'mt-2 text-xs text-red-400';
  }
}

async function triggerScan() {
  const spinner = document.getElementById('scan-spinner');
  spinner.classList.add('fa-spin');
  try {
    const res = await fetch('/api/scan', { method: 'POST' });
    const data = await res.json();
    refreshActiveTab();
  } catch (err) {
    alert(`Scan error: ${err.message}`);
  } finally {
    spinner.classList.remove('fa-spin');
  }
}

function showLogsModal(title, content) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-content').textContent = content || 'No logs captured.';
  document.getElementById('modal-backdrop').classList.remove('hidden');
}

function closeModal() {
  document.getElementById('modal-backdrop').classList.add('hidden');
}

function getSeverityBadge(severity) {
  switch (severity) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    case 'LOW': return 'badge-low';
    default: return 'badge-medium';
  }
}

function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
