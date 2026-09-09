// Kubebee SRE Agent Frontend Application

let currentTab = 'approvals';
let activeIssues = [];
let cleanablePods = [];
const API_TOKEN_STORAGE_KEY = 'sre-agent-api-token';

function initializeDashboard() {
  const authForm = document.getElementById('auth-form');
  if (authForm && !authForm.dataset.authBootstrap) authForm.addEventListener('submit', event => {
    event.preventDefault();
    login();
  });
  document.addEventListener('click', handleDashboardClick);
  document.addEventListener('submit', handlePlaybookSubmit);

  loadStatus();
  loadProposals();
  loadIssues();
  loadAnalyzers();
  loadCleanablePods();
  loadConfig();
  loadDashboardMetrics();
  setInterval(refreshActiveTab, 15000);
}

function handleDashboardClick(event) {
  const target = event.target instanceof Element ? event.target.closest('[data-action]') : null;
  if (!target) return;

  switch (target.dataset.action) {
    case 'playbook-tab':
      switchTab('playbooks');
      break;
    case 'playbook-refresh':
      loadPlaybooks();
      break;
    case 'playbook-transition':
      transitionPlaybook(target);
      break;
    case 'approve-proposal':
      approveProposal(target.dataset.proposalId);
      break;
    case 'reject-proposal':
      rejectProposal(target.dataset.proposalId);
      break;
    case 'show-logs': {
      const issue = activeIssues.find(item => String(item.id) === target.dataset.issueId);
      if (issue) showLogsModal(issue.name, issue.logs_snippet);
      break;
    }
    case 'ask-ai':
      askAIAboutIssue(target.dataset.issueId);
      break;
    case 'clean-pod':
      cleanSinglePod(target.dataset.namespace, target.dataset.podName);
      break;
    default:
      break;
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeDashboard);
} else {
  initializeDashboard();
}

function getStoredAPIToken() {
  try {
    return sessionStorage.getItem(API_TOKEN_STORAGE_KEY) || '';
  } catch (err) {
    return '';
  }
}

function setStoredAPIToken(token) {
  try {
    sessionStorage.setItem(API_TOKEN_STORAGE_KEY, token);
    return true;
  } catch (err) {
    return false;
  }
}

function clearStoredAPIToken() {
  try {
    sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
  } catch (err) {
    // Storage can be unavailable in restricted browser contexts.
  }
}

function showAuthRequired(message = 'An API token is required to use the dashboard.') {
  const panel = document.getElementById('auth-panel');
  if (!panel) return;

  panel.classList.remove('hidden');
  const messageEl = document.getElementById('auth-message');
  if (messageEl) messageEl.textContent = message;
}

function hideAuthRequired() {
  const panel = document.getElementById('auth-panel');
  if (panel) panel.classList.add('hidden');
}

async function login() {
  const input = document.getElementById('auth-token');
  const token = input ? input.value.trim() : '';
  if (!token) {
    showAuthRequired('Enter an API token to continue.');
    return;
  }
  if (!setStoredAPIToken(token)) {
    showAuthRequired('This browser does not permit session storage.');
    return;
  }

  showAuthRequired('Checking credentials...');
  try {
    const res = await apiFetch('/api/status');
    if (!res.ok) {
      clearStoredAPIToken();
      if (input) input.value = '';
      showAuthRequired(res.status === 401 ? 'The API token was rejected.' : 'The dashboard could not verify the API token.');
      return;
    }

    if (input) input.value = '';
    hideAuthRequired();
    refreshActiveTab();
  } catch (err) {
    clearStoredAPIToken();
    if (input) input.value = '';
    showAuthRequired('The dashboard could not verify the API token.');
  }
}

function logout() {
  clearStoredAPIToken();
  showAuthRequired('Dashboard session cleared.');
}

function apiFetch(input, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = getStoredAPIToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);

  return fetch(input, { ...options, headers }).then(res => {
    if (res.status === 401) showAuthRequired();
    return res;
  });
}

function switchTab(tab) {
  currentTab = tab;
  ['approvals', 'anomalies', 'metrics', 'analyzers', 'hygiene', 'chat', 'playbooks', 'settings'].forEach(t => {
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
  if (currentTab === 'metrics') loadDashboardMetrics();
  if (currentTab === 'analyzers') loadAnalyzers();
  if (currentTab === 'hygiene') loadCleanablePods();
  if (currentTab === 'settings') loadConfig();
  if (currentTab === 'playbooks') loadPlaybooks();
}

async function loadStatus() {
  try {
    const res = await apiFetch('/api/status');
    const data = await res.json();
    document.getElementById('stat-issues').textContent = data.active_issues_count;
    document.getElementById('stat-pending').textContent = data.pending_proposals_count;
    document.getElementById('stat-completed').textContent = data.completed_proposals_count;
    document.getElementById('llm-provider-label').textContent = data.llm_provider;
    updateRuntimeSettings(data);

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

function setDashboardText(id, value, fallback = 'Unavailable') {
  const element = document.getElementById(id);
  if (!element) return;
  const text = value === null || value === undefined || String(value).trim() === '' ? fallback : value;
  element.textContent = text;
}

function updateRuntimeSettings(data) {
  if (!data) return;
  const settings = data.settings || {};
  const value = (key, fallbackKey) => settings[key] ?? data[key] ?? (fallbackKey ? data[fallbackKey] : undefined);
  setDashboardText('settings-provider', value('llm_provider'));
  setDashboardText('settings-wire-api', value('llm_wire_api', 'wire_api'));
  setDashboardText('settings-model', value('llm_model'));
  setDashboardText('settings-base-url', value('llm_base_url_display', 'base_url_display'), 'Masked');
  setDashboardText('settings-scan-interval', value('scan_interval'));
  setDashboardText('settings-scan-jitter', value('scan_jitter'));
  const eventDriven = settings.event_driven_scanning ?? data.event_driven_scanning;
  setDashboardText('settings-event-driven', eventDriven === true ? 'Enabled' : eventDriven === false ? 'Disabled' : undefined);
  setDashboardText('settings-event-queue-capacity', value('event_queue_capacity'));
  setDashboardText('settings-event-debounce', value('event_debounce'));
  const cacheEnabled = settings.cache_enabled ?? data.cache_enabled;
  setDashboardText('settings-cache', cacheEnabled === true ? 'Enabled' : cacheEnabled === false ? 'Disabled' : undefined);
  const webhookConfigured = settings.webhook_configured ?? data.webhook_configured;
  setDashboardText('settings-webhook-status', webhookConfigured === true ? 'Configured' : webhookConfigured === false ? 'Not configured' : undefined);
}

function parsePrometheusMetrics(text) {
  const metrics = {};
  const linePattern = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+0-9.eE]+)(?:\s+\d+)?$/;
  String(text || '').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const match = trimmed.match(linePattern);
    if (!match) return;
    const value = Number(match[3]);
    if (!Number.isFinite(value)) return;
    const labels = {};
    const labelPattern = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"])*)"/g;
    let labelMatch;
    while ((labelMatch = labelPattern.exec(match[2] || '')) !== null) {
      labels[labelMatch[1]] = labelMatch[2].replace(/\\([\\"nrt])/g, (_, escaped) => ({ '\\': '\\', '"': '"', n: '\n', r: '\r', t: '\t' }[escaped] || escaped));
    }
    if (!metrics[match[1]]) metrics[match[1]] = [];
    metrics[match[1]].push({ labels, value });
  });
  return metrics;
}

function sumPrometheusMetric(metrics, name, labelName, labelValue) {
  return (metrics[name] || []).reduce((sum, sample) => {
    if (labelName && sample.labels[labelName] !== labelValue) return sum;
    return sum + sample.value;
  }, 0);
}

function setMetricValue(id, value, available = true) {
  setDashboardText(id, available ? Number(value || 0).toLocaleString() : undefined, available ? '0' : 'Unavailable');
}

async function loadDashboardMetrics() {
  const errorState = document.getElementById('metrics-error-state');
  try {
    const res = await apiFetch('/metrics');
    if (!res.ok) throw new Error(`metrics request returned ${res.status}`);
    const metrics = parsePrometheusMetrics(await res.text());
    const scanErrors = sumPrometheusMetric(metrics, 'sre_scans_total', 'status', 'error');
    const analyzerErrors = sumPrometheusMetric(metrics, 'sre_analyzer_runs_total', 'status', 'error');
    const providerErrors = sumPrometheusMetric(metrics, 'sre_provider_requests_total', 'status', 'error');
    const cacheErrors = sumPrometheusMetric(metrics, 'sre_cache_operations_total', 'status', 'error');
    const explicitErrors = sumPrometheusMetric(metrics, 'sre_errors_total');
    const hasErrorMetric = Boolean(metrics.sre_errors_total || metrics.sre_scans_total || metrics.sre_analyzer_runs_total || metrics.sre_provider_requests_total || metrics.sre_cache_operations_total);
    setMetricValue('metric-scan-errors', scanErrors);
    setMetricValue('metric-analyzer-errors', analyzerErrors);
    setMetricValue('metric-provider-errors', providerErrors);
    setMetricValue('metric-error-count', metrics.sre_errors_total ? explicitErrors : scanErrors + analyzerErrors + providerErrors + cacheErrors, hasErrorMetric);

    const prompt = sumPrometheusMetric(metrics, 'sre_provider_tokens_total', 'kind', 'prompt') || sumPrometheusMetric(metrics, 'sre_provider_tokens_total', 'token_type', 'prompt');
    const completion = sumPrometheusMetric(metrics, 'sre_provider_tokens_total', 'kind', 'completion') || sumPrometheusMetric(metrics, 'sre_provider_tokens_total', 'token_type', 'completion');
    const total = sumPrometheusMetric(metrics, 'sre_provider_tokens_total', 'kind', 'total') || sumPrometheusMetric(metrics, 'sre_provider_tokens_total', 'token_type', 'total');
    const hasTokenMetric = Boolean(metrics.sre_provider_tokens_total);
    setMetricValue('metric-token-prompt', prompt, hasTokenMetric);
    setMetricValue('metric-token-completion', completion, hasTokenMetric);
    setMetricValue('metric-token-total', total || (hasTokenMetric ? prompt + completion : 0), hasTokenMetric);
    setDashboardText('metric-token-status', hasTokenMetric ? 'Reported by provider' : 'Unavailable', 'Unavailable');
    setDashboardText('metric-last-refresh', new Date().toLocaleTimeString(), 'Never');
    setDashboardText('metric-refresh-state', 'Updated', 'Waiting for metrics');
    if (errorState) {
      errorState.classList.add('hidden');
      errorState.textContent = '';
    }
  } catch (err) {
    console.error('Failed to load dashboard metrics:', err);
    setDashboardText('metric-refresh-state', 'Unavailable', 'Unavailable');
    if (errorState) {
      errorState.textContent = 'Metrics are temporarily unavailable. Check authentication and the agent health state.';
      errorState.classList.remove('hidden');
    }
  }
}

async function loadProposals() {
  try {
    const res = await apiFetch('/api/proposals');
    if (!res.ok) throw new Error('Proposal refresh unavailable');
    const proposals = await res.json();
    if (!Array.isArray(proposals)) throw new Error('Invalid proposal response');
    const container = document.getElementById('proposals-container');

    const statusFilter = document.getElementById('proposal-status-filter')?.value || '';
    const pending = proposals.filter(p => !statusFilter || p.status === statusFilter);

    if (pending.length === 0) {
      container.innerHTML = `
        <div class="card p-8 text-center space-y-2">
          <div class="w-10 h-10 rounded-full bg-emerald-500/20 text-emerald-400 mx-auto flex items-center justify-center">
            <i class="fa-solid fa-check text-lg"></i>
          </div>
          <div class="text-sm font-semibold text-white">No matching proposals</div>
          <div class="text-xs text-gray-400">Check the incident findings and scan coverage for current cluster health.</div>
        </div>
      `;
      return;
    }

    container.innerHTML = pending.map(p => `
      <div class="card p-5 space-y-4 border-l-4 border-l-amber-500" id="proposal-${escapeHtml(p.id)}">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="text-xs px-2 py-0.5 rounded font-mono ${getSeverityBadge(p.diagnosis.severity)}">${escapeHtml(p.diagnosis.severity)}</span>
            <span class="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">${escapeHtml(p.kind)}</span>
            <span class="text-sm font-bold text-white">${escapeHtml(p.namespace)}/${escapeHtml(p.name)}</span>
          </div>
          <div class="text-xs text-gray-200">${escapeHtml(p.status)}</div>
          <div class="text-xs text-gray-400">Proposed by <span class="text-gray-200">${escapeHtml(p.diagnosis.provider_name)}</span></div>
        </div>

        <div class="space-y-1">
          <div class="text-sm font-semibold text-gray-200">${escapeHtml(p.diagnosis.summary)}</div>
          <div class="text-xs text-gray-400 leading-relaxed">${escapeHtml(p.diagnosis.root_cause)}</div>
        </div>

        <div class="p-3 bg-[#0d1117] rounded-md border border-[#30363d] space-y-2">
          <div class="flex items-center justify-between text-xs">
            <span class="text-gray-400 font-semibold">Action Plan (${escapeHtml(p.diagnosis.action_type)}):</span>
            <span class="text-gray-500">Confidence: ${(p.diagnosis.confidence_score * 100).toFixed(0)}%</span>
          </div>
          <div class="text-xs text-emerald-400 font-mono bg-black/40 p-2 rounded">${escapeHtml(p.diagnosis.proposed_command)}</div>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-[#30363d]">
          <span class="text-xs text-amber-400 flex items-center gap-1.5">
            <i class="fa-solid fa-lock"></i>
            <span>${p.status === 'PENDING_APPROVAL' ? 'Permission Required' : escapeHtml(p.status)}</span>
          </span>
          ${p.status === 'PENDING_APPROVAL' ? `<div class="flex items-center gap-2">
            <button type="button" data-action="reject-proposal" data-proposal-id="${escapeHtml(p.id)}" class="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-semibold transition">
              Reject
            </button>
            <button type="button" data-action="approve-proposal" data-proposal-id="${escapeHtml(p.id)}" class="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition">
              <i class="fa-solid fa-play"></i>
              <span>Approve & Execute</span>
            </button>
          </div>` : `<div class="text-xs text-gray-400">${escapeHtml(p.rejection_reason || p.execution_error || p.execution_result || (['REJECTED', 'EXPIRED', 'STALE'].includes(p.status) ? 'No action executed' : 'Awaiting execution result'))}<br>Operation check: ${escapeHtml(p.verification_status || 'Not verified')}${p.verification_error ? '<br>' + escapeHtml(p.verification_error) : ''}</div>`}
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load proposals:', err);
    document.getElementById('proposals-container').innerHTML = '<div role="status" class="card p-4">Proposal data is unavailable. Previous results may be stale; refresh before acting.</div>';
  }
}

async function approveProposal(id) {
  if (!confirm(`Are you sure you want to authorize and execute proposal ${id}?`)) return;

  try {
    const res = await apiFetch(`/api/proposals/${id}/approve`, { method: 'POST' });
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
    const res = await apiFetch(`/api/proposals/${id}/reject`, {
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
    const res = await apiFetch('/api/issues');
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
          <span class="text-xs px-2 py-0.5 rounded font-mono ${getSeverityBadge(i.severity)}">${escapeHtml(i.severity)}</span>
          <span class="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">${escapeHtml(i.kind)}</span>
          <span class="text-xs font-bold text-white">${i.namespace ? escapeHtml(i.namespace) + '/' : ''}${escapeHtml(i.name)}</span>
          <span class="text-xs text-gray-400 font-mono">(${escapeHtml(i.category)})</span>
        </div>
        <div class="flex items-center gap-2">
          ${i.logs_snippet ? `<button type="button" data-action="show-logs" data-issue-id="${escapeHtml(i.id)}" class="px-2 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs"><i class="fa-solid fa-file-lines mr-1"></i>Logs</button>` : ''}
          <button type="button" data-action="ask-ai" data-issue-id="${escapeHtml(i.id)}" class="px-2 py-1 bg-blue-600/30 hover:bg-blue-600/50 text-blue-400 border border-blue-500/50 rounded text-xs"><i class="fa-solid fa-robot mr-1"></i>Ask AI</button>
        </div>
      </div>
      <div class="text-xs text-gray-300 font-medium">${escapeHtml(i.summary)}</div>
      <div class="text-xs text-gray-400">${escapeHtml(i.details)}</div>
    </div>
  `).join('');
}

async function loadAnalyzers() {
  try {
    const res = await apiFetch('/api/analyzers');
    const analyzers = await res.json();
    document.getElementById('stat-analyzers').textContent = analyzers.length;
    const grid = document.getElementById('analyzers-grid');

    grid.innerHTML = analyzers.map(a => `
      <div class="card p-4 space-y-2">
        <div class="flex items-center justify-between">
          <div class="text-sm font-bold text-white">${escapeHtml(a.name)}</div>
          ${a.issue_count > 0 
            ? `<span class="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-400 border border-red-500/30 font-mono">${escapeHtml(a.issue_count)} Issues</span>`
            : `<span class="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono">Healthy</span>`}
        </div>
        <div class="text-xs text-blue-400 font-mono">Target: ${escapeHtml(a.resource)}</div>
        <div class="text-xs text-gray-400 leading-relaxed">${escapeHtml(a.description)}</div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load analyzers:', err);
  }
}

async function loadCleanablePods() {
  try {
    const res = await apiFetch('/api/clean/pods');
    if (!res.ok) throw new Error('Cleanup refresh unavailable');
    const result = await res.json();
    if (!Array.isArray(result)) throw new Error('Invalid cleanup response');
    cleanablePods = result;
    const tbody = document.getElementById('cleanable-pods-tbody');

    if (!cleanablePods || cleanablePods.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-gray-500">No cleanable or failed pods found. No cleanup candidates in this response.</td></tr>`;
      return;
    }

    tbody.innerHTML = cleanablePods.map((p, idx) => `
      <tr class="hover:bg-gray-800/40 transition">
        <td class="p-3"><input type="checkbox" class="pod-select-checkbox" data-index="${idx}"></td>
        <td class="p-3 font-mono text-gray-300">${escapeHtml(p.namespace)}</td>
        <td class="p-3 font-bold text-white">${escapeHtml(p.name)}</td>
        <td class="p-3">
          <span class="px-2 py-0.5 rounded text-xs ${p.is_stuck ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-gray-800 text-gray-300'} font-mono">
            ${escapeHtml(p.reason || p.phase)}
          </span>
        </td>
        <td class="p-3 font-mono text-gray-400">${escapeHtml(p.restart_count)}</td>
        <td class="p-3 text-gray-400">${escapeHtml(p.age)}</td>
        <td class="p-3 text-right">
          <button type="button" data-action="clean-pod" data-namespace="${escapeHtml(p.namespace)}" data-pod-name="${escapeHtml(p.name)}" class="px-2 py-1 bg-red-800/30 hover:bg-red-800 text-red-300 hover:text-white rounded transition">
            Propose cleanup
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load cleanable pods:', err);
    cleanablePods = [];
    document.getElementById('cleanable-pods-tbody').innerHTML = '<tr><td colspan="7" role="status" class="p-6">Cleanup data is unavailable. Previous selections were cleared; refresh before proposing cleanup.</td></tr>';
    const master = document.getElementById('check-all-pods');
    if (master) master.checked = false;
  }
}

function toggleSelectAllPods() {
  const master = document.getElementById('check-all-pods');
  document.querySelectorAll('.pod-select-checkbox').forEach(cb => {
    cb.checked = master.checked;
  });
}

async function submitCleanupProposals(targets, dryRun) {
  const groups = new Map();
  for (const target of targets) {
    if (!target.namespace || !target.name) throw new Error('Cleanup requires namespace and name');
    if (!groups.has(target.namespace)) groups.set(target.namespace, new Set());
    groups.get(target.namespace).add(target.name);
  }
  const counts = {candidates: 0, pending: 0, active: 0, other: 0};
  const summary = () => dryRun ? `${counts.candidates} cleanup candidates; no changes made.` : `${counts.pending} cleanup proposals pending approval; ${counts.active} already approved or executing; ${counts.other} in other states. Open Approvals for current status.`;
  for (const [namespace, names] of groups) {
    try {
      const res = await apiFetch('/api/clean/pods', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({namespace, pod_names: [...names], dry_run: dryRun})
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Cleanup request failed');
      if (!dryRun && (res.status !== 202 || !Array.isArray(data.proposals))) throw new Error('Unexpected cleanup response');
      if (dryRun) counts.candidates += (data.candidate_pods || []).length;
      else for (const proposal of data.proposals) {
        if (proposal.status === 'PENDING_APPROVAL') counts.pending++;
        else if (['APPROVED', 'EXECUTING'].includes(proposal.status)) counts.active++;
        else counts.other++;
      }
    } catch (err) {
      throw new Error(`${summary()} Remaining request failed: ${err.message}`);
    }
  }
  return summary();
}

async function cleanSinglePod(namespace, name) {
  if (!confirm(`Propose cleanup of pod ${namespace}/${name}? Owner approval is required before deletion.`)) return;
  try {
    const summary = await submitCleanupProposals([{namespace, name}], false);
    alert(summary);
    loadCleanablePods(); loadStatus();
  } catch (err) { alert(err.message); }
}

async function cleanSelectedPods(dryRun) {
  const targets = [];
  document.querySelectorAll('.pod-select-checkbox:checked').forEach(cb => {
    const candidate = cleanablePods[Number(cb.dataset.index)];
    if (candidate) targets.push({namespace: candidate.namespace, name: candidate.name});
  });
  if (!targets.length) { alert('Select at least one pod to propose cleanup.'); return; }
  if (!confirm(`${dryRun ? 'Preview' : 'Propose'} cleanup for ${targets.length} selected pods? Deletion requires approval.`)) return;
  try {
    const summary = await submitCleanupProposals(targets, dryRun);
    alert(summary);
    loadCleanablePods(); loadStatus();
  } catch (err) { alert(err.message); }
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
    const res = await apiFetch('/api/chat', {
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
    const res = await apiFetch('/api/config');
    const data = await res.json();
    updateRuntimeSettings(data);
    setDashboardText('settings-load-state', 'Loaded', 'Unavailable');
    // A configured URL is returned only in masked form; never put that value
    // into the editable input because saving it would replace the real target.
    if (data.webhook_url && !data.webhook_configured) {
      document.getElementById('settings-webhook-url').value = data.webhook_url;
    }
  } catch (err) {
    console.error('Failed to load config:', err);
    setDashboardText('settings-load-state', 'Unavailable', 'Unavailable');
  }
}

async function saveWebhookConfig() {
  const url = document.getElementById('settings-webhook-url').value.trim();
  try {
    const res = await apiFetch('/api/config', {
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
    const res = await apiFetch('/api/notify/test', {
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
    const res = await apiFetch('/api/scan', { method: 'POST' });
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
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


// Playbook content is untrusted. Build text nodes and DOM properties only.
function playbookNode(tag, text, className = '') {
  const node = document.createElement(tag);
  node.textContent = String(text ?? '');
  if (className) node.className = className;
  return node;
}

async function playbookResponse(response) {
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Playbook request failed.');
  return data;
}

function playbookMessage(message) {
  const target = document.getElementById('playbook-message');
  if (target) target.textContent = message;
}

let playbookLoadPending = false;
let playbookSettingsLoaded = false;
async function loadPlaybooks() {
  if (playbookLoadPending) return;
  playbookLoadPending = true;
  try {
    const status = await playbookResponse(await apiFetch('/api/v1/playbooks/status'));
    renderPlaybookStatus(status);
    const list = await playbookResponse(await apiFetch('/api/v1/playbooks?limit=256'));
    renderPlaybookCatalog(list.playbooks || []);
    if (!playbookSettingsLoaded) {
      const settings = await playbookResponse(await apiFetch('/api/v1/playbooks/settings'));
      fillPlaybookSettings(settings);
    }
  } catch (err) {
    document.getElementById('playbook-catalog').replaceChildren(playbookNode('p', err.message));
  } finally {
    playbookLoadPending = false;
  }
}

function renderPlaybookStatus(status) {
  const counts = status.catalog || {};
  document.getElementById('playbook-status').textContent = `${status.available ? 'Available' : (status.reason || 'Unavailable')} · ${counts.active_playbooks || 0} active · ${counts.review_playbooks || 0} in review · ${counts.playbooks || 0} total`;
  document.getElementById('playbook-provider').textContent = `Provider: ${status.provider || 'Unavailable'} · Model: ${status.model || 'Unavailable'}`;
  const tasks = document.getElementById('playbook-task-usage');
  tasks.replaceChildren();
  for (const [name, task] of Object.entries(status.tasks || {})) {
    const usage = task.token_usage;
    const text = usage ? `${usage.input_tokens} input / ${usage.output_tokens} output / ${usage.total_tokens} total tokens` : 'Token usage: Unavailable';
    tasks.append(playbookNode('p', `${name}: ${task.calls || 0} calls, ${task.errors || 0} errors · ${text} · ${task.usage_unavailable_calls || 0} calls with usage unavailable`));
  }
  const outcomes = document.getElementById('playbook-outcomes');
  outcomes.replaceChildren();
  const entries = Object.entries(status.outcomes || {});
  if (!entries.length) outcomes.append(playbookNode('p', 'No resolution, learning, or guardrail outcomes recorded.'));
  for (const [name, count] of entries) outcomes.append(playbookNode('p', `${name}: ${count}`));
}

function renderPlaybookCatalog(playbooks) {
  const target = document.getElementById('playbook-catalog');
  target.replaceChildren();
  if (!playbooks.length) target.append(playbookNode('p', 'No playbooks yet. Import a runbook to create a review draft.'));
  for (const item of playbooks) {
    const card = playbookNode('article', '', 'card p-5');
    card.append(playbookNode('h3', item.title || item.id, 'font-semibold text-white'));
    card.append(playbookNode('p', `${item.id} · version ${item.version} · ${item.lifecycle} · confidence ${item.confidence}`, 'text-xs text-gray-400'));
    card.append(playbookNode('p', item.summary, 'text-sm mt-2'));
    const detail = playbookNode('details', '', 'mt-2');
    detail.append(playbookNode('summary', 'Review steps, evidence, and provenance'));
    detail.append(playbookNode('pre', JSON.stringify({source_ids: item.source_ids || [], lineage: item.lineage || [], applicability: item.applicability || [], steps: item.steps || [], evidence: item.evidence || [], preconditions: item.preconditions || [], postconditions: item.postconditions || [], unknowns: item.unknowns || [], canonical_hash: item.canonical_hash}, null, 2), 'playbook-details'));
    card.append(detail);
    const actions = playbookNode('div', '', 'playbook-actions');
    const allowed = item.lifecycle === 'NORMALIZED' ? [['review', 'Submit for review']] : item.lifecycle === 'REVIEW' ? [['approve', 'Activate'], ['reject', 'Reject']] : item.lifecycle === 'ACTIVE' ? [['retire', 'Retire']] : [];
    for (const [action, label] of allowed) {
      const button = playbookNode('button', label);
      button.type = 'button';
      button.dataset.action = 'playbook-transition';
      button.dataset.playbookId = item.id;
      button.dataset.version = String(item.version);
      button.dataset.transition = action;
      actions.append(button);
    }
    card.append(actions);
    target.append(card);
  }
}

async function transitionPlaybook(button) {
  button.disabled = true;
  try {
    const id = encodeURIComponent(button.dataset.playbookId);
    const action = encodeURIComponent(button.dataset.transition);
    await playbookResponse(await apiFetch(`/api/v1/playbooks/${id}/${action}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({version: Number(button.dataset.version)})}));
    playbookMessage('Playbook state updated.');
    await loadPlaybooks();
  } catch (err) { playbookMessage(err.message); }
  finally { button.disabled = false; }
}

function fillPlaybookSettings(settings) {
  const form = document.getElementById('playbook-settings-form');
  for (const [name, value] of Object.entries(settings)) {
    const input = form.elements.namedItem(name);
    if (!input) continue;
    if (input.type === 'checkbox') input.checked = Boolean(value);
    else input.value = Array.isArray(value) ? value.join(', ') : String(value);
  }
  document.getElementById('playbook-settings-fields').disabled = false;
  playbookSettingsLoaded = true;
}

async function handlePlaybookSubmit(event) {
  const form = event.target;
  if (form.id !== 'playbook-import-form' && form.id !== 'playbook-settings-form') return;
  event.preventDefault();
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const values = new FormData(form);
    if (form.id === 'playbook-import-form') {
      const body = {content: values.get('content'), media_type: values.get('media_type'), origin: values.get('origin')};
      const result = await playbookResponse(await apiFetch('/api/v1/playbooks/import', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}));
      playbookMessage(`${result.duplicate ? 'Existing version found.' : 'Imported for review.'} Guardrails: ${JSON.stringify(result.guardrails || {})}`);
      form.elements.namedItem('content').value = '';
    } else {
      const body = {enabled: values.has('enabled'), allow_cluster_scoped: values.has('allow_cluster_scoped'), learning_mode: values.get('learning_mode')};
      for (const name of ['min_confidence', 'max_steps', 'max_source_bytes', 'max_total_text_bytes']) body[name] = Number(values.get(name));
      for (const name of ['allowed_actions', 'allowed_namespaces', 'allowed_kinds']) body[name] = String(values.get(name) || '').split(',').map(value => value.trim()).filter(Boolean);
      const settings = await playbookResponse(await apiFetch('/api/v1/playbooks/settings', {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}));
      fillPlaybookSettings(settings);
      playbookMessage('Playbook settings updated for this running service.');
    }
    await loadPlaybooks();
  } catch (err) { playbookMessage(err.message); }
  finally { submit.disabled = false; }
}
