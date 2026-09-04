// Kubebee SRE Agent Frontend Application

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('llm-provider-label').textContent = data.llm_provider || 'Active';
    document.getElementById('stat-issues').textContent = data.active_issues_count || 0;
    document.getElementById('stat-pending').textContent = data.pending_proposals_count || 0;
    document.getElementById('stat-completed').textContent = data.completed_proposals_count || 0;
    if (data.last_scan) {
      const dt = new Date(data.last_scan);
      document.getElementById('last-scan-time').textContent = 'Last scan: ' + dt.toLocaleTimeString();
    }
  } catch (err) {
    console.error('Failed to fetch status:', err);
  }
}

async function fetchProposals() {
  try {
    const res = await fetch('/api/proposals');
    const proposals = await res.json();
    renderProposals(proposals);
    renderHistory(proposals);
  } catch (err) {
    console.error('Failed to fetch proposals:', err);
  }
}

async function fetchIssues() {
  try {
    const res = await fetch('/api/issues');
    const issues = await res.json();
    renderIssues(issues);
  } catch (err) {
    console.error('Failed to fetch issues:', err);
  }
}

function renderProposals(proposals) {
  const container = document.getElementById('proposals-container');
  const pending = proposals.filter(p => p.status === 'PENDING_APPROVAL');
  document.getElementById('pending-count-tag').textContent = `${pending.length} pending`;

  if (pending.length === 0) {
    container.innerHTML = `
      <div class="card p-8 text-center text-gray-500 text-sm">
        <i class="fa-solid fa-circle-check text-2xl text-emerald-500 mb-2 block"></i>
        No pending approvals required. All cluster workloads operating normally.
      </div>
    `;
    return;
  }

  container.innerHTML = pending.map(p => {
    const diag = p.diagnosis || {};
    return `
      <div class="card p-5 border-l-4 border-l-amber-500 space-y-4" id="proposal-${p.id}">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-[#30363d] pb-3">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40">
              ${diag.severity || 'HIGH'}
            </span>
            <span class="text-sm font-semibold text-white">
              ${p.kind}/${p.name}
            </span>
            <span class="text-xs text-gray-400 font-mono">
              ns: ${p.namespace || 'cluster-wide'}
            </span>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="approveProposal('${p.id}')" class="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition">
              <i class="fa-solid fa-check"></i>
              <span>Approve & Execute</span>
            </button>
            <button onclick="rejectProposal('${p.id}')" class="px-3 py-1.5 rounded bg-rose-900/60 hover:bg-rose-800 text-rose-200 text-xs font-semibold flex items-center gap-1.5 transition border border-rose-700/50">
              <i class="fa-solid fa-xmark"></i>
              <span>Reject</span>
            </button>
          </div>
        </div>

        <div>
          <div class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-1">AI Root Cause Analysis (${diag.provider_name || 'AI Engine'})</div>
          <p class="text-sm text-gray-200 leading-relaxed">${diag.root_cause || diag.summary || 'Investigation underway.'}</p>
        </div>

        <div class="bg-[#0d1117] p-3 rounded border border-[#30363d]">
          <div class="text-xs font-bold text-gray-400 uppercase tracking-wider mb-1 flex items-center justify-between">
            <span>Proposed Action (${diag.action_type || 'Custom'})</span>
            <span class="text-[10px] text-gray-500">Confidence: ${Math.round((diag.confidence_score || 0.85) * 100)}%</span>
          </div>
          <div class="text-xs text-emerald-400 mb-1.5 font-medium">${diag.remediation_plan || ''}</div>
          <pre class="p-2 text-xs font-mono text-gray-200 overflow-x-auto select-all">${diag.proposed_command || 'Manual review required'}</pre>
        </div>
      </div>
    `;
  }).join('');
}

function renderIssues(issues) {
  const container = document.getElementById('issues-container');
  if (!issues || issues.length === 0) {
    container.innerHTML = `
      <div class="card p-6 text-center text-gray-500 text-sm">
        <i class="fa-solid fa-check text-emerald-500 mr-1.5"></i> No active anomalies detected in current cluster state.
      </div>
    `;
    return;
  }

  container.innerHTML = issues.map(iss => {
    let badgeClass = 'badge-medium';
    if (iss.severity === 'CRITICAL') badgeClass = 'badge-critical';
    else if (iss.severity === 'HIGH') badgeClass = 'badge-high';

    const eventsHtml = (iss.events && iss.events.length > 0)
      ? `<div class="mt-2 text-xs text-gray-400 space-y-1">
          <div class="font-semibold text-gray-300">Warning Events:</div>
          ${iss.events.map(e => `<div class="font-mono text-[11px] text-amber-400/90 pl-2 border-l border-amber-500/30">${e}</div>`).join('')}
         </div>`
      : '';

    const logsHtml = iss.logs_snippet
      ? `<details class="mt-2">
          <summary class="text-xs text-blue-400 hover:underline cursor-pointer select-none">Show Container Logs (tail)</summary>
          <pre class="mt-1 p-2 text-[11px] font-mono text-gray-300 max-h-48 overflow-y-auto">${iss.logs_snippet}</pre>
        </details>`
      : '';

    return `
      <div class="card p-4 space-y-2">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">
              ${iss.severity}
            </span>
            <span class="text-sm font-semibold text-white">${iss.kind}/${iss.name}</span>
            <span class="text-xs text-gray-400 font-mono">ns: ${iss.namespace || 'cluster-wide'}</span>
          </div>
          <span class="text-xs text-gray-500 font-mono">${iss.category}</span>
        </div>
        <div class="text-xs text-gray-300">${iss.summary}</div>
        ${iss.details ? `<div class="text-xs text-gray-400">${iss.details}</div>` : ''}
        ${eventsHtml}
        ${logsHtml}
      </div>
    `;
  }).join('');
}

function renderHistory(proposals) {
  const tbody = document.getElementById('history-table-body');
  const finished = proposals.filter(p => p.status !== 'PENDING_APPROVAL');

  if (finished.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="px-4 py-4 text-center text-gray-500">No executed remediations recorded yet.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = finished.map(p => {
    let statusBadge = 'badge-medium';
    if (p.status === 'COMPLETED') statusBadge = 'badge-success';
    else if (p.status === 'FAILED') statusBadge = 'badge-critical';
    else if (p.status === 'REJECTED') statusBadge = 'badge-high';

    const dateStr = new Date(p.updated_at || p.created_at).toLocaleString();
    return `
      <tr class="hover:bg-[#1f242c] transition">
        <td class="px-4 py-3 font-mono text-[11px] text-gray-400">${dateStr}</td>
        <td class="px-4 py-3 font-medium text-white">${p.kind}/${p.name} <span class="text-gray-500">(${p.namespace || 'global'})</span></td>
        <td class="px-4 py-3 font-mono text-gray-300">${p.diagnosis ? p.diagnosis.action_type : 'Custom'}</td>
        <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${statusBadge}">${p.status}</span></td>
        <td class="px-4 py-3 text-gray-400">${p.approved_by || p.rejected_by || 'System'}</td>
        <td class="px-4 py-3 font-mono text-[11px] text-gray-300 truncate max-w-xs" title="${p.execution_result || p.execution_error || ''}">
          ${p.execution_result || p.execution_error || 'N/A'}
        </td>
      </tr>
    `;
  }).join('');
}

async function approveProposal(id) {
  try {
    const res = await fetch(`/api/proposals/${id}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved_by: 'Dashboard Operator' })
    });
    if (!res.ok) {
      const err = await res.json();
      alert('Approval failed: ' + (err.error || res.statusText));
      return;
    }
    refreshAll();
  } catch (err) {
    alert('Error sending approval: ' + err);
  }
}

async function rejectProposal(id) {
  try {
    const res = await fetch(`/api/proposals/${id}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rejected_by: 'Dashboard Operator' })
    });
    if (!res.ok) {
      const err = await res.json();
      alert('Rejection failed: ' + (err.error || res.statusText));
      return;
    }
    refreshAll();
  } catch (err) {
    alert('Error rejecting proposal: ' + err);
  }
}

async function triggerScan() {
  const spinner = document.getElementById('scan-spinner');
  spinner.classList.add('fa-spin');
  try {
    await fetch('/api/scan', { method: 'POST' });
    setTimeout(refreshAll, 1000);
  } catch (err) {
    console.error('Scan trigger failed:', err);
  } finally {
    setTimeout(() => spinner.classList.remove('fa-spin'), 1200);
  }
}

function refreshAll() {
  fetchStatus();
  fetchProposals();
  fetchIssues();
}

// Initial load & 10s auto-refresh
refreshAll();
setInterval(refreshAll, 10000);
