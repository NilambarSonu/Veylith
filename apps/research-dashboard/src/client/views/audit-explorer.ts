import { formatIsoTime, formatLatency, escapeHtml, el } from '../utils.js';

export interface AuditRecordView {
  caseId?: string;
  sequenceNumber: number;
  eventId: string;
  timestamp: string;
  sessionId?: string;
  serverId: string;
  clientIdentity?: string;
  mcpMethod: string;
  targetName?: string;
  stage: string;
  decision: string;
  reasonCode: string;
  policyVersion: string;
  modelId?: string;
  latencyMs: number;
  tokenUsage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  routing?: {
    decision?: string;
    reason?: string;
    origin?: string;
    capability?: string;
    inputBytes?: number;
    contextIncluded?: boolean;
  };
  previousEventHash: string;
  currentEventHash: string;
}

export interface AuditExplorerData {
  records: AuditRecordView[];
  total: number;
  page: number;
  totalPages: number;
  source: string;
  chainVerified: boolean;
  verificationError?: string;
  chainVerification?: {
    verified: boolean;
    structure: string;
    totalChainsEvaluated: number;
    validChains: number;
    totalRecords: number;
    hashAlgorithm: string;
    genesisHash: string;
    tamperedCaseId?: string;
    tamperedIndex?: number;
    error?: string;
  };
}

export function renderAuditExplorer(
  initialData: AuditExplorerData,
  onFetchMore: (query: string) => Promise<AuditExplorerData>,
): HTMLElement {
  const container = el('div', { className: 'view-container' });

  // State
  let currentSource = 'phase-2f-mock-semantic';
  let currentDecision = 'all';
  let currentStage = 'all';
  const currentMethod = 'all';
  let currentSearch = '';
  let currentPage = 1;
  let auditState = initialData;

  // Header & Cryptographic Status Panel
  const headerCard = el('div', { className: 'panel-card' });
  const statusBadge = el(
    'div',
    {
      className: auditState.chainVerified ? 'badge allow' : 'badge block',
      style: 'display: flex; align-items: center; gap: 6px;',
    },
    [
      el('span', {
        className: 'status-dot',
        style: `background: ${auditState.chainVerified ? 'var(--status-success)' : 'var(--status-error)'};`,
      }),
      el('span', {}, [
        auditState.chainVerified ? 'Chain Integrity Validated' : 'Chain Integrity Compromised',
      ]),
    ],
  );

  const statusSubtext = el('p', { className: 'stat-sub', style: 'margin-top: 4px;' }, [
    auditState.chainVerified
      ? `SHA-256 hash-chained log: verified locally against in-situ modifications, reordering, and deletions; external anchoring or public ledger notarization is not implemented.`
      : `Tamper detected: ${auditState.verificationError ?? 'Hash mismatch'}`,
  ]);

  headerCard.appendChild(
    el('div', { className: 'panel-header' }, [
      el('div', {}, [
        el('h2', { className: 'panel-title' }, ['Tamper-Evident Local Audit Log Chain']),
        statusSubtext,
      ]),
      statusBadge,
    ]),
  );

  // Genesis reference
  const genesisBar = el(
    'div',
    {
      style:
        'background: var(--surface-secondary); padding: 8px 12px; border-radius: 4px; font-size: 11px; font-family: var(--font-mono); color: var(--text-dim); display: flex; justify-content: space-between;',
    },
    [
      el('span', {}, [
        'Genesis Hash: 0000000000000000000000000000000000000000000000000000000000000000',
      ]),
      el('span', {}, ['Hash Algorithm: SHA-256 Canonical JSON']),
    ],
  );
  headerCard.appendChild(genesisBar);

  const integrityCallout = el(
    'div',
    { className: 'callout info', style: 'margin-top: 12px; margin-bottom: 0;' },
    [
      el('div', { className: 'callout-title' }, ['Cryptographic Audit Scope & Limitations']),
      el('div', { className: 'callout-desc' }, [
        'What this establishes: Local sequence continuity and payload immutability. Each audit record links to its predecessor via SHA-256 canonical JSON hashing, detecting in-situ event edits, omissions, or reordering across local runs. | What this does NOT establish: External anchoring, public transparency (e.g. Rekor), or immutable write-once hardware protection. An attacker with full local file write privileges could theoretically regenerate the chain from genesis.',
      ]),
    ],
  );
  headerCard.appendChild(integrityCallout);
  container.appendChild(headerCard);

  // Toolbar (Source selector + Filters + Search)
  const toolbar = el('div', { className: 'toolbar' });

  // Source selector
  const sourceSelect = el('select', {
    className: 'filter-select',
    id: 'audit-source',
  }) as HTMLSelectElement;
  sourceSelect.innerHTML = `
    <option value="phase-2f-mock-semantic">Source: Phase 2F Mock-Semantic Run</option>
    <option value="phase-2f-deterministic-only">Source: Phase 2F Deterministic-Only Run</option>
    <option value="phase-2e-holdout">Source: Phase 2E Frozen Holdout Run</option>
  `;
  sourceSelect.value = currentSource;

  // Decision filter
  const decisionSelect = el('select', { className: 'filter-select' }) as HTMLSelectElement;
  decisionSelect.innerHTML = `
    <option value="all">All Decisions</option>
    <option value="allow">Allow</option>
    <option value="block">Block</option>
    <option value="sanitize">Sanitize</option>
  `;

  // Stage filter
  const stageSelect = el('select', { className: 'filter-select' }) as HTMLSelectElement;
  stageSelect.innerHTML = `
    <option value="all">All Inspection Stages</option>
    <option value="discovery">discovery (tools/list)</option>
    <option value="call_arguments">call_arguments (tools/call)</option>
    <option value="call_response">call_response (output)</option>
    <option value="resource_discovery">resource_discovery</option>
    <option value="resource_content">resource_content</option>
    <option value="prompt_discovery">prompt_discovery</option>
    <option value="prompt_messages">prompt_messages</option>
  `;

  // Search input
  const searchInput = el('input', {
    type: 'text',
    className: 'search-input',
    placeholder: 'Search event ID, target name, or reason code...',
  }) as HTMLInputElement;

  toolbar.appendChild(sourceSelect);
  toolbar.appendChild(decisionSelect);
  toolbar.appendChild(stageSelect);
  toolbar.appendChild(searchInput);
  container.appendChild(toolbar);

  // Table Container
  const tableContainer = el('div', { className: 'data-table-container' });
  container.appendChild(tableContainer);

  // Pagination Footer
  const paginationBar = el('div', { className: 'pagination-bar' });
  const paginationInfo = el('span', { className: 'stat-sub' });
  const paginationControls = el('div', { className: 'pagination-controls' });
  const btnPrev = el('button', { className: 'btn-page' }, ['Previous']);
  const btnNext = el('button', { className: 'btn-page' }, ['Next']);
  paginationControls.appendChild(btnPrev);
  paginationControls.appendChild(btnNext);
  paginationBar.appendChild(paginationInfo);
  paginationBar.appendChild(paginationControls);
  container.appendChild(paginationBar);

  async function loadData() {
    const query = new URLSearchParams({
      source: currentSource,
      page: String(currentPage),
      limit: '25',
      decision: currentDecision,
      stage: currentStage,
      method: currentMethod,
      search: currentSearch,
    }).toString();

    auditState = await onFetchMore(query);
    renderTable();
  }

  function renderTable() {
    tableContainer.innerHTML = '';
    const records = auditState.records || [];

    if (records.length === 0) {
      tableContainer.appendChild(
        el('div', { className: 'empty-state' }, [
          el('p', { style: 'font-weight: 600;' }, ['No audit records found matching criteria']),
          el('span', { className: 'stat-sub' }, [
            'Try resetting filters or changing the evidence source.',
          ]),
        ]),
      );
      paginationInfo.textContent = 'Showing 0 records';
      btnPrev.setAttribute('disabled', 'true');
      btnNext.setAttribute('disabled', 'true');
      return;
    }

    const table = el('table', { className: 'data-table' });
    let rowsHtml = '';

    // Update status badge and subtext dynamically
    statusBadge.className = auditState.chainVerified ? 'badge allow' : 'badge block';
    statusBadge.innerHTML = `
      <span class="status-dot" style="background: ${auditState.chainVerified ? 'var(--status-success)' : 'var(--status-error)'};"></span>
      <span>${auditState.chainVerified ? 'Chain Integrity Validated' : 'Chain Integrity Compromised'}</span>
    `;
    statusSubtext.textContent = auditState.chainVerified
      ? `SHA-256 hash-chained log: verified locally against in-situ modifications, reordering, and deletions; external anchoring or public ledger notarization is not implemented.`
      : `Tamper detected: ${auditState.verificationError ?? 'Hash mismatch'}`;

    for (const r of records) {
      const decClass =
        r.decision.toLowerCase() === 'allow'
          ? 'allow'
          : r.decision.toLowerCase() === 'block'
            ? 'block'
            : r.decision.toLowerCase() === 'sanitize'
              ? 'sanitize'
              : 'unknown';

      const targetEscaped = escapeHtml(r.targetName || '—');
      const reasonEscaped = escapeHtml(r.reasonCode || 'none');
      const routingDesc = r.routing?.reason
        ? escapeHtml(r.routing.reason)
        : r.modelId
          ? escapeHtml(r.modelId)
          : 'fast_path';

      rowsHtml += `
        <tr class="clickable" data-event-id="${escapeHtml(r.eventId)}">
          <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);">${r.sequenceNumber}</td>
          <td class="code-cell" style="font-size: 11px;">${escapeHtml(r.caseId || '—')}</td>
          <td style="font-size: 12px; color: var(--text-muted);">${formatIsoTime(r.timestamp)}</td>
          <td><span class="badge unknown">${escapeHtml(r.mcpMethod)}</span></td>
          <td class="code-cell">${targetEscaped}</td>
          <td><span style="font-size: 11px; color: var(--text-muted);">${escapeHtml(r.stage)}</span></td>
          <td><span class="badge ${decClass}">${escapeHtml(r.decision)}</span></td>
          <td style="font-size: 12px; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${reasonEscaped}">${reasonEscaped}</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${formatLatency(r.latencyMs)}</td>
          <td style="font-size: 11px; color: var(--accent-cyan);">${routingDesc}</td>
        </tr>
      `;
    }

    table.innerHTML = `
      <thead>
        <tr>
          <th title="Sequence index within this test case's cryptographic chain starting at Genesis (#0)">Case Seq #</th>
          <th>Case ID</th>
          <th>Timestamp</th>
          <th>MCP Method</th>
          <th>Target</th>
          <th>Stage</th>
          <th>Decision</th>
          <th>Reason</th>
          <th>Latency</th>
          <th>Routing / Model</th>
        </tr>
      </thead>
      <tbody>${rowsHtml}</tbody>
    `;

    // Row click opens detail drawer
    table.querySelectorAll('tr.clickable').forEach((row) => {
      row.addEventListener('click', () => {
        const evId = row.getAttribute('data-event-id');
        const record = records.find((rec) => rec.eventId === evId);
        if (record) {
          openDetailDrawer(record);
        }
      });
    });

    tableContainer.appendChild(table);

    // Update pagination
    const total = auditState.total || 0;
    const page = auditState.page || 1;
    const totalPages = auditState.totalPages || 1;
    paginationInfo.textContent = `Showing page ${page} of ${totalPages} (${total} total records)`;

    if (page <= 1) {
      btnPrev.setAttribute('disabled', 'true');
    } else {
      btnPrev.removeAttribute('disabled');
    }

    if (page >= totalPages) {
      btnNext.setAttribute('disabled', 'true');
    } else {
      btnNext.removeAttribute('disabled');
    }
  }

  function openDetailDrawer(record: AuditRecordView) {
    const drawer = document.getElementById('detail-drawer');
    const drawerBody = document.getElementById('drawer-body');
    if (!drawer || !drawerBody) return;

    drawerBody.innerHTML = '';

    // Summary attributes
    const summaryCard = el('div', { className: 'panel-card', style: 'padding: 14px;' });
    summaryCard.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 12px;">
        <div><span style="color: var(--text-dim);">Event ID:</span> <span class="code-cell">${escapeHtml(record.eventId)}</span></div>
        <div><span style="color: var(--text-dim);">Sequence:</span> <strong>#${record.sequenceNumber}</strong></div>
        <div><span style="color: var(--text-dim);">Method:</span> <span class="badge unknown">${escapeHtml(record.mcpMethod)}</span></div>
        <div><span style="color: var(--text-dim);">Target:</span> <strong>${escapeHtml(record.targetName || 'none')}</strong></div>
        <div><span style="color: var(--text-dim);">Stage:</span> ${escapeHtml(record.stage)}</div>
        <div><span style="color: var(--text-dim);">Decision:</span> <span class="badge ${record.decision.toLowerCase()}">${escapeHtml(record.decision)}</span></div>
        <div><span style="color: var(--text-dim);">Session ID:</span> <span class="code-cell">${escapeHtml(record.sessionId || 'isolated')}</span></div>
        <div><span style="color: var(--text-dim);">Evaluation Case:</span> <span class="code-cell">${escapeHtml(record.caseId || 'standalone')}</span></div>
        <div><span style="color: var(--text-dim);">Latency:</span> ${formatLatency(record.latencyMs)}</div>
      </div>
    `;
    drawerBody.appendChild(summaryCard);

    // Hashes verification card
    const hashCard = el('div', { className: 'panel-card', style: 'padding: 14px;' });
    hashCard.innerHTML = `
      <h4 style="font-size: 12px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px;">Cryptographic Chain Verification</h4>
      <div style="font-size: 11px; font-family: var(--font-mono); display: flex; flex-direction: column; gap: 6px;">
        <div>
          <span style="color: var(--text-dim);">Prev Hash:</span>
          <div style="word-break: break-all; color: var(--accent-secondary);">${escapeHtml(record.previousEventHash)}</div>
        </div>
        <div>
          <span style="color: var(--text-dim);">Curr Hash:</span>
          <div style="word-break: break-all; color: var(--accent-cyan);">${escapeHtml(record.currentEventHash)}</div>
        </div>
      </div>
    `;
    drawerBody.appendChild(hashCard);

    // Full JSON viewer (sanitized, zero arbitrary HTML)
    const jsonTitle = el(
      'h4',
      { style: 'font-size: 12px; text-transform: uppercase; color: var(--text-muted);' },
      ['Canonical Sanitized Event JSON'],
    );
    const pre = el('pre', { className: 'code-viewer' }, [JSON.stringify(record, null, 2)]);
    drawerBody.appendChild(jsonTitle);
    drawerBody.appendChild(pre);

    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
  }

  // Drawer close handler
  const drawer = document.getElementById('detail-drawer');
  const drawerClose = document.getElementById('drawer-close');
  if (drawerClose && drawer) {
    drawerClose.onclick = () => {
      drawer.classList.remove('open');
      drawer.setAttribute('aria-hidden', 'true');
    };
    drawer.onclick = (e) => {
      if (e.target === drawer) {
        drawer.classList.remove('open');
        drawer.setAttribute('aria-hidden', 'true');
      }
    };
  }

  // Event Listeners for controls
  sourceSelect.addEventListener('change', () => {
    currentSource = sourceSelect.value;
    currentPage = 1;
    loadData();
  });

  decisionSelect.addEventListener('change', () => {
    currentDecision = decisionSelect.value;
    currentPage = 1;
    loadData();
  });

  stageSelect.addEventListener('change', () => {
    currentStage = stageSelect.value;
    currentPage = 1;
    loadData();
  });

  let searchTimeout: ReturnType<typeof setTimeout> | undefined;
  searchInput.addEventListener('input', () => {
    if (searchTimeout) clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      currentSearch = searchInput.value;
      currentPage = 1;
      loadData();
    }, 250);
  });

  btnPrev.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      loadData();
    }
  });

  btnNext.addEventListener('click', () => {
    currentPage++;
    loadData();
  });

  renderTable();
  return container;
}
