import { escapeHtml, el } from '../utils.js';

export interface SecurityFindingsViewData {
  unresolvedIssues: Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
    status: string;
    evidence: string;
    impact: string;
    reference: string;
  }>;
  reservedLiveCandidates: {
    status: string;
    count: number;
    cases: Array<{
      id: string;
      scenarioId: string;
      stage: string;
      inputPreview: string;
      expectedSecurityDecision: string;
      status: string;
    }>;
    instructions?: string;
  };
}

export function renderSecurityFindings(data: SecurityFindingsViewData): HTMLElement {
  const container = el('div', { className: 'view-container' });

  // 1. Header Card
  const headerCard = el('div', { className: 'hero-card' });
  headerCard.appendChild(
    el('div', { className: 'hero-header' }, [
      el('div', {}, [
        el('h2', { className: 'hero-title' }, [
          'Veylith Known Security Limitations & Research Findings',
        ]),
        el('p', { className: 'hero-desc', style: 'margin-top: 6px;' }, [
          'Honest evaluation of unresolved risks, architectural boundaries, and pending validation items documented in Phase 2F security audit.',
        ]),
      ]),
      el('span', { className: 'badge high', style: 'font-size: 12px; padding: 4px 10px;' }, [
        '8 Open Security & Reliability Findings',
      ]),
    ]),
  );

  const honestCallout = el(
    'div',
    { className: 'callout critical', style: 'margin-top: 16px; margin-bottom: 0;' },
    [
      el('div', { className: 'callout-title' }, [
        'Integrity Principle: Passing Automated Tests ≠ Complete Security',
      ]),
      el('div', { className: 'callout-desc' }, [
        'Veylith explicitly separates verified unit/integration passes (408/408 tests across 43 files, 100% passing) from holistic threat model coverage. These 8 findings represent known system limitations and reliability observations that require ongoing architectural work and live model evaluation. Veylith is a research prototype, not a certified production appliance.',
      ]),
    ],
  );
  headerCard.appendChild(honestCallout);

  // Live Testing Status Callout
  const liveStatusCallout = el(
    'div',
    { className: 'callout info', style: 'margin-top: 12px; margin-bottom: 0;' },
    [
      el('div', { className: 'callout-title' }, [
        'Live Model Testing Status: Phase 5D Fireworks Evaluated • 6 Reserved Candidates Offline',
      ]),
      el('div', { className: 'callout-desc' }, [
        'What was tested live: Phase 4B.1 executed one real Meta Model API compatibility request (3,726.52 ms, 599 tokens, $0.00107 spend). Phase 5D evaluated 91 real Fireworks API inference requests on a frozen 100-case synthetic validation benchmark ($0.169 spend, 100% recall, 0% benign FPR). | What has NOT been tested live: The 6 reserved live adversarial candidates remain sealed offline (0 executions). Broader open-ended production MCP traffic with Meta Muse Spark 1.3 remains untested.',
      ]),
    ],
  );
  headerCard.appendChild(liveStatusCallout);
  container.appendChild(headerCard);

  // 2. Reserved Live Meta Muse Candidates (Locked Panel)
  const reservedData = data.reservedLiveCandidates;
  const lockedPanel = el('div', { className: 'locked-reserve-panel' });

  const lockedHeader = el('div', { className: 'locked-header' }, [
    el('div', { className: 'locked-title' }, [
      el('span', { style: 'font-size: 18px;' }, ['🔒']),
      el('span', {}, ['Reserved Live Meta Muse Candidates (Unseen Test Set — 0 Executions)']),
    ]),
    el('span', { className: 'locked-badge' }, [reservedData.status]),
  ]);

  const lockedNotice = el('div', { className: 'callout info', style: 'margin-bottom: 16px;' }, [
    el('div', { className: 'callout-title' }, [
      'Strict Founder Authorization Policy & Zero Execution Guarantee',
    ]),
    el('div', { className: 'callout-desc' }, [
      reservedData.instructions ||
        'These 6 reserved cases are held back for manual founder-authorized live Meta Muse API validation. Zero automated or background live requests are executed by this research dashboard. Candidates remain untouched.',
    ]),
  ]);

  // Read-only table of 6 reserved candidates
  const tableContainer = el('div', { className: 'data-table-container' });
  const table = el('table', { className: 'data-table' });
  let rowsHtml = '';

  for (const c of reservedData.cases || []) {
    rowsHtml += `
      <tr>
        <td class="code-cell"><strong>${escapeHtml(c.id)}</strong></td>
        <td><span class="tier-tag tier-god-level">${escapeHtml(c.scenarioId)}</span></td>
        <td><span class="badge unknown">${escapeHtml(c.stage)}</span></td>
        <td style="font-size: 12px; font-family: var(--font-mono); color: var(--text-main); max-width: 380px;">${escapeHtml(c.inputPreview)}</td>
        <td><span class="badge ${c.expectedSecurityDecision}">${c.expectedSecurityDecision.toUpperCase()}</span></td>
        <td><span class="badge low">${escapeHtml(c.status)}</span></td>
      </tr>
    `;
  }

  table.innerHTML = `
    <thead>
      <tr>
        <th>Candidate ID</th>
        <th>Scenario</th>
        <th>Inspection Stage</th>
        <th>Payload Preview (Sanitized)</th>
        <th>Expected Decision</th>
        <th>Execution Status</th>
      </tr>
    </thead>
    <tbody>${rowsHtml}</tbody>
  `;
  tableContainer.appendChild(table);

  lockedPanel.appendChild(lockedHeader);
  lockedPanel.appendChild(lockedNotice);
  lockedPanel.appendChild(tableContainer);
  container.appendChild(lockedPanel);

  // 3. Grid of the 8 Known Security Findings
  const findingsList = data.unresolvedIssues || [];
  const findingsGrid = el('div', { className: 'findings-grid' });

  for (const f of findingsList) {
    const sevClass = f.severity.toLowerCase() === 'high' ? 'high' : 'medium';

    const card = el('div', { className: 'finding-card' });

    // Card Header
    const cardHeader = el('div', { className: 'finding-header' }, [
      el('div', { className: 'finding-title-group' }, [
        el('span', { className: 'finding-id' }, [f.id]),
        el('h3', { className: 'finding-title' }, [f.title]),
      ]),
      el('div', { className: 'finding-badges' }, [
        el('span', { className: `badge ${sevClass}` }, [f.severity]),
        el('span', { className: 'badge unknown' }, [f.category]),
      ]),
    ]);

    // Status
    const statusSection = el('div', { className: 'finding-section' }, [
      el('span', { className: 'finding-section-title' }, ['Current Status']),
      el(
        'div',
        {
          className: 'finding-section-content',
          style: 'color: var(--text-main); font-weight: 500;',
        },
        [f.status],
      ),
    ]);

    // Evidence
    const evidenceSection = el('div', { className: 'finding-section' }, [
      el('span', { className: 'finding-section-title' }, ['Observed Evidence & Test Context']),
      el('div', { className: 'finding-section-content' }, [f.evidence]),
    ]);

    // Impact
    const impactSection = el('div', { className: 'finding-section' }, [
      el('span', { className: 'finding-section-title' }, ['Security Impact & Threat Risk']),
      el('div', { className: 'finding-section-content' }, [f.impact]),
    ]);

    // Reference
    const refSection = el('div', { className: 'finding-section' }, [
      el('span', { className: 'finding-section-title' }, ['Documentation & Source Reference']),
      el('div', { className: 'finding-section-content code-cell' }, [f.reference]),
    ]);

    card.appendChild(cardHeader);
    card.appendChild(statusSection);
    card.appendChild(evidenceSection);
    card.appendChild(impactSection);
    card.appendChild(refSection);

    findingsGrid.appendChild(card);
  }

  container.appendChild(findingsGrid);
  return container;
}
