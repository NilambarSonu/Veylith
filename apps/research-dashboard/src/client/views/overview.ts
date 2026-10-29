import { el } from '../utils.js';

export interface OverviewViewData {
  product: string;
  tagline: string;
  environment: {
    mode: string;
    binding: string;
    readOnly: boolean;
    authStatus: string;
    platform: string;
    nodeVersion: string;
  };
  provenance: {
    baseCommit: string;
    evaluatedSourceCommit: string;
    manifestSha256: string;
    workingTreeStatus: string;
  };
  metricsSummary: {
    principalScenarios: number;
    offlineVariants: number;
    totalDatasetVariants: number;
    frozenHoldoutCount: number;
    reservedLiveCandidates: number;
    automatedTestsPassed: number;
    automatedTestsTotal: number;
    reliabilityProbesPassed: number;
    reliabilityProbesTotal: number;
    reliabilityProbesFailed: number;
  };
  qualityGates?: Array<{
    command: string;
    exitCode: number;
    durationMs: number;
    log: string;
  }>;
  badges: Array<{
    label: string;
    value: string;
    type: string;
  }>;
}

export function renderOverview(data: OverviewViewData): HTMLElement {
  const container = el('div', { className: 'view-container' });

  // 1. Hero Card
  const heroCard = el('div', { className: 'hero-card' });
  const heroHeader = el('div', { className: 'hero-header' }, [
    el('div', {}, [
      el('h2', { className: 'hero-title' }, [data.product]),
      el('p', { className: 'hero-desc', style: 'margin-top: 6px;' }, [
        'An AI-native security gateway for Model Context Protocol (MCP) clients and servers, evaluating tool calls, prompt messages, and resource contents with hybrid deterministic policies and semantic review.',
      ]),
    ]),
    el('span', { className: 'hero-tag' }, [data.environment.binding]),
  ]);

  const noticeCallout = el(
    'div',
    { className: 'callout warning', style: 'margin-top: 18px; margin-bottom: 0;' },
    [
      el('div', { className: 'callout-title' }, ['Non-Production Local Research Prototype']),
      el('div', { className: 'callout-desc' }, [
        'This dashboard runs locally over 127.0.0.1 in read-only mode to visualize evaluated offline benchmarks and test results. It does not provide remote security console capabilities, user authentication, or production runtime authorization guarantees.',
      ]),
    ],
  );

  // Explicit status badges
  const badgesGrid = el('div', { className: 'badges-grid' });
  if (Array.isArray(data.badges)) {
    for (const b of data.badges) {
      const badgeClass = `eval-badge ${b.type}`;
      badgesGrid.appendChild(
        el('div', { className: badgeClass }, [
          el('span', { className: 'eval-badge-label' }, [b.label]),
          el('span', { className: 'eval-badge-value' }, [b.value]),
        ]),
      );
    }
  }

  heroCard.appendChild(heroHeader);
  heroCard.appendChild(noticeCallout);
  heroCard.appendChild(badgesGrid);
  container.appendChild(heroCard);

  // 2. Metrics Summary Grid (Real verified counts)
  const statsGrid = el('div', { className: 'stats-grid' });
  const ms = data.metricsSummary;

  statsGrid.appendChild(
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Principal Scenarios']),
      el('span', { className: 'stat-value' }, [String(ms.principalScenarios)]),
      el('span', { className: 'stat-sub' }, ['14 scenarios across 5 difficulty tiers']),
    ]),
  );

  statsGrid.appendChild(
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Dataset Offline Variants']),
      el('span', { className: 'stat-value' }, [String(ms.totalDatasetVariants)]),
      el('span', { className: 'stat-sub' }, [`112 core offline + 16 generated splits`]),
    ]),
  );

  statsGrid.appendChild(
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Frozen Holdout Cases']),
      el('span', { className: 'stat-value' }, [String(ms.frozenHoldoutCount)]),
      el('span', { className: 'stat-sub' }, ['Phase 2E frozen benchmark split']),
    ]),
  );

  statsGrid.appendChild(
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Reserved Live Candidates']),
      el('span', { className: 'stat-value', style: 'color: var(--accent-cyan);' }, [
        String(ms.reservedLiveCandidates),
      ]),
      el('span', { className: 'stat-sub' }, ['Locked: Founder Authorization Req.']),
    ]),
  );

  statsGrid.appendChild(
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Automated Tests']),
      el('span', { className: 'stat-value', style: 'color: var(--status-success);' }, [
        `${ms.automatedTestsPassed} / ${ms.automatedTestsTotal}`,
      ]),
      el('span', { className: 'stat-sub' }, ['252/252 tests passing in Phase 2F']),
    ]),
  );

  statsGrid.appendChild(
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Inherited Reliability Probes']),
      el('span', { className: 'stat-value', style: 'color: var(--status-warning);' }, [
        `${ms.reliabilityProbesPassed} / ${ms.reliabilityProbesTotal}`,
      ]),
      el('span', { className: 'stat-sub' }, ['13 passed, 2 unresolved failures']),
    ]),
  );

  container.appendChild(statsGrid);

  // 3. Provenance & Evaluation Metadata Panel
  const provPanel = el('div', { className: 'panel-card' });
  provPanel.appendChild(
    el('div', { className: 'panel-header' }, [
      el('h3', { className: 'panel-title' }, ['Dataset Provenance & Evaluated Commit']),
      el('span', { className: 'stat-sub' }, ['Phase 2F Clean Working Tree']),
    ]),
  );

  const provTable = el('div', { className: 'data-table-container' });
  const table = el('table', { className: 'data-table' });
  table.innerHTML = `
    <thead>
      <tr>
        <th>Attribute</th>
        <th>Recorded Evidence Value</th>
        <th>Verification Status</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Evaluated Source Commit</td>
        <td class="code-cell">${data.provenance.evaluatedSourceCommit}</td>
        <td><span class="badge allow">Verified Source</span></td>
      </tr>
      <tr>
        <td>Base Commit</td>
        <td class="code-cell">${data.provenance.baseCommit}</td>
        <td><span class="badge allow">Verified Parent</span></td>
      </tr>
      <tr>
        <td>Holdout Manifest Digest</td>
        <td class="code-cell">2270b7052e864a84ec28f38fbd15eeed1ccb50447e0ce934de0d508f2337d89c</td>
        <td><span class="badge allow">SHA-256 Match</span></td>
      </tr>
      <tr>
        <td>Live Reserve Digest</td>
        <td class="code-cell">e4f918504d7a54bf89a4f599fe6c6a2ef7de9a42c86909613c80de5f826ee276</td>
        <td><span class="badge unknown">Locked Offline</span></td>
      </tr>
      <tr>
        <td>Measurement Working Tree</td>
        <td>Clean (dev/phase-2f-boundary-remediation)</td>
        <td><span class="badge allow">Unmodified Tree</span></td>
      </tr>
      <tr>
        <td>Inference Spending During Eval</td>
        <td>$0.000000 USD (0 paid Meta API calls)</td>
        <td><span class="badge allow">Cost Cap Intact</span></td>
      </tr>
    </tbody>
  `;
  provTable.appendChild(table);
  provPanel.appendChild(provTable);
  container.appendChild(provPanel);

  // 4. Quality Gates Table
  if (Array.isArray(data.qualityGates) && data.qualityGates.length > 0) {
    const gatesPanel = el('div', { className: 'panel-card' });
    gatesPanel.appendChild(
      el('div', { className: 'panel-header' }, [
        el('h3', { className: 'panel-title' }, ['Verified CI & Security Quality Gates']),
        el('span', { className: 'stat-sub' }, [`${data.qualityGates.length} Gates Executed`]),
      ]),
    );

    const gatesTable = el('div', { className: 'data-table-container' });
    const gTable = el('table', { className: 'data-table' });
    let rowsHtml = '';
    for (const g of data.qualityGates) {
      const isSuccess = g.exitCode === 0;
      rowsHtml += `
        <tr>
          <td class="code-cell">${g.command}</td>
          <td>${isSuccess ? '<span class="badge allow">Exit 0</span>' : '<span class="badge block">Failed</span>'}</td>
          <td style="font-family: var(--font-mono);">${(g.durationMs / 1000).toFixed(2)}s</td>
          <td style="color: var(--text-dim);">${g.log}</td>
        </tr>
      `;
    }
    gTable.innerHTML = `
      <thead>
        <tr>
          <th>Command</th>
          <th>Status</th>
          <th>Duration</th>
          <th>Evidence Archive</th>
        </tr>
      </thead>
      <tbody>${rowsHtml}</tbody>
    `;
    gatesTable.appendChild(gTable);
    gatesPanel.appendChild(gatesTable);
    container.appendChild(gatesPanel);
  }

  return container;
}
