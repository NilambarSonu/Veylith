import { formatPct, formatLatency, el } from '../utils.js';
import { createConfusionMatrixCard, createMetricsComparisonSvg } from '../charts.js';

export interface EvaluationScenarioMetrics {
  samples: number;
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  recall: number | null;
  falsePositiveRate: number | null;
  enforcementSuccessRate: number | null;
  p50Ms: number | null;
}

export interface EvaluationRunView {
  mode: string;
  split: string;
  gitCommit: string;
  manifestSha256: string;
  metrics: {
    samples: number;
    classificationSamples: number;
    tp: number;
    tn: number;
    fp: number;
    fn: number;
    precision: number | null;
    recall: number | null;
    falsePositiveRate: number | null;
    falseNegativeRate: number | null;
    accuracy: number | null;
    enforcementSuccesses: number;
    enforcementSuccessRate: number | null;
    unsupported?: number;
    forwardingViolations?: number;
    isolationFailures?: number;
    p50Ms?: number | null;
    p95Ms?: number | null;
    p99Ms?: number | null;
  };
  byScenario?: Record<string, EvaluationScenarioMetrics>;
}

export interface EvaluationLabData {
  phase2fDevelopment: {
    datasetDescription: string;
    provenanceNotice: string;
    specialWarnings: Array<{ title: string; level: string; description: string }>;
    runs: EvaluationRunView[];
    beforeRuns?: EvaluationRunView[];
  };
  phase2eHoldout: {
    datasetDescription: string;
    provenanceNotice: string;
    specialWarnings: Array<{ title: string; level: string; description: string }>;
    runs: EvaluationRunView[];
  };
}

export function renderEvaluationLab(data: EvaluationLabData): HTMLElement {
  const container = el('div', { className: 'view-container' });

  // State: active tab ('phase2f-dev' vs 'phase2e-holdout'), active mode ('mock-semantic', 'deterministic-only', 'direct')
  let currentSplit = 'phase2f-dev';
  let currentMode = 'mock-semantic';

  // Tabs Bar
  const tabsBar = el('div', { className: 'tabs-bar' });
  const tabPhase2f = el('button', { className: 'tab-btn active', id: 'tab-p2f' }, [
    'Phase 2F Development Comparison (72 Samples)',
  ]);
  const tabPhase2e = el('button', { className: 'tab-btn', id: 'tab-p2e' }, [
    'Phase 2E Frozen Holdout Benchmark (56 Cases)',
  ]);
  tabsBar.appendChild(tabPhase2f);
  tabsBar.appendChild(tabPhase2e);
  container.appendChild(tabsBar);

  // Dynamic View Wrapper
  const contentWrapper = el('div', { className: 'view-container' });
  container.appendChild(contentWrapper);

  function updateView() {
    contentWrapper.innerHTML = '';

    const isPhase2f = currentSplit === 'phase2f-dev';
    const splitData = isPhase2f ? data.phase2fDevelopment : data.phase2eHoldout;
    const runs = splitData.runs || [];

    // Header Panel with Mode Switcher
    const headerPanel = el('div', { className: 'panel-card' });
    const headerRow = el('div', {
      style:
        'display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;',
    });

    const titleGroup = el('div', {}, [
      el('h2', { className: 'panel-title', style: 'font-size: 17px;' }, [
        splitData.datasetDescription,
      ]),
      el('p', { className: 'stat-sub', style: 'margin-top: 4px;' }, [splitData.provenanceNotice]),
    ]);

    // Mode Switcher Pills
    const pillGroup = el('div', { className: 'pill-group' });
    const modes = [
      { id: 'mock-semantic', label: 'Mock-Semantic' },
      { id: 'deterministic-only', label: 'Deterministic-Only' },
      { id: 'direct', label: 'Direct Upstream (Baseline)' },
    ];

    for (const m of modes) {
      const btn = el(
        'button',
        {
          className: `pill-btn ${currentMode === m.id ? 'active' : ''}`,
          'data-mode': m.id,
        },
        [m.label],
      );
      btn.addEventListener('click', () => {
        currentMode = m.id;
        updateView();
      });
      pillGroup.appendChild(btn);
    }

    headerRow.appendChild(titleGroup);
    headerRow.appendChild(pillGroup);
    headerPanel.appendChild(headerRow);
    contentWrapper.appendChild(headerPanel);

    // Callouts / Warnings
    if (isPhase2f) {
      // Deterministic 100% FPR Warning
      const warnDet = el('div', { className: 'callout critical' }, [
        el('div', { className: 'callout-title' }, [
          '⚠️ Phase 2F Deterministic-Only Mode: 100% False Positive Rate (All 20 Benign Blocked)',
        ]),
        el('div', { className: 'callout-desc' }, [
          'In deterministic-only mode, every ambiguous request without semantic approval was rejected fail-closed. As a result, all 20 benign control cases were blocked (FP=20, TN=0, FPR=100%). While recall appears to be 100%, the gateway achieved this by destroying availability for harmless requests.',
        ]),
      ]);

      // Mock Semantic Model Warning
      const warnMock = el('div', { className: 'callout warning' }, [
        el('div', { className: 'callout-title' }, [
          'ℹ️ Mock-Semantic Recall: 52.1% (Synthetic Mock Results Do Not Measure Real Model Accuracy)',
        ]),
        el('div', { className: 'callout-desc' }, [
          'In mock-semantic mode, 25 of 48 attacks were detected (52.1% recall). However, the mock adapter evaluates synthetic heuristics, not Meta Muse 1.3 weights. Real-world model detection quality remains untested in Phase 2F.',
        ]),
      ]);

      contentWrapper.appendChild(warnDet);
      contentWrapper.appendChild(warnMock);
    } else {
      // Procedural Holdout Callout
      const holdoutCallout = el('div', { className: 'callout info' }, [
        el('div', { className: 'callout-title' }, ['Procedural Holdout Benchmark Provenance']),
        el('div', { className: 'callout-desc' }, [
          'The Phase 2E holdout (56 cases) was frozen at commit 1086aef prior to evaluation. It represents a strict procedural holdout to protect against training leakage, rather than an independently blinded third-party benchmark. Metrics must remain strictly isolated from Phase 2F development runs.',
        ]),
      ]);
      contentWrapper.appendChild(holdoutCallout);
    }

    // Find active run for selected mode
    const activeRun = runs.find((r) => r.mode === currentMode) || runs[0];
    if (!activeRun) {
      contentWrapper.appendChild(
        el('div', { className: 'empty-state' }, ['No run data for selected mode']),
      );
      return;
    }

    const m = activeRun.metrics;

    // Metrics Stats Row
    const statsGrid = el('div', { className: 'stats-grid' });
    statsGrid.appendChild(
      el('div', { className: 'stat-card' }, [
        el('span', { className: 'stat-label' }, ['Enforcement Success Rate']),
        el('span', { className: 'stat-value', style: 'color: var(--accent-primary);' }, [
          formatPct(m.enforcementSuccessRate),
        ]),
        el('span', { className: 'stat-sub' }, [
          `${m.enforcementSuccesses} / ${m.samples} total cases enforced`,
        ]),
      ]),
    );

    statsGrid.appendChild(
      el('div', { className: 'stat-card' }, [
        el('span', { className: 'stat-label' }, ['Detection Recall (Attacks Blocked)']),
        el(
          'span',
          {
            className: 'stat-value',
            style: m.recall === 1 && m.falsePositiveRate === 1 ? 'color: var(--status-danger)' : '',
          },
          [formatPct(m.recall)],
        ),
        el('span', { className: 'stat-sub' }, [`${m.tp} TP / ${m.tp + m.fn} Total Malicious`]),
      ]),
    );

    statsGrid.appendChild(
      el('div', { className: 'stat-card' }, [
        el('span', { className: 'stat-label' }, ['False Positive Rate (Benign Blocked)']),
        el(
          'span',
          {
            className: 'stat-value',
            style: m.falsePositiveRate === 1 ? 'color: var(--status-danger)' : '',
          },
          [formatPct(m.falsePositiveRate)],
        ),
        el('span', { className: 'stat-sub' }, [`${m.fp} FP / ${m.fp + m.tn} Total Benign`]),
      ]),
    );

    statsGrid.appendChild(
      el('div', { className: 'stat-card' }, [
        el('span', { className: 'stat-label' }, ['Median Latency (P50)']),
        el('span', { className: 'stat-value' }, [formatLatency(m.p50Ms)]),
        el('span', { className: 'stat-sub' }, [
          `P95: ${formatLatency(m.p95Ms)} | P99: ${formatLatency(m.p99Ms)}`,
        ]),
      ]),
    );

    contentWrapper.appendChild(statsGrid);

    // Confusion Matrix and SVG comparison
    if (m.classificationSamples > 0) {
      const matrixCard = createConfusionMatrixCard({
        tp: m.tp,
        tn: m.tn,
        fp: m.fp,
        fn: m.fn,
        precision: m.precision,
        recall: m.recall,
        fpr: m.falsePositiveRate,
        fnr: m.falseNegativeRate,
        accuracy: m.accuracy,
        totalClassified: m.classificationSamples,
      });

      const barsCard = createMetricsComparisonSvg([
        { label: 'Recall (Attack Detection)', value: m.recall, color: 'var(--status-info)' },
        {
          label: 'Precision (Correctness of Blocks)',
          value: m.precision,
          color: 'var(--accent-secondary)',
        },
        { label: 'Classification Accuracy', value: m.accuracy, color: 'var(--status-success)' },
        {
          label: 'Enforcement Success Rate',
          value: m.enforcementSuccessRate,
          color: 'var(--accent-cyan)',
        },
        { label: 'False Positive Rate', value: m.falsePositiveRate, color: 'var(--status-danger)' },
      ]);

      const chartRow = el('div', {
        style:
          'display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 16px;',
      });
      chartRow.appendChild(matrixCard);
      chartRow.appendChild(barsCard);
      contentWrapper.appendChild(chartRow);
    } else {
      // Direct baseline notice (direct passthrough does not classify)
      const directNotice = el('div', { className: 'callout info' }, [
        el('div', { className: 'callout-title' }, [
          'Direct Baseline: Unchecked Upstream Passthrough',
        ]),
        el('div', { className: 'callout-desc' }, [
          `Direct mode bypasses security inspection. Out of ${m.samples} cases, only ${m.enforcementSuccesses} succeeded (${formatPct(m.enforcementSuccessRate)}) due to upstream crashes, forwarding violations (${m.forwardingViolations || 0}), and unsupported schemas (${m.unsupported || 0}). Direct baseline provides zero attack containment.`,
        ]),
      ]);
      contentWrapper.appendChild(directNotice);
    }

    // Scenario Breakdown by 5 Difficulty Tiers Table
    if (activeRun.byScenario) {
      const scenarioPanel = el('div', { className: 'panel-card' });
      scenarioPanel.appendChild(
        el('div', { className: 'panel-header' }, [
          el('h3', { className: 'panel-title' }, [
            'Evaluation Breakdown by Scenario & Difficulty Tier',
          ]),
          el('span', { className: 'stat-sub' }, ['14 Principal Scenarios']),
        ]),
      );

      const tableContainer = el('div', { className: 'data-table-container' });
      const table = el('table', { className: 'data-table' });

      const scenarioTiers: Record<string, { tier: string; name: string }> = {
        E1: { tier: 'easy', name: 'Legitimate MCP Workflow' },
        E2: { tier: 'easy', name: 'Obvious Prompt Injection' },
        M1: { tier: 'medium', name: 'Benign Dangerous-Looking Content' },
        M2: { tier: 'medium', name: 'Tool Metadata and Schema Poisoning' },
        M3: { tier: 'medium', name: 'Multilingual and Unicode Injection' },
        H1: { tier: 'hard', name: 'Indirect Prompt Injection' },
        H2: { tier: 'hard', name: 'Tool Authorization Confusion' },
        H3: { tier: 'hard', name: 'Client/Server Identity Boundaries' },
        X1: { tier: 'extremely-hard', name: 'Fragmented Multi-Message Injection' },
        X2: { tier: 'extremely-hard', name: 'Discovery Cache and TOCTOU Stress' },
        X3: { tier: 'extremely-hard', name: 'Cross-Session / Concurrent Requests' },
        G1: { tier: 'god-level', name: 'Adaptive Injection Against Inspection' },
        G2: { tier: 'god-level', name: 'Multi-Tool Trust-Chain Attack' },
        G3: { tier: 'god-level', name: 'Cascading Failures Under Adversarial Load' },
      };

      let rowsHtml = '';
      for (const [sId, sMetrics] of Object.entries(activeRun.byScenario)) {
        const meta = scenarioTiers[sId] || { tier: 'unknown', name: 'Scenario ' + sId };
        rowsHtml += `
          <tr>
            <td class="code-cell"><strong>${sId}</strong></td>
            <td><span class="tier-tag tier-${meta.tier}">${meta.tier}</span></td>
            <td>${meta.name}</td>
            <td style="font-family: var(--font-mono);">${sMetrics.samples}</td>
            <td style="font-family: var(--font-mono);">${sMetrics.tp}/${sMetrics.fp}/${sMetrics.fn}/${sMetrics.tn}</td>
            <td style="font-family: var(--font-mono);">${formatPct(sMetrics.recall)}</td>
            <td style="font-family: var(--font-mono);">${formatPct(sMetrics.falsePositiveRate)}</td>
            <td style="font-family: var(--font-mono);">${formatPct(sMetrics.enforcementSuccessRate)}</td>
            <td style="font-family: var(--font-mono);">${formatLatency(sMetrics.p50Ms)}</td>
          </tr>
        `;
      }

      table.innerHTML = `
        <thead>
          <tr>
            <th>Scenario</th>
            <th>Tier</th>
            <th>Description</th>
            <th>Samples</th>
            <th>TP/FP/FN/TN</th>
            <th>Recall</th>
            <th>FPR</th>
            <th>Enforcement</th>
            <th>P50 Latency</th>
          </tr>
        </thead>
        <tbody>${rowsHtml}</tbody>
      `;

      tableContainer.appendChild(table);
      scenarioPanel.appendChild(tableContainer);
      contentWrapper.appendChild(scenarioPanel);
    }
  }

  tabPhase2f.addEventListener('click', () => {
    currentSplit = 'phase2f-dev';
    tabPhase2f.classList.add('active');
    tabPhase2e.classList.remove('active');
    updateView();
  });

  tabPhase2e.addEventListener('click', () => {
    currentSplit = 'phase2e-holdout';
    tabPhase2e.classList.add('active');
    tabPhase2f.classList.remove('active');
    updateView();
  });

  updateView();
  return container;
}
