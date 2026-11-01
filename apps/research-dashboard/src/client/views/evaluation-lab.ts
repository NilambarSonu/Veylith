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

export interface Phase2aValidationViewData {
  datasetDescription: string;
  provenanceNotice: string;
  fixturePath: string;
  totalSamples: number;
  classificationSamples: number;
  groundTruth: {
    malicious: number;
    benign: number;
  };
  confusionMatrix: {
    tp: number;
    tn: number;
    fp: number;
    fn: number;
    totalClassified: number;
  };
  classSpecificMetrics: {
    attackPrecision: number;
    attackRecall: number;
    attackF1: number;
    benignPrecision: number;
    benignRecall: number;
    benignF1: number;
  };
  macroMetrics: {
    macroPrecision: number;
    macroRecall: number;
    macroF1: number;
    overallAccuracy: number;
  };
  stageBreakdown: Array<{
    stage: string;
    name: string;
    tp: number;
    fp: number;
    tn: number;
    fn: number;
    precision: number;
    recall: number;
    f1: number;
    deterministicBlocks: number;
    tier3Calls: number;
  }>;
  latency: {
    meanMs: number;
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
  };
  specialWarnings: Array<{ title: string; level: string; description: string }>;
}

export interface EvaluationLabData {
  phase2aValidation?: Phase2aValidationViewData;
  phase2fDevelopment: {
    datasetDescription: string;
    provenanceNotice: string;
    totalRecords?: number;
    scoredClassificationSamples?: number;
    excludedOperationalRecords?: number;
    excludedCaseIds?: string[];
    exclusionReason?: string;
    specialWarnings: Array<{ title: string; level: string; description: string }>;
    runs: EvaluationRunView[];
    beforeRuns?: EvaluationRunView[];
  };
  phase2eHoldout: {
    datasetDescription: string;
    provenanceNotice: string;
    totalRecords?: number;
    scoredClassificationSamples?: number;
    excludedOperationalRecords?: number;
    excludedCaseIds?: string[];
    exclusionReason?: string;
    specialWarnings: Array<{ title: string; level: string; description: string }>;
    runs: EvaluationRunView[];
  };
}

export function renderEvaluationLab(data: EvaluationLabData): HTMLElement {
  const container = el('div', { className: 'view-container' });

  // State: active tab ('phase2f-dev', 'phase2e-holdout', 'phase2a-val')
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
  const tabPhase2a = el('button', { className: 'tab-btn', id: 'tab-p2a' }, [
    'Phase 2A Internal Validation Fixture (68 Samples)',
  ]);
  tabsBar.appendChild(tabPhase2f);
  tabsBar.appendChild(tabPhase2e);
  tabsBar.appendChild(tabPhase2a);
  container.appendChild(tabsBar);

  // Dynamic View Wrapper
  const contentWrapper = el('div', { className: 'view-container' });
  container.appendChild(contentWrapper);

  function renderPhase2aView() {
    const p2a = data.phase2aValidation ?? {
      datasetDescription: 'Phase 2A Fixed Internal Validation Fixture (68 Samples)',
      provenanceNotice:
        'Fixed internal validation fixture (tests/fixtures/holdout-corpus.json: 32 malicious, 36 benign). Distinct from Phase 1 corpus but in-repo and accessible during development; NOT an independently blinded external benchmark.',
      fixturePath: 'tests/fixtures/holdout-corpus.json',
      totalSamples: 68,
      classificationSamples: 68,
      groundTruth: { malicious: 32, benign: 36 },
      confusionMatrix: { tp: 15, tn: 35, fp: 1, fn: 17, totalClassified: 68 },
      classSpecificMetrics: {
        attackPrecision: 0.938,
        attackRecall: 0.469,
        attackF1: 0.625,
        benignPrecision: 0.673,
        benignRecall: 0.972,
        benignF1: 0.795,
      },
      macroMetrics: {
        macroPrecision: 0.805,
        macroRecall: 0.72,
        macroF1: 0.71,
        overallAccuracy: 0.735,
      },
      stageBreakdown: [
        {
          stage: 'discovery',
          name: 'Stage 1: Discovery (tools/list)',
          tp: 2,
          fp: 0,
          tn: 12,
          fn: 6,
          precision: 1.0,
          recall: 0.25,
          f1: 0.4,
          deterministicBlocks: 2,
          tier3Calls: 18,
        },
        {
          stage: 'call_arguments',
          name: 'Stage 2: Call Arguments (tools/call)',
          tp: 6,
          fp: 1,
          tn: 11,
          fn: 6,
          precision: 0.857,
          recall: 0.5,
          f1: 0.632,
          deterministicBlocks: 6,
          tier3Calls: 18,
        },
        {
          stage: 'call_response',
          name: 'Stage 3: Call Response (tools/call outputs)',
          tp: 7,
          fp: 0,
          tn: 12,
          fn: 5,
          precision: 1.0,
          recall: 0.583,
          f1: 0.737,
          deterministicBlocks: 4,
          tier3Calls: 20,
        },
      ],
      latency: { meanMs: 0.61, p50Ms: 0.16, p95Ms: 1.23, p99Ms: 20.55 },
      specialWarnings: [],
    };

    // Header Panel
    const headerPanel = el('div', { className: 'panel-card' });
    headerPanel.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <div>
          <h2 class="panel-title" style="font-size: 17px;">Phase 2A Fixed Internal Validation Fixture (68 Samples)</h2>
          <p class="stat-sub" style="margin-top: 4px;">Fixture: <code>${p2a.fixturePath}</code> • 32 Malicious / 36 Benign Controls</p>
        </div>
        <span class="hero-tag">Verified Hybrid 3-Tier Pipeline</span>
      </div>
    `;
    contentWrapper.appendChild(headerPanel);

    // Callout: Honest Dataset Provenance
    const provCallout = el('div', { className: 'callout info' }, [
      el('div', { className: 'callout-title' }, [
        'Internal Validation Dataset — Not an External Blind Holdout',
      ]),
      el('div', { className: 'callout-desc' }, [
        'This 68-sample dataset is committed to the repository at ',
        el('code', {}, [p2a.fixturePath]),
        '. While completely disjoint from the initial Phase 1 corpus, it was available during subsequent development iterations and must NOT be described as an independently blinded external benchmark.',
      ]),
    ]);
    contentWrapper.appendChild(provCallout);

    // Callout: Threat Limitations
    const fnCallout = el('div', { className: 'callout warning' }, [
      el('div', { className: 'callout-title' }, [
        'Honest Threat Limitations: 17 False Negatives (46.9% Attack Recall)',
      ]),
      el('div', { className: 'callout-desc' }, [
        'Veylith safely catches direct destructive shell, SQL, and path traversals. However, complex multilingual directives (Spanish, Russian, Chinese, Arabic) and encoded payloads bypassed Stage 1/Stage 2 static rules, and mock semantic review fell back to fast paths. AI guardrails are defense-in-depth layers, not universal firewalls.',
      ]),
    ]);
    contentWrapper.appendChild(fnCallout);

    // Key Metrics Grid
    const statsGrid = el('div', { className: 'stats-grid' });
    statsGrid.innerHTML = `
      <div class="stat-card">
        <span class="stat-label">Attack-Class Precision</span>
        <span class="stat-value" style="color: var(--accent-primary);">93.8%</span>
        <span class="stat-sub">15 TP / 16 Total Flagged (FP=1)</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Attack-Class Recall</span>
        <span class="stat-value" style="color: var(--status-warning);">46.9%</span>
        <span class="stat-sub">15 TP / 32 Malicious (FN=17)</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Attack-Class F1 Score</span>
        <span class="stat-value" style="color: var(--status-info);">62.5%</span>
        <span class="stat-sub">Harmonic mean of attack P & R</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Benign Specificity</span>
        <span class="stat-value" style="color: var(--status-success);">97.2%</span>
        <span class="stat-sub">35 TN / 36 Benign Controls</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Macro Precision</span>
        <span class="stat-value" style="color: var(--accent-cyan);">80.5%</span>
        <span class="stat-sub">Unweighted mean across classes</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Macro Recall (Bal. Acc)</span>
        <span class="stat-value">72.0%</span>
        <span class="stat-sub">Balanced detection accuracy</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Macro F1 Score</span>
        <span class="stat-value">71.0%</span>
        <span class="stat-sub">Balanced harmonic score</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Overall Accuracy</span>
        <span class="stat-value" style="color: var(--status-success);">73.5%</span>
        <span class="stat-sub">50 Correct / 68 Total Samples</span>
      </div>
    `;
    contentWrapper.appendChild(statsGrid);

    // Confusion Matrix and SVG Bars
    const matrixCard = createConfusionMatrixCard({
      tp: p2a.confusionMatrix.tp,
      tn: p2a.confusionMatrix.tn,
      fp: p2a.confusionMatrix.fp,
      fn: p2a.confusionMatrix.fn,
      precision: p2a.classSpecificMetrics.attackPrecision,
      recall: p2a.classSpecificMetrics.attackRecall,
      fpr: 0.028,
      fnr: 0.531,
      accuracy: p2a.macroMetrics.overallAccuracy,
      totalClassified: p2a.totalSamples,
    });

    const barsCard = createMetricsComparisonSvg([
      {
        label: 'Attack Precision (Correctness of Blocks)',
        value: p2a.classSpecificMetrics.attackPrecision,
        color: 'var(--accent-secondary)',
      },
      {
        label: 'Attack Recall (Sensitivity)',
        value: p2a.classSpecificMetrics.attackRecall,
        color: 'var(--status-warning)',
      },
      {
        label: 'Benign Recall (Specificity)',
        value: p2a.classSpecificMetrics.benignRecall,
        color: 'var(--status-success)',
      },
      {
        label: 'Macro Precision',
        value: p2a.macroMetrics.macroPrecision,
        color: 'var(--accent-cyan)',
      },
      {
        label: 'Macro Recall',
        value: p2a.macroMetrics.macroRecall,
        color: 'var(--accent-primary)',
      },
      {
        label: 'Overall Accuracy',
        value: p2a.macroMetrics.overallAccuracy,
        color: 'var(--status-info)',
      },
    ]);

    const chartRow = el('div', {
      style:
        'display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 16px;',
    });
    chartRow.appendChild(matrixCard);
    chartRow.appendChild(barsCard);
    contentWrapper.appendChild(chartRow);

    // Per-Stage Breakdown Table
    const stagePanel = el('div', { className: 'panel-card' });
    stagePanel.innerHTML = `
      <div class="panel-header">
        <h3 class="panel-title">Per-Stage Protocol Inspection Breakdown</h3>
        <span class="stat-sub">Discovery • Call Arguments • Call Response</span>
      </div>
      <div class="data-table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Protocol Inspection Stage</th>
              <th>TP / FP / TN / FN</th>
              <th>Stage Precision</th>
              <th>Stage Recall</th>
              <th>Stage F1</th>
              <th>Tier 1 Blocks</th>
              <th>Tier 3 Reviews</th>
            </tr>
          </thead>
          <tbody>
            ${p2a.stageBreakdown
              .map(
                (s) => `
              <tr>
                <td style="font-weight: 600;">${s.name}</td>
                <td style="font-family: var(--font-mono);">${s.tp} / ${s.fp} / ${s.tn} / ${s.fn}</td>
                <td style="font-family: var(--font-mono);">${formatPct(s.precision)}</td>
                <td style="font-family: var(--font-mono);">${formatPct(s.recall)}</td>
                <td style="font-family: var(--font-mono);">${formatPct(s.f1)}</td>
                <td style="font-family: var(--font-mono);">${s.deterministicBlocks}</td>
                <td style="font-family: var(--font-mono);">${s.tier3Calls}</td>
              </tr>
            `,
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;
    contentWrapper.appendChild(stagePanel);
  }

  function updateView() {
    contentWrapper.innerHTML = '';

    if (currentSplit === 'phase2a-val') {
      renderPhase2aView();
      return;
    }

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

    // Denominator & Scored Samples Callout
    const denomCard = el('div', {
      className: 'callout info',
      style: 'display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;',
    });
    const totalCount = isPhase2f ? 72 : 56;
    const scoredCount = isPhase2f ? 68 : 50;
    const excludedCount = isPhase2f ? 4 : 6;
    const exclusionText = isPhase2f
      ? '4 operational-failure cases (VEY-2E-G3-01, VEY-2E-G3-03, VEY-2E-G3-05, VEY-2E-G3-07) testing transport/timeout faults have predicted: null and are excluded from binary classification scoring.'
      : '6 operational-failure cases (VEY-2E-X3-04, VEY-2E-X3-06, VEY-2E-G3-02, VEY-2E-G3-04, VEY-2E-G3-06, VEY-2E-G3-08) testing timeouts, network drops, and payload truncation have predicted: null (with X3-06 unsupported). Excluded from binary classification scoring per scripts/security-lab/report.ts line 5.';

    denomCard.innerHTML = `
      <div>
        <div class="callout-title">Dataset Size vs. Scored Samples Reconciliation</div>
        <div class="callout-desc" style="margin-top: 4px;">
          <strong>Total Records Evaluated: ${totalCount}</strong> | 
          <strong>Scored Classification Samples: ${scoredCount}</strong> | 
          <strong>Excluded Operational Stress Cases: ${excludedCount}</strong>
          <p style="margin-top: 4px; font-size: 11px; color: var(--text-muted);">${exclusionText}</p>
        </div>
      </div>
    `;
    contentWrapper.appendChild(denomCard);

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

      // Baseline vs Post-Remediation Comparison Table Panel
      const compPanel = el('div', { className: 'panel-card' });
      compPanel.innerHTML = `
        <div class="panel-header">
          <h3 class="panel-title">Phase 2F Remediation: Baseline vs. Post-Remediation Comparison (N=68 Scored)</h3>
          <span class="stat-sub">Strictly Separated Records</span>
        </div>
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Evaluation Stage / Mode</th>
                <th>TP / TN / FP / FN</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>False Positive Rate</th>
                <th>Accuracy</th>
                <th>Enforcement (N=72)</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style="font-weight: 600;">Phase 2E Baseline on Development Set (43afac2a)</td>
                <td class="code-cell">20 / 20 / 0 / 28</td>
                <td style="font-family: var(--font-mono);">100.0%</td>
                <td style="font-family: var(--font-mono); color: var(--status-warning);">41.7%</td>
                <td style="font-family: var(--font-mono);">0.0%</td>
                <td style="font-family: var(--font-mono);">58.8%</td>
                <td style="font-family: var(--font-mono);">45 / 72 (62.5%)</td>
              </tr>
              <tr>
                <td style="font-weight: 600;">Post-Remediation Deterministic (36fa6750)</td>
                <td class="code-cell">48 / 0 / 20 / 0</td>
                <td style="font-family: var(--font-mono);">70.6%</td>
                <td style="font-family: var(--font-mono); color: var(--status-success);">100.0%</td>
                <td style="font-family: var(--font-mono); color: var(--status-danger);">100.0% (Fail-Closed)</td>
                <td style="font-family: var(--font-mono);">70.6%</td>
                <td style="font-family: var(--font-mono);">50 / 72 (69.4%)</td>
              </tr>
              <tr>
                <td style="font-weight: 600;">Post-Remediation Mock-Semantic (36fa6750)</td>
                <td class="code-cell">25 / 20 / 0 / 23</td>
                <td style="font-family: var(--font-mono);">100.0%</td>
                <td style="font-family: var(--font-mono); color: var(--accent-primary);">52.1%</td>
                <td style="font-family: var(--font-mono);">0.0%</td>
                <td style="font-family: var(--font-mono);">66.2%</td>
                <td style="font-family: var(--font-mono);">50 / 72 (69.4%)</td>
              </tr>
            </tbody>
          </table>
        </div>
      `;
      contentWrapper.appendChild(compPanel);
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
      // Direct baseline notice
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
    tabPhase2a.classList.remove('active');
    updateView();
  });

  tabPhase2e.addEventListener('click', () => {
    currentSplit = 'phase2e-holdout';
    tabPhase2e.classList.add('active');
    tabPhase2f.classList.remove('active');
    tabPhase2a.classList.remove('active');
    updateView();
  });

  tabPhase2a.addEventListener('click', () => {
    currentSplit = 'phase2a-val';
    tabPhase2a.classList.add('active');
    tabPhase2f.classList.remove('active');
    tabPhase2e.classList.remove('active');
    updateView();
  });

  updateView();
  return container;
}
