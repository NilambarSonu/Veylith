import { formatPct, el } from './utils.js';

export interface ConfusionMatrixData {
  readonly tp: number;
  readonly tn: number;
  readonly fp: number;
  readonly fn: number;
  readonly precision: number | null;
  readonly recall: number | null;
  readonly fpr: number | null;
  readonly fnr: number | null;
  readonly accuracy: number | null;
  readonly totalClassified: number;
}

/**
 * Creates an interactive, accessible 2x2 confusion matrix card with real counts.
 */
export function createConfusionMatrixCard(data: ConfusionMatrixData): HTMLElement {
  const container = el('div', { className: 'panel-card' });

  const header = el('div', { className: 'panel-header' }, [
    el('h3', { className: 'panel-title' }, ['Classification Confusion Matrix']),
    el('span', { className: 'stat-sub' }, [`Classified Samples: ${data.totalClassified}`]),
  ]);
  container.appendChild(header);

  const matrixGrid = el('div', { className: 'matrix-grid' });

  // TP: Malicious -> Block
  const tpCell = el('div', { className: 'matrix-cell tp' }, [
    el('span', { className: 'matrix-title' }, ['True Positive (TP)']),
    el('span', { className: 'matrix-val' }, [String(data.tp)]),
    el('span', { className: 'matrix-rate' }, [`Recall: ${formatPct(data.recall)}`]),
    el('span', { className: 'stat-sub' }, ['Attack Blocked']),
  ]);

  // FP: Benign -> Block
  const fpCell = el('div', { className: 'matrix-cell fp' }, [
    el('span', { className: 'matrix-title' }, ['False Positive (FP)']),
    el('span', { className: 'matrix-val' }, [String(data.fp)]),
    el('span', { className: 'matrix-rate' }, [`FPR: ${formatPct(data.fpr)}`]),
    el('span', { className: 'stat-sub' }, ['Benign Blocked']),
  ]);

  // FN: Malicious -> Allow
  const fnCell = el('div', { className: 'matrix-cell fn' }, [
    el('span', { className: 'matrix-title' }, ['False Negative (FN)']),
    el('span', { className: 'matrix-val' }, [String(data.fn)]),
    el('span', { className: 'matrix-rate' }, [`FNR: ${formatPct(data.fnr)}`]),
    el('span', { className: 'stat-sub' }, ['Attack Missed']),
  ]);

  // TN: Benign -> Allow
  const tnCell = el('div', { className: 'matrix-cell tn' }, [
    el('span', { className: 'matrix-title' }, ['True Negative (TN)']),
    el('span', { className: 'matrix-val' }, [String(data.tn)]),
    el('span', { className: 'matrix-rate' }, [
      `Specificity: ${formatPct(data.fpr !== null ? 1 - data.fpr : null)}`,
    ]),
    el('span', { className: 'stat-sub' }, ['Benign Allowed']),
  ]);

  matrixGrid.appendChild(tpCell);
  matrixGrid.appendChild(fpCell);
  matrixGrid.appendChild(fnCell);
  matrixGrid.appendChild(tnCell);

  container.appendChild(matrixGrid);

  // Summary Metrics Footer
  const footerGrid = el('div', { className: 'stats-grid', style: 'margin-top: 16px;' }, [
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Precision']),
      el('span', { className: 'stat-value' }, [formatPct(data.precision)]),
      el('span', { className: 'stat-sub' }, ['TP / (TP + FP)']),
    ]),
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Recall / Detection Rate']),
      el('span', { className: 'stat-value' }, [formatPct(data.recall)]),
      el('span', { className: 'stat-sub' }, ['TP / (TP + FN)']),
    ]),
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['False Positive Rate']),
      el(
        'span',
        { className: 'stat-value', style: data.fpr === 1 ? 'color: var(--status-danger)' : '' },
        [formatPct(data.fpr)],
      ),
      el('span', { className: 'stat-sub' }, ['FP / (FP + TN)']),
    ]),
    el('div', { className: 'stat-card' }, [
      el('span', { className: 'stat-label' }, ['Classification Accuracy']),
      el('span', { className: 'stat-value' }, [formatPct(data.accuracy)]),
      el('span', { className: 'stat-sub' }, ['(TP + TN) / Total']),
    ]),
  ]);
  container.appendChild(footerGrid);

  return container;
}

/**
 * Creates clean SVG horizontal comparison bars for key metrics.
 */
export function createMetricsComparisonSvg(
  metrics: Array<{ label: string; value: number | null; color: string; sampleText?: string }>,
): HTMLElement {
  const container = el('div', { className: 'panel-card' });
  container.appendChild(
    el('div', { className: 'panel-header' }, [
      el('h3', { className: 'panel-title' }, ['Performance & Enforcement Rates']),
    ]),
  );

  const barList = el('div', { style: 'display: flex; flex-direction: column; gap: 14px;' });

  for (const m of metrics) {
    const row = el('div', { style: 'display: flex; flex-direction: column; gap: 4px;' });
    const labelRow = el(
      'div',
      { style: 'display: flex; justify-content: space-between; font-size: 12px;' },
      [
        el('span', { style: 'color: var(--text-muted); font-weight: 500;' }, [m.label]),
        el('span', { style: 'font-family: var(--font-mono); font-weight: 600;' }, [
          formatPct(m.value),
          m.sampleText ? ` (${m.sampleText})` : '',
        ]),
      ],
    );

    const pct =
      m.value !== null && !Number.isNaN(m.value) ? Math.min(100, Math.max(0, m.value * 100)) : 0;

    const track = el('div', {
      style:
        'width: 100%; height: 8px; background: var(--surface-elevated); border-radius: 4px; overflow: hidden; position: relative;',
    });
    const fill = el('div', {
      style: `width: ${pct}%; height: 100%; background: ${m.color}; border-radius: 4px; transition: width 0.3s ease;`,
    });
    track.appendChild(fill);

    row.appendChild(labelRow);
    row.appendChild(track);
    barList.appendChild(row);
  }

  container.appendChild(barList);
  return container;
}
