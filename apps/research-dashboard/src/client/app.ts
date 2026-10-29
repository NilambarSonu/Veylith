import { renderOverview, type OverviewViewData } from './views/overview.js';
import { renderEvaluationLab, type EvaluationLabData } from './views/evaluation-lab.js';
import { renderAuditExplorer, type AuditExplorerData } from './views/audit-explorer.js';
import {
  renderSecurityFindings,
  type SecurityFindingsViewData,
} from './views/security-findings.js';

interface DashboardState {
  overview: OverviewViewData | null;
  evaluations: EvaluationLabData | null;
  audit: AuditExplorerData | null;
  findings: SecurityFindingsViewData | null;
  activeRoute: string;
}

const state: DashboardState = {
  overview: null,
  evaluations: null,
  audit: null,
  findings: null,
  activeRoute: 'overview',
};

async function fetchJson<T>(endpoint: string): Promise<T> {
  const res = await fetch(endpoint, {
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({ error: 'Network error' }))) as {
      details?: string;
      message?: string;
    };
    throw new Error(
      err.details || err.message || `Failed to fetch ${endpoint} (HTTP ${res.status})`,
    );
  }
  return res.json() as Promise<T>;
}

function updateNavigation(route: string): void {
  const routes = ['overview', 'evaluation-lab', 'audit-explorer', 'security-findings'];
  for (const r of routes) {
    const navEl = document.getElementById(`nav-${r}`);
    if (navEl) {
      if (r === route) {
        navEl.classList.add('active');
      } else {
        navEl.classList.remove('active');
      }
    }
  }

  const pageTitle = document.getElementById('page-title');
  const breadcrumbs = document.getElementById('breadcrumbs');
  if (pageTitle && breadcrumbs) {
    switch (route) {
      case 'overview':
        pageTitle.textContent = 'Project Overview';
        breadcrumbs.textContent = 'Evidence Baseline • 14 Scenarios • 252 Tests Verified';
        break;
      case 'evaluation-lab':
        pageTitle.textContent = 'Evaluation Lab';
        breadcrumbs.textContent = 'Phase 2F Development Comparison • Phase 2E Frozen Holdout';
        break;
      case 'audit-explorer':
        pageTitle.textContent = 'Audit Explorer';
        breadcrumbs.textContent = 'Cryptographic SHA-256 Event Chain • Secret Redacted';
        break;
      case 'security-findings':
        pageTitle.textContent = 'Security Findings';
        breadcrumbs.textContent = '8 Open Vulnerabilities • 6 Reserved Live Muse Candidates';
        break;
    }
  }
}

async function renderCurrentView(): Promise<void> {
  const contentEl = document.getElementById('app-content');
  if (!contentEl) return;

  const hash = window.location.hash.replace('#', '') || 'overview';
  state.activeRoute = hash;
  updateNavigation(hash);

  contentEl.innerHTML = `
    <div class="loading-state">
      <div class="spinner"></div>
      <p>Loading local evidence data...</p>
    </div>
  `;

  try {
    switch (hash) {
      case 'overview': {
        if (!state.overview) {
          state.overview = await fetchJson<OverviewViewData>('/api/overview');
        }
        contentEl.innerHTML = '';
        contentEl.appendChild(renderOverview(state.overview));
        break;
      }
      case 'evaluation-lab': {
        if (!state.evaluations) {
          state.evaluations = await fetchJson<EvaluationLabData>('/api/evaluations');
        }
        contentEl.innerHTML = '';
        contentEl.appendChild(renderEvaluationLab(state.evaluations));
        break;
      }
      case 'audit-explorer': {
        if (!state.audit) {
          state.audit = await fetchJson<AuditExplorerData>('/api/audit');
        }
        contentEl.innerHTML = '';
        contentEl.appendChild(
          renderAuditExplorer(state.audit, async (query: string) => {
            return fetchJson<AuditExplorerData>(`/api/audit?${query}`);
          }),
        );
        break;
      }
      case 'security-findings': {
        if (!state.findings) {
          state.findings = await fetchJson<SecurityFindingsViewData>('/api/findings');
        }
        contentEl.innerHTML = '';
        contentEl.appendChild(renderSecurityFindings(state.findings));
        break;
      }
      default: {
        window.location.hash = '#overview';
        break;
      }
    }
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    contentEl.innerHTML = `
      <div class="error-state">
        <h3 style="color: var(--status-danger);">Failed to load view</h3>
        <p style="font-size: 13px; color: var(--text-muted); max-width: 500px;">${errorMsg}</p>
        <button class="btn-refresh" style="margin-top: 12px;" onclick="window.location.reload()">Retry</button>
      </div>
    `;
  }
}

// Global initialization
window.addEventListener('DOMContentLoaded', () => {
  // Listen for hash changes
  window.addEventListener('hashchange', () => {
    renderCurrentView();
  });

  // Refresh button
  const btnRefresh = document.getElementById('btn-refresh');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', async () => {
      state.overview = null;
      state.evaluations = null;
      state.audit = null;
      state.findings = null;
      await renderCurrentView();
    });
  }

  // Keyboard navigation shortcuts (1, 2, 3, 4, r)
  window.addEventListener('keydown', (e: KeyboardEvent) => {
    // Avoid triggering when user is typing in search input
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) {
      return;
    }
    if (e.key === '1') window.location.hash = '#overview';
    else if (e.key === '2') window.location.hash = '#evaluation-lab';
    else if (e.key === '3') window.location.hash = '#audit-explorer';
    else if (e.key === '4') window.location.hash = '#security-findings';
    else if (e.key === 'r' || e.key === 'R') {
      const btn = document.getElementById('btn-refresh');
      btn?.click();
    }
  });

  // Initial render
  renderCurrentView();
});
