import type { IncomingMessage, ServerResponse } from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { EvidenceLoader } from './evidence-loader.js';
import type { DashboardConfig } from './config.js';
import { getSecurityHeaders, validateLoopbackAccess } from './security.js';

export function createRouter(config: DashboardConfig, loader: EvidenceLoader) {
  const clientDistDir = path.join(
    config.projectRoot,
    'apps',
    'research-dashboard',
    'dist',
    'client',
  );

  return function handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const headers = getSecurityHeaders();
    for (const [key, value] of Object.entries(headers)) {
      res.setHeader(key, value);
    }

    // Enforce strictly GET and HEAD methods (Read-Only)
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Method Not Allowed',
          message:
            'Veylith Research Dashboard is strictly read-only. No mutations or tool execution are permitted.',
        }),
      );
      return;
    }

    // Verify Loopback Boundary
    const accessCheck = validateLoopbackAccess(req, config.port);
    if (!accessCheck.allowed) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Forbidden',
          reason: accessCheck.reason ?? 'Local loopback security policy violated.',
        }),
      );
      return;
    }

    const rawUrl = req.url ?? '/';
    let safePathname: string;
    try {
      safePathname = decodeURIComponent(rawUrl.split('?')[0] ?? '/');
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad Request', message: 'Malformed URL path' }));
      return;
    }

    // Universal Path Traversal Guard: reject directory traversal attempts
    if (
      rawUrl.includes('..') ||
      rawUrl.toLowerCase().includes('%2e') ||
      rawUrl.toLowerCase().includes('%2f') ||
      rawUrl.includes('%00') ||
      safePathname.includes('..') ||
      safePathname.includes('\0')
    ) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Forbidden',
          message: 'Access denied: path traversal attempt',
        }),
      );
      return;
    }

    const reqUrl = new URL(req.url ?? '/', `http://${req.headers['host'] ?? '127.0.0.1'}`);
    const pathname = reqUrl.pathname;

    // --- API Endpoints ---

    if (pathname === '/api/overview') {
      try {
        const scenarios = loader.getScenarios();
        const manifest = loader.getManifest();
        const liveReserve = loader.getLiveCandidates();
        const reliability = loader.getReliabilityProbes();
        const gates = loader.getGates();

        const overview = {
          product: 'Veylith — The AI Agent Security Boundary',
          tagline: 'Local Security Research & Evaluation Dashboard',
          environment: {
            mode: 'local-research',
            binding: `127.0.0.1:${config.port}`,
            readOnly: true,
            authStatus: 'loopback-guarded (no production auth)',
            platform: process.platform,
            nodeVersion: process.version,
          },
          provenance: {
            baseCommit: '82b492a5d8c8ae54d2b7974df342e976914a7c49',
            evaluatedSourceCommit: '36fa675051f85437db55a5ccfff6ce18b7791392',
            phase2fArchiveCommit: '8cdd2a647acf2f31b6ca766e83f7531e68ce2046',
            phase3DashboardCommit: '0650d233337de0200f22bcd21ada28d08923afac',
            manifestSha256: '2270b7052e864a84ec28f38fbd15eeed1ccb50447e0ce934de0d508f2337d89c',
            targetBranchSnapshot: 'dev/phase-5d-live-validation',
            workingTreeStatus: 'dev/phase-5d-live-validation (recorded snapshot)',
          },
          metricsSummary: {
            principalScenarios: scenarios.length,
            offlineVariants: manifest.offlineVariants,
            generatedG1Variants: 16,
            evaluatedDevelopmentSamples: 72,
            totalDatasetVariants: 128,
            frozenHoldoutCount: manifest.holdoutCount,
            reservedLiveCandidates: liveReserve.length,
            totalStoredCandidateInputs: 134,
            phase2fTestsPassed: 252,
            automatedTestsPassed: 296,
            automatedTestsTotal: 296,
            workspaceTestsPassed: 408,
            workspaceTestsTotal: 408,
            workspaceTestFiles: 43,
            lastVerifiedTestRun: '408 tests, 43 files (100% passing)',
            reliabilityProbesPassed: reliability.passedCount,
            reliabilityProbesTotal: reliability.totalCount,
            reliabilityProbesFailed: reliability.failedCount,
            failedReliabilityProbes: reliability.probes.filter((p) => !p.passed),
          },
          phase5dSummary: {
            provider: 'fireworks',
            model: 'accounts/fireworks/models/muse-spark-open',
            datasetCases: 100,
            datasetSha256: '97383d1180b217130b270c9429dd94e5f6af752e4e92b14f12dfd5326c04df62',
            attackRecall: 1.0,
            clearlyBenignFpr: 0.0,
            ambiguousAllowed: 15,
            overallAccuracy: 0.85,
            dispatchedRequests: 91,
            fastPathRequests: 9,
            totalTokens: 82312,
            actualSpendUsd: 0.169359,
            budgetLimitUsd: 2.0,
            p50LatencyMs: 7377.15,
            p95LatencyMs: 14154.43,
            provenanceNotice:
              'Empirical evaluation of real Fireworks model inference on the frozen 100-case synthetic validation benchmark (SHA-256: 97383d11...). Not an evaluation of open-ended production MCP traffic.',
          },
          qualityGates: gates,
          badges: [
            { label: 'Evaluation Status', value: 'Live Fireworks & Mock Evaluated', type: 'info' },
            { label: 'Workspace Tests', value: '408 / 408 Passed (100%)', type: 'success' },
            {
              label: 'Phase 5D Live Validation',
              value: '100% Recall • 0% Benign FPR ($0.169)',
              type: 'success',
            },
            {
              label: 'Inherited Reliability',
              value: '13 / 15 Passed (2 Known Failures)',
              type: 'warning',
            },
            { label: 'Frozen Holdout', value: '56 Cases (Procedural Holdout)', type: 'neutral' },
            {
              label: 'Live Meta API',
              value: '6 Reserved Candidates (Founder Auth Req)',
              type: 'locked',
            },
            { label: 'Environment', value: 'Local-Only • Non-Production', type: 'danger' },
          ],
        };

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(overview, null, 2));
      } catch (err: unknown) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Failed to load overview data',
            details: err instanceof Error ? err.message : String(err),
          }),
        );
      }
      return;
    }

    if (pathname === '/api/scenarios') {
      try {
        const scenarios = loader.getScenarios();
        const tierGrouping: Record<string, typeof scenarios> = {
          easy: [],
          medium: [],
          hard: [],
          'extremely-hard': [],
          'god-level': [],
        };
        for (const s of scenarios) {
          if (!tierGrouping[s.tier]) tierGrouping[s.tier] = [];
          tierGrouping[s.tier]!.push(s);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify(
            {
              scenarios,
              byTier: tierGrouping,
              totalScenarios: scenarios.length,
              totalVariants: scenarios.reduce((acc, s) => acc + s.variants, 0),
            },
            null,
            2,
          ),
        );
      } catch (err: unknown) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Failed to load scenarios',
            details: err instanceof Error ? err.message : String(err),
          }),
        );
      }
      return;
    }

    if (pathname === '/api/evaluations') {
      try {
        const phase2aValidation = loader.getPhase2aValidationData();
        const phase2fDev = loader.getPhase2fDevelopmentComparison();
        const phase2eHoldout = loader.getPhase2eHoldoutRuns();
        const phase5dLive = loader.getPhase5dResults();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify(
            {
              phase5dLive,
              phase2aValidation,
              phase2fDevelopment: {
                datasetDescription:
                  'Phase 2F Development Set (72 samples: 56 core + 16 generated G1)',
                provenanceNotice:
                  'Evaluation performed on development variants after Phase 2F boundary remediation.',
                totalRecords: 72,
                scoredClassificationSamples: 68,
                excludedOperationalRecords: 4,
                excludedCaseIds: ['VEY-2E-G3-01', 'VEY-2E-G3-03', 'VEY-2E-G3-05', 'VEY-2E-G3-07'],
                exclusionReason:
                  'Operational-failure cases have predicted: null (with G3-03 marked unsupported) and are excluded from binary classification scoring.',
                specialWarnings: [
                  {
                    title: 'Deterministic-Only Mode 100% False Positive Rate',
                    level: 'critical',
                    description:
                      'Phase 2F deterministic-only mode blocked all 20 benign cases (FP=20, TN=0). Its 100% recall is accompanied by a 100% false-positive rate, sacrificing availability to eliminate false negatives.',
                  },
                  {
                    title: 'Mock Semantic Accuracy Does Not Measure Real Model',
                    level: 'warning',
                    description:
                      'Phase 2F mock-semantic recall was 52.1% (TP=25, FN=23). Mock classifications use synthetic heuristic rules and do NOT demonstrate real Meta Muse LLM accuracy.',
                  },
                ],
                runs: phase2fDev.afterRuns,
                beforeRuns: phase2fDev.beforeRuns,
              },
              phase2eHoldout: {
                datasetDescription: 'Phase 2E Frozen Holdout Benchmark (56 cases)',
                provenanceNotice:
                  'Frozen prior to evaluation at commit 1086aef. Procedural holdout; not an independently blinded third-party benchmark.',
                totalRecords: 56,
                scoredClassificationSamples: 50,
                excludedOperationalRecords: 6,
                excludedCaseIds: [
                  'VEY-2E-X3-04',
                  'VEY-2E-X3-06',
                  'VEY-2E-G3-02',
                  'VEY-2E-G3-04',
                  'VEY-2E-G3-06',
                  'VEY-2E-G3-08',
                ],
                exclusionReason:
                  'Operational-failure cases (testing timeouts, network drops, and payload truncation) have predicted: null (with X3-06 marked unsupported). Per scripts/security-lab/report.ts line 5, they are excluded from binary classification scoring to prevent network transport faults from distorting threat detection metrics.',
                specialWarnings: [
                  {
                    title: 'Procedural Holdout Dataset Provenance',
                    level: 'info',
                    description:
                      'The Phase 2E holdout was frozen procedurally prior to evaluation. It preserves historical benchmark separation and was never retrained or reused for development tuning.',
                  },
                ],
                runs: phase2eHoldout,
              },
            },
            null,
            2,
          ),
        );
      } catch (err: unknown) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Failed to load evaluations',
            details: err instanceof Error ? err.message : String(err),
          }),
        );
      }
      return;
    }

    if (pathname === '/api/audit') {
      try {
        const source = reqUrl.searchParams.get('source') ?? 'phase-2f-mock-semantic';
        const page = Number.parseInt(reqUrl.searchParams.get('page') ?? '1', 10);
        const limit = Number.parseInt(reqUrl.searchParams.get('limit') ?? '25', 10);
        const decision = reqUrl.searchParams.get('decision') ?? 'all';
        const stage = reqUrl.searchParams.get('stage') ?? 'all';
        const method = reqUrl.searchParams.get('method') ?? 'all';
        const search = reqUrl.searchParams.get('search') ?? '';

        const auditData = loader.getAuditRecords({
          source,
          page,
          limit,
          decision,
          stage,
          method,
          search,
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(auditData, null, 2));
      } catch (err: unknown) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Failed to load audit records',
            details: err instanceof Error ? err.message : String(err),
          }),
        );
      }
      return;
    }

    if (pathname === '/api/findings') {
      try {
        const findings = loader.getSecurityFindings();
        const liveReserve = loader.getLiveCandidates();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify(
            {
              unresolvedIssues: findings,
              reservedLiveCandidates: {
                status: 'Pending separate founder authorization',
                count: liveReserve.length,
                cases: liveReserve.map((c) => ({
                  id: c.id,
                  scenarioId: c.scenarioId,
                  stage: c.stage,
                  inputPreview: typeof c.input === 'string' ? c.input : c.input[0],
                  expectedSecurityDecision: c.expectedSecurityDecision,
                  status: 'Locked / No Execution Allowed',
                })),
                instructions:
                  'These 6 reserved cases are held back for manual founder-authorized live Meta Muse API validation. No automated or background live requests are executed by this research dashboard.',
              },
            },
            null,
            2,
          ),
        );
      } catch (err: unknown) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Failed to load findings',
            details: err instanceof Error ? err.message : String(err),
          }),
        );
      }
      return;
    }

    if (pathname === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          mode: 'local-research-dashboard',
          readOnly: true,
          uptimeSeconds: Math.round(process.uptime()),
        }),
      );
      return;
    }

    // --- Static Asset Serving ---

    if (pathname === '/favicon.svg') {
      res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
      res.end(
        `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none">
          <path d="M16 2L4 7v9c0 8 5.12 13.12 12 14 6.88-.88 12-6 12-14V7L16 2z" fill="#0A1120" stroke="#38bdf8" stroke-width="2"/>
          <path d="M16 8l-6 6 1.41 1.41L16 10.83l4.59 4.58L22 14l-6-6z" fill="#38bdf8"/>
        </svg>`,
      );
      return;
    }

    const resolvedDistDir = path.resolve(clientDistDir);
    const relPath = safePathname === '/' ? 'index.html' : safePathname.replace(/^\/+/, '');
    const resolvedPath = path.resolve(resolvedDistDir, relPath);

    // Confinement check: resolvedPath MUST be strictly within resolvedDistDir
    if (resolvedPath !== resolvedDistDir && !resolvedPath.startsWith(resolvedDistDir + path.sep)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Forbidden',
          message: 'Access denied: path traversal attempt',
        }),
      );
      return;
    }

    // If client build file exists, serve it
    if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isFile()) {
      // Symlink confinement check: verify actual target on disk is confined to resolvedDistDir
      try {
        const realTarget = fs.realpathSync(resolvedPath);
        const realDistDir = fs.realpathSync(resolvedDistDir);
        if (realTarget !== realDistDir && !realTarget.startsWith(realDistDir + path.sep)) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'Forbidden',
              message: 'Access denied: path traversal attempt via symlink',
            }),
          );
          return;
        }
      } catch {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Forbidden',
            message: 'Access denied: unable to resolve file target',
          }),
        );
        return;
      }

      const ext = path.extname(resolvedPath);
      let contentType = 'text/plain';
      if (ext === '.html') contentType = 'text/html; charset=utf-8';
      else if (ext === '.js') contentType = 'application/javascript; charset=utf-8';
      else if (ext === '.css') contentType = 'text/css; charset=utf-8';
      else if (ext === '.json') contentType = 'application/json';
      else if (ext === '.svg') contentType = 'image/svg+xml';

      res.writeHead(200, { 'Content-Type': contentType });
      fs.createReadStream(resolvedPath).pipe(res);
      return;
    }

    // Fallback for SPA routing: serve index.html
    const indexHtmlPath = path.join(resolvedDistDir, 'index.html');
    if (fs.existsSync(indexHtmlPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(indexHtmlPath).pipe(res);
      return;
    }

    // Default 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found', path: pathname }));
  };
}
