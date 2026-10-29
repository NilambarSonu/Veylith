import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import * as http from 'node:http';
import { startDashboardServer } from '../src/server/index.js';

interface TestHttpResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  json?: Record<string, unknown> & {
    product?: string;
    metricsSummary?: Record<string, number>;
    provenance?: Record<string, string>;
    totalScenarios?: number;
    byTier?: Record<string, unknown[]>;
    phase2fDevelopment?: {
      specialWarnings: Array<{ title: string; level: string; description: string }>;
      runs: Array<{ mode: string; metrics: Record<string, unknown> }>;
    };
    phase2eHoldout?: {
      runs: Array<{ split: string; metrics: Record<string, unknown> }>;
    };
    records?: Array<{
      sequenceNumber: number;
      previousEventHash: string;
      currentEventHash: string;
      sessionId?: string;
    }>;
    chainVerified?: boolean;
    unresolvedIssues?: unknown[];
    reservedLiveCandidates?: {
      status: string;
      count: number;
      cases: Array<{ status: string }>;
    };
    status?: string;
    readOnly?: boolean;
    error?: string;
  };
}

describe('Veylith Research Dashboard — Local HTTP Server & Read-Only API', () => {
  let serverInstance: Server;
  let serverUrl: string;
  let serverPort: number;

  beforeAll(async () => {
    // Port 19890 binds to a loopback port on 127.0.0.1
    const { server, port, url } = await startDashboardServer({ port: 19890 });
    serverInstance = server;
    serverPort = port;
    serverUrl = url;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      serverInstance.close(() => resolve());
    });
  });

  function makeRequest(
    method: string,
    path: string,
    headers: Record<string, string> = {},
  ): Promise<TestHttpResponse> {
    return new Promise((resolve, reject) => {
      const defaultHeaders = {
        host: `127.0.0.1:${serverPort}`,
        ...headers,
      };

      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: serverPort,
          path,
          method,
          headers: defaultHeaders,
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            let json: TestHttpResponse['json'] = undefined;
            try {
              json = JSON.parse(data);
            } catch {
              // Not JSON
            }
            resolve({
              statusCode: res.statusCode ?? 0,
              headers: res.headers,
              body: data,
              json,
            });
          });
        },
      );

      req.on('error', reject);
      req.end();
    });
  }

  it('verifies serverUrl binds to loopback 127.0.0.1', () => {
    expect(serverUrl).toBe(`http://127.0.0.1:${serverPort}`);
  });

  it('GET /api/overview returns 200 with complete evaluation summary and provenance', async () => {
    const res = await makeRequest('GET', '/api/overview');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');

    const json = res.json!;
    expect(json.product).toBe('Veylith — The AI Agent Security Boundary');
    expect(json.metricsSummary!.principalScenarios).toBe(14);
    expect(json.metricsSummary!.offlineVariants).toBe(112);
    expect(json.metricsSummary!.frozenHoldoutCount).toBe(56);
    expect(json.metricsSummary!.reservedLiveCandidates).toBe(6);
    expect(json.metricsSummary!.automatedTestsPassed).toBe(296);
    expect(json.metricsSummary!.phase2fTestsPassed).toBe(252);
    expect(json.metricsSummary!.reliabilityProbesPassed).toBe(13);
    expect(json.metricsSummary!.reliabilityProbesFailed).toBe(2);
    expect(json.provenance!.baseCommit).toBeDefined();
    expect(json.provenance!.evaluatedSourceCommit).toBeDefined();
  });

  it('GET /api/scenarios returns 200 with 14 principal scenarios grouped by tier', async () => {
    const res = await makeRequest('GET', '/api/scenarios');
    expect(res.statusCode).toBe(200);

    const json = res.json!;
    expect(json.totalScenarios).toBe(14);
    expect(json.byTier!.easy).toHaveLength(2);
    expect(json.byTier!.medium).toHaveLength(3);
    expect(json.byTier!.hard).toHaveLength(3);
    expect(json.byTier!['extremely-hard']).toHaveLength(3);
    expect(json.byTier!['god-level']).toHaveLength(3);
  });

  it('GET /api/evaluations returns 200 with strictly separated Phase 2E and Phase 2F datasets', async () => {
    const res = await makeRequest('GET', '/api/evaluations');
    expect(res.statusCode).toBe(200);

    const json = res.json!;
    // Check Phase 2F Development Comparison
    expect(json.phase2fDevelopment).toBeDefined();
    expect(json.phase2fDevelopment!.specialWarnings).toHaveLength(2);
    expect(json.phase2fDevelopment!.specialWarnings[0]!.title).toContain(
      '100% False Positive Rate',
    );

    const p2fDetRun = json.phase2fDevelopment!.runs.find((r) => r.mode === 'deterministic-only');
    expect(p2fDetRun!.metrics.fp).toBe(20);
    expect(p2fDetRun!.metrics.tn).toBe(0);

    // Check Phase 2E Frozen Holdout
    expect(json.phase2eHoldout).toBeDefined();
    expect(json.phase2eHoldout!.runs[0]!.split).toBe('holdout');
    expect(json.phase2eHoldout!.runs[0]!.metrics.samples).toBe(56);
  });

  it('GET /api/audit returns 200 with paginated, secret-redacted audit events', async () => {
    const res = await makeRequest('GET', '/api/audit?limit=10&page=1');
    expect(res.statusCode).toBe(200);

    const json = res.json!;
    expect(json.records).toBeDefined();
    expect(json.records!.length).toBeLessThanOrEqual(10);
    expect(json.chainVerified).toBe(true);

    if (json.records!.length > 0) {
      const rec = json.records![0]!;
      expect(rec.sequenceNumber).toBeDefined();
      expect(rec.previousEventHash).toBeDefined();
      expect(rec.currentEventHash).toBeDefined();
      // Ensure session ID is masked
      if (rec.sessionId) {
        expect(rec.sessionId).toContain('***');
      }
    }
  });

  it('GET /api/findings returns 200 with the 8 known unresolved issues and 6 locked live candidates', async () => {
    const res = await makeRequest('GET', '/api/findings');
    expect(res.statusCode).toBe(200);

    const json = res.json!;
    expect(json.unresolvedIssues).toHaveLength(8);

    const live = json.reservedLiveCandidates!;
    expect(live.status).toBe('Pending separate founder authorization');
    expect(live.count).toBe(6);
    expect(live.cases).toHaveLength(6);
    for (const c of live.cases) {
      expect(c.status).toBe('Locked / No Execution Allowed');
    }
  });

  it('GET /api/health returns 200 ok', async () => {
    const res = await makeRequest('GET', '/api/health');
    expect(res.statusCode).toBe(200);
    expect(res.json!.status).toBe('ok');
    expect(res.json!.readOnly).toBe(true);
  });

  it('GET / serves the dashboard HTML shell', async () => {
    const res = await makeRequest('GET', '/');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain('VEYLITH');
    expect(res.body).toContain('app.js');
  });

  describe('Strict Read-Only Enforcement (Mutations Disallowed)', () => {
    it('rejects POST /api/overview with 405 Method Not Allowed', async () => {
      const res = await makeRequest('POST', '/api/overview');
      expect(res.statusCode).toBe(405);
      expect(res.json!.error).toBe('Method Not Allowed');
    });

    it('rejects PUT /api/scenarios with 405 Method Not Allowed', async () => {
      const res = await makeRequest('PUT', '/api/scenarios');
      expect(res.statusCode).toBe(405);
      expect(res.json!.error).toBe('Method Not Allowed');
    });

    it('rejects DELETE /api/audit with 405 Method Not Allowed', async () => {
      const res = await makeRequest('DELETE', '/api/audit');
      expect(res.statusCode).toBe(405);
      expect(res.json!.error).toBe('Method Not Allowed');
    });
  });

  describe('Security Boundary Rejection', () => {
    it('rejects requests with spoofed external Host header', async () => {
      const res = await makeRequest('GET', '/api/health', {
        host: 'evil-phishing-site.com',
      });
      expect(res.statusCode).toBe(403);
      expect(res.json!.error).toBe('Forbidden');
    });

    it('rejects requests with credentials in Host header', async () => {
      const res = await makeRequest('GET', '/api/health', {
        host: `attacker:secret@127.0.0.1:${serverPort}`,
      });
      expect(res.statusCode).toBe(403);
      expect(res.json!.error).toBe('Forbidden');
    });

    it('rejects path traversal attempts on static file routes', async () => {
      const res1 = await makeRequest('GET', '/../../package.json');
      expect(res1.statusCode).toBe(403);
      expect(res1.json!.error).toBe('Forbidden');

      const res2 = await makeRequest('GET', '/%2e%2e/%2e%2e/package.json');
      expect(res2.statusCode).toBe(403);
      expect(res2.json!.error).toBe('Forbidden');

      const res3 = await makeRequest('GET', '/..%2f..%2fpackage.json');
      expect(res3.statusCode).toBe(403);
      expect(res3.json!.error).toBe('Forbidden');
    });
  });
});
