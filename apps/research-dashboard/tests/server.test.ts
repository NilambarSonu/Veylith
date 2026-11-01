import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import * as http from 'node:http';
import * as net from 'node:net';
import * as fs from 'node:fs';
import * as path from 'node:path';
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

  function makeRawSocketRequest(
    rawPayload: string,
  ): Promise<{ statusCode: number; headers: Record<string, string>; body: string }> {
    return new Promise((resolve, reject) => {
      const client = net.createConnection({ host: '127.0.0.1', port: serverPort }, () => {
        client.write(rawPayload);
      });

      let rawData = '';
      client.on('data', (chunk) => {
        rawData += chunk.toString('utf8');
      });

      client.on('end', () => {
        const headerEnd = rawData.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
          resolve({ statusCode: 0, headers: {}, body: rawData });
          return;
        }
        const headerPart = rawData.slice(0, headerEnd);
        const body = rawData.slice(headerEnd + 4);
        const lines = headerPart.split('\r\n');
        const statusLine = lines[0] ?? '';
        const statusMatch = statusLine.match(/HTTP\/1\.[01]\s+(\d{3})/);
        const statusCode = statusMatch ? parseInt(statusMatch[1]!, 10) : 0;
        const headers: Record<string, string> = {};
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i]!;
          const colon = line.indexOf(':');
          if (colon > 0) {
            headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
          }
        }
        resolve({ statusCode, headers, body });
      });

      client.on('error', reject);
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
    expect(json.metricsSummary!.workspaceTestsPassed).toBe(400);
    expect(json.metricsSummary!.workspaceTestsTotal).toBe(400);
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

    // Check Phase 2A Validation Data
    interface Phase2aValidationPayload {
      totalSamples: number;
      classSpecificMetrics: { attackPrecision: number };
      macroMetrics: { macroPrecision: number };
    }
    const p2a = (json as Record<string, unknown>).phase2aValidation as Phase2aValidationPayload;
    expect(p2a).toBeDefined();
    expect(p2a.totalSamples).toBe(68);
    expect(p2a.classSpecificMetrics.attackPrecision).toBeCloseTo(0.938, 2);
    expect(p2a.macroMetrics.macroPrecision).toBeCloseTo(0.805, 2);
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

  it('GET /api/audit ignores client-supplied raw parameter and guarantees redacted secrets', async () => {
    const res = await makeRequest('GET', '/api/audit?raw=true&caseId=VEY-2E-E1-01');
    expect(res.statusCode).toBe(200);

    const json = res.json!;
    expect(json.records).toBeDefined();
    expect(json.records!.length).toBeGreaterThan(0);
    for (const rec of json.records!) {
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

    it('rejects path traversal attempts on static file routes using raw unnormalized TCP sockets', async () => {
      // 1. Raw unnormalized ../
      const res1 = await makeRawSocketRequest(
        `GET /../../package.json HTTP/1.1\r\nHost: 127.0.0.1:${serverPort}\r\nConnection: close\r\n\r\n`,
      );
      expect(res1.statusCode).toBe(403);
      expect(res1.body).toContain('path traversal attempt');

      // 2. Encoded lowercase %2e%2e
      const res2 = await makeRawSocketRequest(
        `GET /%2e%2e/%2e%2e/package.json HTTP/1.1\r\nHost: 127.0.0.1:${serverPort}\r\nConnection: close\r\n\r\n`,
      );
      expect(res2.statusCode).toBe(403);
      expect(res2.body).toContain('path traversal attempt');

      // 3. Encoded uppercase %2E%2E
      const res3 = await makeRawSocketRequest(
        `GET /%2E%2E/%2E%2E/package.json HTTP/1.1\r\nHost: 127.0.0.1:${serverPort}\r\nConnection: close\r\n\r\n`,
      );
      expect(res3.statusCode).toBe(403);
      expect(res3.body).toContain('path traversal attempt');

      // 4. Encoded slash %2f
      const res4 = await makeRawSocketRequest(
        `GET /..%2f..%2fpackage.json HTTP/1.1\r\nHost: 127.0.0.1:${serverPort}\r\nConnection: close\r\n\r\n`,
      );
      expect(res4.statusCode).toBe(403);
      expect(res4.body).toContain('path traversal attempt');

      // 5. Encoded mixed dot: .%2e
      const res5 = await makeRawSocketRequest(
        `GET /.%2e/.%2e/package.json HTTP/1.1\r\nHost: 127.0.0.1:${serverPort}\r\nConnection: close\r\n\r\n`,
      );
      expect(res5.statusCode).toBe(403);
      expect(res5.body).toContain('path traversal attempt');

      // 6. Null byte injection %00
      const res6 = await makeRawSocketRequest(
        `GET /%00/package.json HTTP/1.1\r\nHost: 127.0.0.1:${serverPort}\r\nConnection: close\r\n\r\n`,
      );
      expect(res6.statusCode).toBe(403);
      expect(res6.body).toContain('path traversal attempt');

      // 7. Malformed percent encoding %99%zz
      const res7 = await makeRawSocketRequest(
        `GET /%99%zz/malformed HTTP/1.1\r\nHost: 127.0.0.1:${serverPort}\r\nConnection: close\r\n\r\n`,
      );
      expect(res7.statusCode).toBe(400);
      expect(res7.body).toContain('Malformed URL path');
    });

    it('rejects symlink traversal attempts outside static asset directory via fs.realpathSync', async () => {
      const projectRoot = process.cwd().endsWith('research-dashboard')
        ? path.resolve(process.cwd(), '../..')
        : process.cwd();
      const clientDistDir = path.resolve(
        projectRoot,
        'apps',
        'research-dashboard',
        'dist',
        'client',
      );
      fs.mkdirSync(clientDistDir, { recursive: true });
      const symlinkPath = path.join(clientDistDir, 'test-symlink-escape.txt');
      const targetFile = path.resolve(projectRoot, 'package.json');

      try {
        if (fs.existsSync(symlinkPath)) {
          fs.unlinkSync(symlinkPath);
        }
        fs.symlinkSync(targetFile, symlinkPath);

        const res = await makeRequest('GET', '/test-symlink-escape.txt');
        expect(res.statusCode).toBe(403);
        expect(res.json!.message).toContain('path traversal attempt via symlink');
      } finally {
        if (fs.existsSync(symlinkPath)) {
          fs.unlinkSync(symlinkPath);
        }
      }
    });
  });
});
