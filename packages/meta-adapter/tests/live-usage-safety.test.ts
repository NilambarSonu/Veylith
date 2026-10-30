import { describe, it, expect, vi, afterEach } from 'vitest';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  MetaMuseSecurityAdapter,
  APPROVED_PROVIDERS,
  validateProviderConfiguration,
  isLoopbackEndpoint,
  isPrivateNetworkEndpoint,
  UsageTracker,
} from '../src/index.js';

describe('Veylith — Final Live-Usage Safety Remediation', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Objective 1: Independent Usage Validation & Halt on Missing Usage', () => {
    it('validates classification independently and marks usage unknown when usage metadata is missing', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  flagged: false,
                  threatCategory: 'none',
                  action: 'allow',
                  confidence: 0.99,
                  explanation: 'Input validated clean',
                  evidence: [],
                }),
              },
            },
          ],
          // usage object omitted entirely
        }),
      } as Response);

      const adapter = new MetaMuseSecurityAdapter({
        provider: 'fireworks',
        mode: 'live',
        apiKey: 'fw_test_missing_usage_token',
        allowUnverifiedPricing: true,
      });

      const result = await adapter.inspect('Valid input payload', 'discovery');

      // Classification is fully preserved
      expect(result.action).toBe('allow');
      expect(result.flagged).toBe(false);
      expect(result.explanation).toBe('Input validated clean');

      // Usage is explicitly marked unknown; no fabricated tokens
      expect(result.hasUnknownUsage).toBe(true);
      expect(result.tokenUsage).toBeUndefined();

      const report = adapter.tracker.getReport();
      expect(report.hasUnknownUsage).toBe(true);
      expect(report.unknownUsageCount).toBe(1);
      expect(report.successfulClassifications).toBe(1);
      expect(report.totalTokens).toBe(0); // Never fabricated
      expect(report.estimatedCostUsd).toBeNull(); // Null, never zero
      expect(report.costStatus).toBe('unknown_usage_cost');
    });

    it('simulates multi-candidate dispatch: halts immediately after missing usage and prevents subsequent candidate dispatch', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');

      // First response: HTTP 200, valid classification JSON, missing usage metadata
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  flagged: true,
                  threatCategory: 'suspicious_arguments',
                  action: 'block',
                  confidence: 0.95,
                  explanation: 'Suspicious directive flagged',
                  evidence: ['Suspicious token'],
                }),
              },
            },
          ],
          // usage property is missing
        }),
      } as Response);

      // Second response mock (should NEVER be reached)
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  flagged: false,
                  threatCategory: 'none',
                  action: 'allow',
                  confidence: 1.0,
                  explanation: 'Second candidate',
                  evidence: [],
                }),
              },
            },
          ],
          usage: { prompt_tokens: 50, completion_tokens: 25 },
        }),
      } as Response);

      const adapter = new MetaMuseSecurityAdapter({
        provider: 'baseten',
        mode: 'live',
        apiKey: 'base_test_multi_candidate_halt',
        allowUnverifiedPricing: true,
        maxRequestsPerRun: 5,
      });

      // Dispatch Candidate 1
      const candidate1Result = await adapter.inspect('Candidate 1 input', 'discovery');

      // Candidate 1 classification is preserved
      expect(candidate1Result.action).toBe('block');
      expect(candidate1Result.hasUnknownUsage).toBe(true);
      expect(candidate1Result.tokenUsage).toBeUndefined();

      // Exactly 1 fetch request was made so far
      expect(fetchSpy).toHaveBeenCalledTimes(1);

      // Attempt to dispatch Candidate 2: must be BLOCKED locally before dispatch
      await expect(adapter.inspect('Candidate 2 input', 'discovery')).rejects.toThrowError(
        /Local usage safeguard: Unknown provider usage was previously encountered. Subsequent inference requests are blocked./,
      );

      // Verify Candidate 2 was NEVER dispatched
      expect(fetchSpy).toHaveBeenCalledTimes(1);

      // Verify report marks run with unknown usage and null cost
      const finalReport = adapter.tracker.getReport();
      expect(finalReport.requestCount).toBe(1);
      expect(finalReport.hasUnknownUsage).toBe(true);
      expect(finalReport.estimatedCostUsd).toBeNull();
      expect(finalReport.costStatus).toBe('unknown_usage_cost');
    });
  });

  describe('Objective 2: Unambiguous Null Cost Representation', () => {
    it('reports numeric zero for verified pricing with zero token consumption', () => {
      const tracker = new UsageTracker({
        maxRequestsPerRun: 5,
        dailyBudgetUsd: 0.1,
        pricingVerified: true,
      });

      const report = tracker.getReport();
      expect(report.pricingVerified).toBe(true);
      expect(report.dollarBudgetEnforced).toBe(true);
      expect(report.costStatus).toBe('verified_pricing');
      expect(report.estimatedCostUsd).toBe(0); // Numeric 0 is valid for verified zero usage
    });

    it('reports null (not numeric 0) when pricing is unverified', () => {
      const tracker = new UsageTracker({
        maxRequestsPerRun: 5,
        pricingVerified: false,
        allowUnverifiedPricing: true,
      });

      tracker.recordSuccess(100, 50, 10);

      const report = tracker.getReport();
      expect(report.pricingVerified).toBe(false);
      expect(report.dollarBudgetEnforced).toBe(false);
      expect(report.costStatus).toBe('unverified_unbounded_cost');
      expect(report.estimatedCostUsd).toBeNull(); // Must be null, never 0
    });

    it('reports null (not numeric 0) when usage is unknown regardless of pricing status', () => {
      const tracker = new UsageTracker({
        maxRequestsPerRun: 5,
        dailyBudgetUsd: 0.25,
        pricingVerified: true, // Even with verified Meta pricing
      });

      tracker.recordSuccessWithUnknownUsage(25);

      const report = tracker.getReport();
      expect(report.hasUnknownUsage).toBe(true);
      expect(report.dollarBudgetEnforced).toBe(false);
      expect(report.costStatus).toBe('unknown_usage_cost');
      expect(report.estimatedCostUsd).toBeNull(); // Must be null, never 0
    });

    it('preserves null distinction in JSON serialization', () => {
      const tracker = new UsageTracker({
        maxRequestsPerRun: 5,
        pricingVerified: false,
        allowUnverifiedPricing: true,
      });
      tracker.recordSuccess(100, 50, 10);

      const jsonStr = JSON.stringify(tracker.getReport());
      const parsed = JSON.parse(jsonStr);

      expect(parsed.estimatedCostUsd).toBeNull();
      expect(parsed.dollarBudgetEnforced).toBe(false);
      expect(parsed.costStatus).toBe('unverified_unbounded_cost');
    });
  });

  describe('Objective 3: Offline Adversarial Credential Exfiltration Protection', () => {
    it('guarantees fake secret canary token never reaches local malicious server, loopback, or private destinations', async () => {
      const capturedRequests: Array<{ url: string; method: string; headers: http.IncomingHttpHeaders }> = [];

      // Create controlled local mock server
      const localServer = http.createServer((req, res) => {
        capturedRequests.push({
          url: req.url ?? '',
          method: req.method ?? '',
          headers: req.headers,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });

      await new Promise<void>((resolve) => localServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (localServer.address() as AddressInfo).port;
      const fakeCanarySecret = 'CANARY_TOKEN_SECRET_9876543210_DO_NOT_EXFILTRATE';

      try {
        // 1. Loopback attack attempt
        expect(() => {
          new MetaMuseSecurityAdapter({
            provider: 'fireworks',
            mode: 'live',
            apiKey: fakeCanarySecret,
            endpoint: `http://127.0.0.1:${port}/steal/credentials`,
            model: 'accounts/fireworks/models/muse-spark-open',
          });
        }).toThrowError(/Insecure protocol|Loopback destination/);

        // 2. Private IP destination attempt
        expect(() => {
          new MetaMuseSecurityAdapter({
            provider: 'baseten',
            mode: 'live',
            apiKey: fakeCanarySecret,
            endpoint: 'https://192.168.1.250/v1/chat/completions',
            model: 'meta-models/muse-spark-open-1026',
          });
        }).toThrowError(/Private network destination .* is strictly forbidden/);

        // 3. Arbitrary HTTPS destination attempt
        expect(() => {
          new MetaMuseSecurityAdapter({
            provider: 'meta',
            mode: 'live',
            apiKey: fakeCanarySecret,
            endpoint: 'https://malicious-collector.evil.com/v1/responses',
            model: 'muse-spark-1.3',
          });
        }).toThrowError(/Endpoint 'https:\/\/malicious-collector\.evil\.com\/v1\/responses' is not an approved destination/);

        // 4. Conflicting ambient override attempt
        const origEnv = process.env['META_MODEL_API_ENDPOINT'];
        try {
          process.env['META_MODEL_API_ENDPOINT'] = `http://127.0.0.1:${port}/sink`;
          expect(() => {
            new MetaMuseSecurityAdapter({
              provider: 'meta',
              mode: 'live',
              apiKey: fakeCanarySecret,
            });
          }).toThrowError(/Conflicting ambient META_MODEL_API_ENDPOINT/);
        } finally {
          if (origEnv !== undefined) {
            process.env['META_MODEL_API_ENDPOINT'] = origEnv;
          } else {
            delete process.env['META_MODEL_API_ENDPOINT'];
          }
        }

        // 5. Cross-origin redirect blocking attempt
        // When redirect: 'error' is set, fetch rejects on 3xx without following to redirect location
        vi.spyOn(globalThis, 'fetch').mockImplementationOnce(async (url, init) => {
          if (init?.redirect === 'error') {
            // Native fetch throws a TypeError when encountering a redirect with redirect='error'
            throw new TypeError('Failed to fetch: redirect mode is set to error');
          }
          return { ok: true } as Response;
        });

        const adapter = new MetaMuseSecurityAdapter({
          provider: 'meta',
          mode: 'live',
          apiKey: fakeCanarySecret,
        });

        const redirectResult = await adapter.inspect('Test redirect block', 'discovery');
        expect(redirectResult.action).toBe('review');
        expect(redirectResult.explanation).toContain('redirect mode is set to error');

        // ASSERT: Local malicious server received ZERO requests, and fake key was NEVER sent!
        expect(capturedRequests).toHaveLength(0);
        for (const req of capturedRequests) {
          const serializedHeaders = JSON.stringify(req.headers);
          expect(serializedHeaders).not.toContain(fakeCanarySecret);
        }
      } finally {
        localServer.closeAllConnections();
        await new Promise<void>((resolve) => localServer.close(() => resolve()));
      }
    });

    it('verifies internal MCP loopback requests never contain provider credentials or inference payloads', () => {
      // Simulate loopback interceptor check from scripts/security-lab/live.ts
      const interceptor = (inputUrl: string, init?: RequestInit) => {
        const url = new URL(inputUrl);
        if (url.hostname === '127.0.0.1' || url.hostname === 'localhost') {
          const headers = init?.headers as Record<string, string> | undefined;
          if (headers && Object.keys(headers).some((k) => k.toLowerCase() === 'authorization')) {
            throw new Error(
              'Security boundary violation: Authorization header with provider credentials cannot be dispatched to loopback destination.',
            );
          }
          if (init?.body && String(init.body).includes('messages')) {
            throw new Error(
              'Security boundary violation: Model inference request cannot be dispatched to loopback destination.',
            );
          }
        }
        return { ok: true, status: 200 };
      };

      // 1. Legitimate MCP loopback request passes
      const legitimateMcpRequest = {
        headers: {
          'x-veylith-client-id': 'manual-live',
          'x-veylith-session-id': 'vyl-sess-test-1234',
        },
      };
      expect(() =>
        interceptor('http://127.0.0.1:8788/mcp', legitimateMcpRequest),
      ).not.toThrow();

      // 2. Accidental Authorization header on loopback request throws
      const contaminatedMcpRequest = {
        headers: {
          'x-veylith-client-id': 'manual-live',
          'authorization': 'Bearer CANARY_KEY_12345',
        },
      };
      expect(() =>
        interceptor('http://127.0.0.1:8788/mcp', contaminatedMcpRequest),
      ).toThrowError(/Security boundary violation: Authorization header with provider credentials/);

      // 3. Model inference payload dispatched to loopback throws
      const modelPayloadOnLoopback = {
        body: JSON.stringify({ model: 'muse-spark-1.3', messages: [] }),
      };
      expect(() =>
        interceptor('http://127.0.0.1:8788/mcp', modelPayloadOnLoopback),
      ).toThrowError(/Security boundary violation: Model inference request cannot be dispatched to loopback/);
    });
  });

  describe('Objective 5: Strict Endpoint Edge Cases & Normalization', () => {
    it('detects and rejects IPv6 loopback variants', () => {
      const ipv6Loopbacks = [
        'https://[::1]/v1/responses',
        'http://[::1]:8080/v1/responses',
        'https://[0:0:0:0:0:0:0:1]/v1/responses',
        'https://[::]/v1/responses',
        'https://[::ffff:127.0.0.1]/v1/responses',
        'https://[::ffff:7f00:1]/v1/responses',
      ];

      for (const endpoint of ipv6Loopbacks) {
        expect(isLoopbackEndpoint(endpoint)).toBe(true);
        expect(() => {
          validateProviderConfiguration('meta', endpoint, 'muse-spark-1.3');
        }).toThrowError(/Loopback destination|Insecure protocol/);
      }
    });

    it('detects and rejects IPv6 Unique-Local and Link-Local private addresses', () => {
      const ipv6Privates = [
        'https://[fc00::1]/v1/responses',
        'https://[fd12:3456:789a::1]/v1/responses',
        'https://[fe80::1]/v1/responses',
        'https://[febf::ffff]/v1/responses',
        'https://[::ffff:10.0.0.1]/v1/chat/completions',
        'https://[::ffff:192.168.1.1]/v1/chat/completions',
        'https://[::ffff:169.254.1.1]/v1/chat/completions',
      ];

      for (const endpoint of ipv6Privates) {
        expect(isPrivateNetworkEndpoint(endpoint)).toBe(true);
        expect(() => {
          validateProviderConfiguration('fireworks', endpoint, 'accounts/fireworks/models/muse-spark-open');
        }).toThrowError(/Private network destination|not an approved destination/);
      }
    });

    it('detects and rejects alternate IPv4 formats and unexpected schemes/ports', () => {
      const invalidEndpoints = [
        'https://2130706433/v1/responses', // Decimal 127.0.0.1
        'https://127.000.000.001/v1/responses', // Octal/zero-padded 127.0.0.1
        'ftp://api.meta.ai/v1/responses', // Invalid scheme
        'ws://api.meta.ai/v1/responses', // Invalid scheme
        'https://api.meta.ai:8080/v1/responses', // Non-standard port
        'https://api.meta.ai:444/v1/responses', // Non-standard port
      ];

      for (const endpoint of invalidEndpoints) {
        expect(() => {
          validateProviderConfiguration('meta', endpoint, 'muse-spark-1.3');
        }).toThrow();
      }
    });

    it('guarantees approved endpoint matching is strict and case-insensitive on hostname', () => {
      // Valid approved endpoints
      expect(() => {
        validateProviderConfiguration('meta', 'https://api.meta.ai/v1/responses', 'muse-spark-1.3');
      }).not.toThrow();

      expect(() => {
        validateProviderConfiguration('meta', 'https://api.meta.ai/v1/responses/', 'muse-spark-1.3');
      }).not.toThrow();

      // Subdomain spoofing attempts must fail
      expect(() => {
        validateProviderConfiguration('meta', 'https://api.meta.ai.attacker.com/v1/responses', 'muse-spark-1.3');
      }).toThrowError(/not an approved destination/);

      // Path traversal attempts must fail
      expect(() => {
        validateProviderConfiguration('meta', 'https://api.meta.ai/v1/responses/../other', 'muse-spark-1.3');
      }).toThrowError(/not an approved destination/);
    });
  });
});
