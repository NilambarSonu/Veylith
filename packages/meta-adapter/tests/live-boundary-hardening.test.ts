import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  MetaMuseSecurityAdapter,
  APPROVED_PROVIDERS,
  validateProviderConfiguration,
  isLoopbackEndpoint,
  isPrivateNetworkEndpoint,
  resolveProviderApiKey,
  sanitizeProviderError,
  UsageTracker,
} from '../src/index.js';

describe('Veylith — Critical Live-Boundary Security Hardening', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('1 & 2: Rejection of Loopback, Localhost, Private, and Insecure Destinations', () => {
    it('strictly rejects localhost and loopback IPv4/IPv6 destinations in live mode', () => {
      const loopbacks = [
        'http://localhost:8080/v1/responses',
        'https://localhost/v1/responses',
        'http://127.0.0.1:8788/chat/completions',
        'https://127.0.0.1:9999/chat/completions',
        'https://127.0.1.1/chat/completions',
        'http://[::1]:8080/responses',
        'https://[::1]/responses',
        'https://0.0.0.0:8000/responses',
      ];

      for (const endpoint of loopbacks) {
        expect(() => {
          validateProviderConfiguration('meta', endpoint, 'muse-spark-1.3');
        }).toThrowError(/Loopback destination|Insecure protocol/);

        expect(() => {
          validateProviderConfiguration(
            'fireworks',
            endpoint,
            'accounts/fireworks/models/muse-spark-open',
          );
        }).toThrowError(/Loopback destination|Insecure protocol/);

        expect(() => {
          validateProviderConfiguration(
            'baseten',
            endpoint,
            'meta-models/muse-spark-open-1026',
          );
        }).toThrowError(/Loopback destination|Insecure protocol/);
      }
    });

    it('strictly rejects non-HTTPS (insecure HTTP) endpoints', () => {
      expect(() => {
        validateProviderConfiguration(
          'meta',
          'http://api.meta.ai/v1/responses',
          'muse-spark-1.3',
        );
      }).toThrowError(/Insecure protocol 'http:'/);

      expect(() => {
        validateProviderConfiguration(
          'fireworks',
          'http://api.fireworks.ai/inference/v1/chat/completions',
          'accounts/fireworks/models/muse-spark-open',
        );
      }).toThrowError(/Insecure protocol 'http:'/);
    });

    it('strictly rejects private network IP addresses and internal LAN domains', () => {
      const privateEndpoints = [
        'https://10.0.0.1/v1/chat/completions',
        'https://10.255.0.1:8443/v1/chat/completions',
        'https://172.16.0.5/v1/chat/completions',
        'https://172.31.255.255/v1/chat/completions',
        'https://192.168.1.1/v1/chat/completions',
        'https://169.254.169.254/latest/meta-data', // AWS/GCP metadata service
        'https://internal-server.local/v1/responses',
        'https://model-service.internal/v1/responses',
        'https://cluster.lan/v1/responses',
      ];

      for (const endpoint of privateEndpoints) {
        expect(() => {
          validateProviderConfiguration('meta', endpoint, 'muse-spark-1.3');
        }).toThrowError(/Private network destination .* is strictly forbidden/);
      }
    });

    it('strictly rejects endpoints specifying unexpected or non-standard ports', () => {
      expect(() => {
        validateProviderConfiguration(
          'meta',
          'https://api.meta.ai:8443/v1/responses',
          'muse-spark-1.3',
        );
      }).toThrowError(/Non-standard port '8443'/);

      expect(() => {
        validateProviderConfiguration(
          'fireworks',
          'https://api.fireworks.ai:444/inference/v1/chat/completions',
          'accounts/fireworks/models/muse-spark-open',
        );
      }).toThrowError(/Non-standard port '444'/);
    });
  });

  describe('3 & 4: Strict Provider, Endpoint, and Model Binding', () => {
    it('accepts only the exact approved HTTPS endpoint for each provider', () => {
      expect(() => {
        validateProviderConfiguration(
          'meta',
          'https://api.meta.ai/v1/responses',
          'muse-spark-1.3',
        );
      }).not.toThrow();

      expect(() => {
        validateProviderConfiguration(
          'fireworks',
          'https://api.fireworks.ai/inference/v1/chat/completions',
          'accounts/fireworks/models/muse-spark-open',
        );
      }).not.toThrow();

      expect(() => {
        validateProviderConfiguration(
          'baseten',
          'https://inference.baseten.co/v1/chat/completions',
          'meta-models/muse-spark-open-1026',
        );
      }).not.toThrow();
    });

    it('prevents mismatched provider and model from receiving credentials or initializing', () => {
      // Mismatched model for Meta
      expect(() => {
        new MetaMuseSecurityAdapter({
          provider: 'meta',
          mode: 'live',
          apiKey: 'test-meta-key',
          model: 'accounts/fireworks/models/muse-spark-open',
        });
      }).toThrowError(/Provider 'meta' does not permit model/);

      // Mismatched endpoint for Fireworks
      expect(() => {
        new MetaMuseSecurityAdapter({
          provider: 'fireworks',
          mode: 'live',
          apiKey: 'test-fw-key',
          model: 'accounts/fireworks/models/muse-spark-open',
          endpoint: 'https://api.meta.ai/v1/responses',
        });
      }).toThrowError(/Endpoint 'https:\/\/api.meta.ai\/v1\/responses' is not an approved destination for provider 'fireworks'/);
    });
  });

  describe('5 & 6: Malicious Loopback Protection & Zero Credential Leakage', () => {
    it('prevents fake credentials from ever being sent to a loopback endpoint in live mode', () => {
      expect(() => {
        new MetaMuseSecurityAdapter({
          provider: 'fireworks',
          mode: 'live',
          apiKey: 'fw_live_secret_canary_key_1234567890',
          endpoint: 'http://127.0.0.1:8788/chat/completions',
          model: 'accounts/fireworks/models/muse-spark-open',
        });
      }).toThrowError(/Insecure protocol|Loopback destination/);
    });

    it('redacts sensitive API keys and Bearer headers from error outputs', () => {
      const activeKey = 'fw_live_canary_secret_9988776655443322';
      const rawError = `Network connection to https://api.fireworks.ai failed with Authorization: Bearer eyJhbGciOi... and key ${activeKey}`;
      const sanitized = sanitizeProviderError(rawError, activeKey);

      expect(sanitized).not.toContain(activeKey);
      expect(sanitized).toContain('[REDACTED_API_KEY]');
      expect(sanitized).toContain('Bearer [REDACTED]');
    });
  });

  describe('7 & 8: Endpoint Overrides & Redirect Hardening', () => {
    it('rejects conflicting ambient META_MODEL_API_ENDPOINT overrides in live mode', () => {
      const originalEnv = { ...process.env };
      try {
        process.env['META_MODEL_API_ENDPOINT'] = 'https://malicious-proxy.attacker.com/v1';
        expect(() => {
          new MetaMuseSecurityAdapter({
            provider: 'meta',
            mode: 'live',
            apiKey: 'test-key',
          });
        }).toThrowError(/Conflicting ambient META_MODEL_API_ENDPOINT/);
      } finally {
        process.env = originalEnv;
      }
    });

    it('rejects conflicting ambient META_MODEL_API_BASE_URL overrides in live mode', () => {
      const originalEnv = { ...process.env };
      try {
        process.env['META_MODEL_API_BASE_URL'] = 'https://unauthorized-destination.com';
        expect(() => {
          new MetaMuseSecurityAdapter({
            provider: 'fireworks',
            mode: 'live',
            apiKey: 'test-key',
          });
        }).toThrowError(/Conflicting ambient META_MODEL_API_BASE_URL/);
      } finally {
        process.env = originalEnv;
      }
    });

    it('strictly sets redirect="error" on live fetch requests to forbid credential forwarding across redirects', async () => {
      let capturedInit: RequestInit | undefined;
      vi.spyOn(globalThis, 'fetch').mockImplementationOnce(async (_url, init) => {
        capturedInit = init;
        return {
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
                    explanation: 'Clean',
                    evidence: [],
                  }),
                },
              },
            ],
          }),
        } as Response;
      });

      const adapter = new MetaMuseSecurityAdapter({
        provider: 'fireworks',
        mode: 'live',
        apiKey: 'fw_canary_key_redirect_test',
        allowUnverifiedPricing: true,
      });

      await adapter.inspect('Clean prompt', 'discovery');
      expect(capturedInit?.redirect).toBe('error');
    });
  });

  describe('9 & 10: Unknown Pricing & Dollar Budget Protection', () => {
    it('refuses paid execution when provider pricing is unverified and unverified pricing is not authorized', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');

      const adapter = new MetaMuseSecurityAdapter({
        provider: 'fireworks',
        mode: 'live',
        apiKey: 'fw_test_unverified_pricing',
        // allowUnverifiedPricing is omitted (defaults to false)
      });

      await expect(adapter.inspect('Suspicious input', 'discovery')).rejects.toThrowError(
        /Local budget safeguard: Provider pricing is unverified.*dollar budget cap cannot be guaranteed or enforced/,
      );
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('allows execution under strict request-count limits when unverified pricing is explicitly authorized', async () => {
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
                  confidence: 1.0,
                  explanation: 'Clean input verified',
                  evidence: [],
                }),
              },
            },
          ],
          usage: { prompt_tokens: 50, completion_tokens: 20 },
        }),
      } as Response);

      const adapter = new MetaMuseSecurityAdapter({
        provider: 'fireworks',
        mode: 'live',
        apiKey: 'fw_test_explicit_unverified',
        allowUnverifiedPricing: true,
      });

      const result = await adapter.inspect('Clean input', 'discovery');
      expect(result.action).toBe('allow');
      expect(result.provider).toBe('fireworks');

      const report = adapter.tracker.getReport();
      expect(report.pricingVerified).toBe(false);
      expect(report.hasUnverifiedPricing).toBe(true);
      expect(report.dollarBudgetEnforced).toBe(false);
      expect(report.costStatus).toBe('unverified_unbounded_cost');
      expect(report.estimatedCostUsd).toBeNull(); // Cost represented as null when unverified
    });

    it('enforces verified dollar cap for Meta Muse Spark 1.3 when pricing is verified', () => {
      const tracker = new UsageTracker({
        maxRequestsPerRun: 10,
        dailyBudgetUsd: 0.05,
        pricingVerified: true,
        standardInputPriceUsd: 0.00000125,
        outputTokenPriceUsd: 0.00000425,
      });

      // Record spending exceeding $0.05
      // 50,000 standard tokens * $1.25/1M = $0.0625 > $0.05
      tracker.recordSuccess(50000, 0, 10);
      expect(() => tracker.assertWithinBudget()).toThrowError(/Daily budget cap reached/);

      const report = tracker.getReport();
      expect(report.pricingVerified).toBe(true);
      expect(report.dollarBudgetEnforced).toBe(true);
      expect(report.costStatus).toBe('verified_pricing');
      expect(report.estimatedCostUsd).toBeGreaterThan(0.05);
    });
  });

  describe('11 & 12: Request-Count, Output Limits, and Missing Usage Metadata', () => {
    it('strictly enforces maxRequestsPerRun regardless of pricing status', () => {
      const tracker = new UsageTracker({
        maxRequestsPerRun: 3,
        pricingVerified: false,
        allowUnverifiedPricing: true,
      });

      tracker.assertWithinBudget();
      tracker.recordSuccess(10, 10, 5);
      tracker.assertWithinBudget();
      tracker.recordSuccess(10, 10, 5);
      tracker.assertWithinBudget();
      tracker.recordSuccess(10, 10, 5);

      expect(() => tracker.assertWithinBudget()).toThrowError(
        /Maximum requests per run limit reached \(3\)/,
      );
    });

    it('flags hasUnknownUsage when provider response is missing usage metadata', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          choices: [
            {
              message: {
                content: 'Malformed non-JSON output',
              },
            },
          ],
          // usage property omitted
        }),
      } as Response);

      const adapter = new MetaMuseSecurityAdapter({
        provider: 'baseten',
        mode: 'live',
        apiKey: 'base_canary_test_key',
        allowUnverifiedPricing: true,
      });

      const result = await adapter.inspect('Test payload', 'discovery');
      expect(result.hasUnknownUsage).toBe(true);
      expect(adapter.tracker.getReport().hasUnknownUsage).toBe(true);
      expect(adapter.tracker.getReport().unknownUsageCount).toBe(1);
    });
  });

  describe('14: Live Runner CLI Safeguards (scripts/security-lab/live.ts)', () => {
    const runLiveCli = (extraArgs: string[], extraEnv: Record<string, string> = {}) => {
      const { spawnSync } = require('node:child_process');
      const { resolve } = require('node:path');
      const scriptPath = resolve(__dirname, '../../../scripts/security-lab/live.ts');
      return spawnSync(
        process.execPath,
        ['--import', 'tsx', scriptPath, ...extraArgs],
        {
          encoding: 'utf8',
          cwd: resolve(__dirname, '../../..'),
          env: {
            ...process.env,
            ...extraEnv,
          },
        },
      );
    };

    it('rejects live execution with Fireworks when pricing is unverified and --allow-unverified-pricing is omitted', () => {
      const result = runLiveCli([
        '--allow-paid',
        '--provider=fireworks',
        '--max-requests=1',
        '--max-total-tokens=2048',
        '--max-cost-usd=0.05',
        '--input-rate=1.25',
        '--output-rate=4.25',
        '--cached-rate=0.15',
      ]);

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("Provider 'fireworks' pricing is unverified");
      expect(result.stderr).toContain('--allow-unverified-pricing');
    });

    it('rejects fabricated or mismatched rates for Meta in live runner', () => {
      const result = runLiveCli([
        '--allow-paid',
        '--provider=meta',
        '--max-requests=1',
        '--max-total-tokens=2048',
        '--max-cost-usd=0.05',
        '--input-rate=9.99', // Fabricated rate
        '--output-rate=4.25',
        '--cached-rate=0.15',
      ]);

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain('Meta model pricing is verified: expected --input-rate=1.25');
    });

    it('rejects conflicting ambient META_MODEL_API_ENDPOINT in live runner', () => {
      const result = runLiveCli(
        [
          '--allow-paid',
          '--provider=meta',
          '--max-requests=1',
          '--max-total-tokens=2048',
          '--max-cost-usd=0.05',
          '--input-rate=1.25',
          '--output-rate=4.25',
          '--cached-rate=0.15',
        ],
        {
          META_MODEL_API_ENDPOINT: 'http://127.0.0.1:9999/malicious-listener',
        },
      );

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain('Conflicting ambient META_MODEL_API_ENDPOINT');
    });

    it('rejects conflicting ambient META_MODEL_API_BASE_URL in live runner', () => {
      const result = runLiveCli(
        [
          '--allow-paid',
          '--provider=fireworks',
          '--allow-unverified-pricing',
          '--max-requests=1',
          '--max-total-tokens=2048',
          '--max-cost-usd=0.05',
          '--input-rate=1.25',
          '--output-rate=4.25',
          '--cached-rate=0.15',
        ],
        {
          META_MODEL_API_BASE_URL: 'http://127.0.0.1:8888/evil-sink',
        },
      );

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain('Conflicting ambient META_MODEL_API_BASE_URL');
    });
  });
});
