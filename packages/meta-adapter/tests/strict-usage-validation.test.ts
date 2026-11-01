import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  MetaMuseSecurityAdapter,
  extractValidatedUsage,
  isLoopbackEndpoint,
  isPrivateNetworkEndpoint,
  extractIpv4Bytes,
  validateProviderConfiguration,
} from '../src/index.js';

describe('Veylith — Final Usage Validation & Network Boundary Hardening', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Task 1: Strict Provider Usage Validation (18 Core Scenarios)', () => {
    // 1. Negative input tokens
    it('Scenario 1: rejects negative input tokens', () => {
      expect(extractValidatedUsage({ prompt_tokens: -1, completion_tokens: 10 })).toBeNull();
      expect(extractValidatedUsage({ input_tokens: -10, output_tokens: 10 })).toBeNull();
    });

    // 2. Negative output tokens
    it('Scenario 2: rejects negative output tokens', () => {
      expect(extractValidatedUsage({ prompt_tokens: 10, completion_tokens: -5 })).toBeNull();
      expect(extractValidatedUsage({ input_tokens: 10, output_tokens: -1 })).toBeNull();
    });

    // 3. Fractional input tokens
    it('Scenario 3: rejects fractional input tokens', () => {
      expect(extractValidatedUsage({ prompt_tokens: 10.5, completion_tokens: 20 })).toBeNull();
      expect(extractValidatedUsage({ input_tokens: 0.1, output_tokens: 20 })).toBeNull();
    });

    // 4. Fractional output tokens
    it('Scenario 4: rejects fractional output tokens', () => {
      expect(extractValidatedUsage({ prompt_tokens: 10, completion_tokens: 20.7 })).toBeNull();
      expect(extractValidatedUsage({ input_tokens: 10, output_tokens: 5.0001 })).toBeNull();
    });

    // 5. String input tokens
    it('Scenario 5: rejects string input tokens', () => {
      expect(extractValidatedUsage({ prompt_tokens: '100', completion_tokens: 20 })).toBeNull();
      expect(extractValidatedUsage({ input_tokens: '0', output_tokens: 20 })).toBeNull();
    });

    // 6. String output tokens
    it('Scenario 6: rejects string output tokens', () => {
      expect(extractValidatedUsage({ prompt_tokens: 10, completion_tokens: '200' })).toBeNull();
      expect(extractValidatedUsage({ input_tokens: 10, output_tokens: 'null' })).toBeNull();
    });

    // 7. NaN input tokens
    it('Scenario 7: rejects NaN input tokens', () => {
      expect(
        extractValidatedUsage({ prompt_tokens: Number.NaN, completion_tokens: 20 }),
      ).toBeNull();
      expect(extractValidatedUsage({ input_tokens: NaN, output_tokens: 20 })).toBeNull();
    });

    // 8. Infinity / -Infinity tokens
    it('Scenario 8: rejects Infinity and -Infinity tokens', () => {
      expect(extractValidatedUsage({ prompt_tokens: Infinity, completion_tokens: 20 })).toBeNull();
      expect(extractValidatedUsage({ prompt_tokens: -Infinity, completion_tokens: 20 })).toBeNull();
      expect(extractValidatedUsage({ prompt_tokens: 10, completion_tokens: Infinity })).toBeNull();
      expect(extractValidatedUsage({ prompt_tokens: 10, completion_tokens: -Infinity })).toBeNull();
    });

    // 9. Unsafe integers exceeding Number.MAX_SAFE_INTEGER
    it('Scenario 9: rejects unsafe integers exceeding Number.MAX_SAFE_INTEGER', () => {
      const unsafeInt = Number.MAX_SAFE_INTEGER + 10;
      expect(extractValidatedUsage({ prompt_tokens: unsafeInt, completion_tokens: 20 })).toBeNull();
      expect(extractValidatedUsage({ prompt_tokens: 10, completion_tokens: unsafeInt })).toBeNull();
    });

    // 10. Missing input tokens
    it('Scenario 10: rejects missing input tokens', () => {
      expect(extractValidatedUsage({ completion_tokens: 20 })).toBeNull();
      expect(extractValidatedUsage({ output_tokens: 20 })).toBeNull();
    });

    // 11. Missing output tokens
    it('Scenario 11: rejects missing output tokens', () => {
      expect(extractValidatedUsage({ prompt_tokens: 10 })).toBeNull();
      expect(extractValidatedUsage({ input_tokens: 10 })).toBeNull();
    });

    // 12. Null usage object
    it('Scenario 12: rejects null usage object', () => {
      expect(extractValidatedUsage(null)).toBeNull();
      expect(extractValidatedUsage(undefined)).toBeNull();
    });

    // 13. Array or non-object usage
    it('Scenario 13: rejects array or non-object usage', () => {
      expect(extractValidatedUsage([10, 20])).toBeNull();
      expect(extractValidatedUsage('usage: prompt_tokens=10')).toBeNull();
      expect(extractValidatedUsage(12345)).toBeNull();
      expect(extractValidatedUsage(true)).toBeNull();
    });

    // 14. Ambiguous conflicting aliases
    it('Scenario 14: rejects ambiguous conflicting aliases', () => {
      // Conflicting prompt/input
      expect(
        extractValidatedUsage({
          prompt_tokens: 10,
          input_tokens: 20,
          completion_tokens: 30,
        }),
      ).toBeNull();

      // Conflicting completion/output
      expect(
        extractValidatedUsage({
          prompt_tokens: 10,
          completion_tokens: 30,
          output_tokens: 40,
        }),
      ).toBeNull();

      // Non-conflicting aliases are permitted
      const valid = extractValidatedUsage({
        prompt_tokens: 10,
        input_tokens: 10,
        completion_tokens: 30,
        output_tokens: 30,
      });
      expect(valid).not.toBeNull();
      expect(valid?.promptTokens).toBe(10);
      expect(valid?.completionTokens).toBe(30);
    });

    // 15. Invalid cached or reasoning tokens
    it('Scenario 15: rejects invalid cached or reasoning tokens', () => {
      // Negative cached tokens
      expect(
        extractValidatedUsage({
          prompt_tokens: 100,
          completion_tokens: 50,
          prompt_tokens_details: { cached_tokens: -1 },
        }),
      ).toBeNull();

      // Fractional reasoning tokens
      expect(
        extractValidatedUsage({
          prompt_tokens: 100,
          completion_tokens: 50,
          completion_tokens_details: { reasoning_tokens: 5.5 },
        }),
      ).toBeNull();

      // Malformed details containers
      expect(
        extractValidatedUsage({
          prompt_tokens: 100,
          completion_tokens: 50,
          prompt_tokens_details: 'malformed_string',
        }),
      ).toBeNull();
      expect(
        extractValidatedUsage({
          prompt_tokens: 100,
          completion_tokens: 50,
          completion_tokens_details: [1, 2, 3],
        }),
      ).toBeNull();
    });

    // 16. Cached tokens exceeding input tokens
    it('Scenario 16: rejects cached tokens exceeding input tokens', () => {
      expect(
        extractValidatedUsage({
          prompt_tokens: 50,
          completion_tokens: 20,
          prompt_tokens_details: { cached_tokens: 51 },
        }),
      ).toBeNull();

      expect(
        extractValidatedUsage({
          input_tokens: 100,
          output_tokens: 20,
          cached_tokens: 150,
        }),
      ).toBeNull();
    });

    // 17. Reasoning tokens exceeding output tokens
    it('Scenario 17: rejects reasoning tokens exceeding output tokens', () => {
      expect(
        extractValidatedUsage({
          prompt_tokens: 50,
          completion_tokens: 20,
          completion_tokens_details: { reasoning_tokens: 21 },
        }),
      ).toBeNull();

      expect(
        extractValidatedUsage({
          input_tokens: 100,
          output_tokens: 30,
          reasoning_tokens: 31,
        }),
      ).toBeNull();
    });

    // 18. Valid usage correctly extracted and recorded across all providers
    it('Scenario 18: correctly validates and extracts usage for Meta, Fireworks, and Baseten', () => {
      // Meta Responses API style
      const metaUsage = extractValidatedUsage({
        input_tokens: 120,
        output_tokens: 45,
        input_tokens_details: { cached_tokens: 20 },
        output_tokens_details: { reasoning_tokens: 10 },
      });
      expect(metaUsage).toEqual({
        promptTokens: 120,
        completionTokens: 45,
        totalTokens: 165,
        cachedPromptTokens: 20,
        reasoningTokens: 10,
      });

      // OpenAI / Fireworks / Baseten style
      const chatUsage = extractValidatedUsage({
        prompt_tokens: 200,
        completion_tokens: 80,
        total_tokens: 280,
        prompt_tokens_details: { cached_tokens: 50 },
        completion_tokens_details: { reasoning_tokens: 30 },
      });
      expect(chatUsage).toEqual({
        promptTokens: 200,
        completionTokens: 80,
        totalTokens: 280,
        cachedPromptTokens: 50,
        reasoningTokens: 30,
      });

      // Zero-token edge case (valid non-negative integers)
      const zeroUsage = extractValidatedUsage({
        prompt_tokens: 0,
        completion_tokens: 0,
      });
      expect(zeroUsage).toEqual({
        promptTokens: 0,
        completionTokens: 0,
        totalTokens: 0,
        cachedPromptTokens: 0,
        reasoningTokens: 0,
      });
    });

    it('end-to-end adapter integration: preserves valid classification while marking usage unknown on negative tokens', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  flagged: true,
                  threatCategory: 'destructive_command',
                  action: 'block',
                  confidence: 0.99,
                  explanation: 'Destructive payload identified',
                  evidence: ['rm -rf'],
                }),
              },
            },
          ],
          usage: { prompt_tokens: -10, completion_tokens: 20 },
        }),
      } as Response);

      const adapter = new MetaMuseSecurityAdapter({
        provider: 'fireworks',
        mode: 'live',
        apiKey: 'fw_test_negative_tokens',
        allowUnverifiedPricing: true,
      });

      const result = await adapter.inspect('rm -rf /', 'discovery');

      // Valid classification is preserved
      expect(result.action).toBe('block');
      expect(result.flagged).toBe(true);
      expect(result.threatCategory).toBe('destructive_command');

      // Usage is marked unknown and cost is null
      expect(result.hasUnknownUsage).toBe(true);
      expect(result.tokenUsage).toBeUndefined();

      const report = adapter.tracker.getReport();
      expect(report.hasUnknownUsage).toBe(true);
      expect(report.unknownUsageCount).toBe(1);
      expect(report.estimatedCostUsd).toBeNull();
      expect(report.costStatus).toBe('unknown_usage_cost');
    });
  });

  describe('Task 2: Complete IPv4-Mapped IPv6 Boundary Detection', () => {
    describe('127.0.0.0/8 Subnet (Loopback)', () => {
      const addresses = [
        '127.0.0.0', // beginning
        '127.42.0.1', // middle
        '127.255.255.255', // end
      ];

      it('detects dotted-decimal and WHATWG-hex loopbacks', () => {
        for (const ip of addresses) {
          expect(isLoopbackEndpoint(`https://${ip}/v1`)).toBe(true);
          expect(isLoopbackEndpoint(`https://[::ffff:${ip}]/v1`)).toBe(true);
          expect(isPrivateNetworkEndpoint(`https://[::ffff:${ip}]/v1`)).toBe(true);
        }

        // Hex representations
        expect(isLoopbackEndpoint('https://[::ffff:7f00:0]/v1')).toBe(true);
        expect(isLoopbackEndpoint('https://[::ffff:7f2a:1]/v1')).toBe(true);
        expect(isLoopbackEndpoint('https://[::ffff:7fff:ffff]/v1')).toBe(true);
      });
    });

    describe('10.0.0.0/8 Subnet (RFC 1918 Private)', () => {
      const addresses = [
        '10.0.0.0', // beginning
        '10.128.0.1', // middle
        '10.255.255.255', // end
      ];

      it('detects dotted-decimal and WHATWG-hex 10.0.0.0/8 private addresses', () => {
        for (const ip of addresses) {
          expect(isPrivateNetworkEndpoint(`https://${ip}/v1`)).toBe(true);
          expect(isPrivateNetworkEndpoint(`https://[::ffff:${ip}]/v1`)).toBe(true);
        }

        // Hex forms
        expect(isPrivateNetworkEndpoint('https://[::ffff:a00:0]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:a80:1]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:aff:ffff]/v1')).toBe(true);

        // Non-private neighbors (11.0.0.1)
        expect(isPrivateNetworkEndpoint('https://[::ffff:11.0.0.1]/v1')).toBe(false);
        expect(isPrivateNetworkEndpoint('https://[::ffff:b00:1]/v1')).toBe(false);
      });
    });

    describe('172.16.0.0/12 Subnet (RFC 1918 Private)', () => {
      it('detects beginning, middle, and end of 172.16.0.0/12 subnet', () => {
        const privates = [
          '172.16.0.0', // beginning
          '172.16.0.1',
          '172.24.0.1', // middle
          '172.31.255.254',
          '172.31.255.255', // end
        ];

        for (const ip of privates) {
          expect(isPrivateNetworkEndpoint(`https://${ip}/v1`)).toBe(true);
          expect(isPrivateNetworkEndpoint(`https://[::ffff:${ip}]/v1`)).toBe(true);
        }

        // Hex representations
        expect(isPrivateNetworkEndpoint('https://[::ffff:ac10:0]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:ac10:1]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:ac18:1]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:ac1f:ffff]/v1')).toBe(true);
      });

      it('accurately distinguishes non-private boundary neighbors', () => {
        const nonPrivates = [
          '172.15.255.255', // Just below 172.16.0.0/12
          '172.32.0.0', // Just above 172.16.0.0/12
          '172.32.0.1',
        ];

        for (const ip of nonPrivates) {
          expect(isPrivateNetworkEndpoint(`https://${ip}/v1`)).toBe(false);
          expect(isPrivateNetworkEndpoint(`https://[::ffff:${ip}]/v1`)).toBe(false);
        }

        expect(isPrivateNetworkEndpoint('https://[::ffff:ac0f:ffff]/v1')).toBe(false);
        expect(isPrivateNetworkEndpoint('https://[::ffff:ac20:0]/v1')).toBe(false);
      });
    });

    describe('192.168.0.0/16 Subnet (RFC 1918 Private)', () => {
      it('detects beginning, middle, and end of 192.168.0.0/16 subnet', () => {
        const privates = [
          '192.168.0.0', // beginning
          '192.168.100.1', // middle
          '192.168.255.255', // end
        ];

        for (const ip of privates) {
          expect(isPrivateNetworkEndpoint(`https://${ip}/v1`)).toBe(true);
          expect(isPrivateNetworkEndpoint(`https://[::ffff:${ip}]/v1`)).toBe(true);
        }

        expect(isPrivateNetworkEndpoint('https://[::ffff:c0a8:0]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:c0a8:6401]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:c0a8:ffff]/v1')).toBe(true);

        // Non-private neighbors
        expect(isPrivateNetworkEndpoint('https://[::ffff:192.167.255.255]/v1')).toBe(false);
        expect(isPrivateNetworkEndpoint('https://[::ffff:192.169.0.1]/v1')).toBe(false);
      });
    });

    describe('169.254.0.0/16 Subnet (RFC 3927 Link-Local)', () => {
      it('detects beginning, middle, and end of 169.254.0.0/16 subnet', () => {
        const privates = [
          '169.254.0.0', // beginning
          '169.254.128.1', // middle
          '169.254.255.255', // end
        ];

        for (const ip of privates) {
          expect(isPrivateNetworkEndpoint(`https://${ip}/v1`)).toBe(true);
          expect(isPrivateNetworkEndpoint(`https://[::ffff:${ip}]/v1`)).toBe(true);
        }

        expect(isPrivateNetworkEndpoint('https://[::ffff:a9fe:0]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:a9fe:8001]/v1')).toBe(true);
        expect(isPrivateNetworkEndpoint('https://[::ffff:a9fe:ffff]/v1')).toBe(true);

        // Non-private neighbors
        expect(isPrivateNetworkEndpoint('https://[::ffff:169.253.255.255]/v1')).toBe(false);
        expect(isPrivateNetworkEndpoint('https://[::ffff:169.255.0.1]/v1')).toBe(false);
      });
    });

    describe('Direct extractIpv4Bytes utility checks', () => {
      it('handles bracketed and unbracketed, lowercase and uppercase strings', () => {
        expect(extractIpv4Bytes('127.0.0.1')).toEqual([127, 0, 0, 1]);
        expect(extractIpv4Bytes('[127.0.0.1]')).toEqual([127, 0, 0, 1]);
        expect(extractIpv4Bytes('::ffff:172.16.0.1')).toEqual([172, 16, 0, 1]);
        expect(extractIpv4Bytes('[::FFFF:172.16.0.1]')).toEqual([172, 16, 0, 1]);
        expect(extractIpv4Bytes('::ffff:ac10:1')).toEqual([172, 16, 0, 1]);
        expect(extractIpv4Bytes('[::FFFF:AC10:0001]')).toEqual([172, 16, 0, 1]);
        expect(extractIpv4Bytes('0:0:0:0:0:ffff:172.16.0.1')).toEqual([172, 16, 0, 1]);
        expect(extractIpv4Bytes('invalid_host')).toBeNull();
      });
    });

    describe('Approved Endpoint Allowlist Invariant', () => {
      it('strictly forbids non-allowlisted endpoints even if external/public', () => {
        // Public non-approved endpoint
        expect(() => {
          validateProviderConfiguration(
            'fireworks',
            'https://api.openai.com/v1/chat/completions',
            'accounts/fireworks/models/muse-spark-open',
          );
        }).toThrowError(/not an approved destination/);

        // Trailing path traversal attempts
        expect(() => {
          validateProviderConfiguration(
            'fireworks',
            'https://api.fireworks.ai/inference/v1/chat/completions/../../admin',
            'accounts/fireworks/models/muse-spark-open',
          );
        }).toThrowError(/not an approved destination/);

        // Subdomain spoofing
        expect(() => {
          validateProviderConfiguration(
            'fireworks',
            'https://api.fireworks.ai.attacker.org/inference/v1/chat/completions',
            'accounts/fireworks/models/muse-spark-open',
          );
        }).toThrowError(/not an approved destination/);

        // Valid approved endpoint succeeds
        expect(() => {
          validateProviderConfiguration(
            'fireworks',
            'https://api.fireworks.ai/inference/v1/chat/completions',
            'accounts/fireworks/models/muse-spark-open',
          );
        }).not.toThrow();
      });
    });
  });
});
