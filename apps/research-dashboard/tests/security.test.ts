import { describe, it, expect } from 'vitest';
import {
  validateLoopbackAccess,
  redactSecrets,
  escapeHtml,
  getSecurityHeaders,
} from '../src/server/security.js';
import type { IncomingMessage } from 'node:http';

describe('Veylith Research Dashboard — Security & Redaction Boundaries', () => {
  describe('Loopback Access Validation', () => {
    function createMockRequest(
      remoteAddress: string,
      host?: string,
      origin?: string,
    ): IncomingMessage {
      return {
        socket: { remoteAddress },
        headers: {
          ...(host ? { host } : {}),
          ...(origin ? { origin } : {}),
        },
      } as unknown as IncomingMessage;
    }

    it('allows valid loopback requests with matching 127.0.0.1 host and port', () => {
      const req = createMockRequest('127.0.0.1', '127.0.0.1:8789');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(true);
    });

    it('allows valid IPv6 loopback requests with localhost host', () => {
      const req = createMockRequest('::1', 'localhost:8789');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(true);
    });

    it('allows mapped IPv4 loopback (::ffff:127.0.0.1)', () => {
      const req = createMockRequest('::ffff:127.0.0.1', '127.0.0.1:8789');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(true);
    });

    it('rejects remote IP addresses', () => {
      const req = createMockRequest('192.168.1.100', '127.0.0.1:8789');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Remote HTTP access is disabled');
    });

    it('rejects public internet IP addresses', () => {
      const req = createMockRequest('8.8.8.8', '127.0.0.1:8789');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(false);
    });

    it('rejects requests missing Host header', () => {
      const req = createMockRequest('127.0.0.1');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(false);
      expect(res.reason).toBe('Missing Host header');
    });

    it('rejects DNS rebinding Host headers (e.g. attacker.com)', () => {
      const req = createMockRequest('127.0.0.1', 'attacker.com:8789');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Host header must specify loopback');
    });

    it('rejects port mismatch in Host header', () => {
      const req = createMockRequest('127.0.0.1', '127.0.0.1:9090');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Host port must match 8789');
    });

    it('rejects Host headers with user credentials (user:pass@loopback)', () => {
      const req = createMockRequest('127.0.0.1', 'alice:secret@127.0.0.1:8789');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('userinfo');
    });

    it('rejects Host headers with query string or hash fragment', () => {
      const reqQuery = createMockRequest('127.0.0.1', '127.0.0.1:8789?param=val');
      const resQuery = validateLoopbackAccess(reqQuery, 8789);
      expect(resQuery.allowed).toBe(false);

      const reqHash = createMockRequest('127.0.0.1', '127.0.0.1:8789#fragment');
      const resHash = validateLoopbackAccess(reqHash, 8789);
      expect(resHash.allowed).toBe(false);
    });

    it('rejects untrusted Cross-Origin Origin header', () => {
      const req = createMockRequest(
        '127.0.0.1',
        '127.0.0.1:8789',
        'http://malicious-website.com:8789',
      );
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(false);
      expect(res.reason).toBe('Cross-origin access is disabled');
    });

    it('allows same-origin Origin header matching loopback port', () => {
      const req = createMockRequest('127.0.0.1', '127.0.0.1:8789', 'http://127.0.0.1:8789');
      const res = validateLoopbackAccess(req, 8789);
      expect(res.allowed).toBe(true);
    });
  });

  describe('Secret Redaction', () => {
    it('redacts explicit API keys, tokens, and authorization fields', () => {
      const input = {
        apiKey: 'sk-meta-muse-live-1234567890abcdef',
        token: 'eyJh...secretToken...',
        authorization: 'Bearer secret-bearer-token',
        password: 'admin-password',
        safeProperty: 'normal-value',
      };

      const redacted = redactSecrets(input) as Record<string, unknown>;
      expect(redacted['apiKey']).toBe('[REDACTED]');
      expect(redacted['token']).toBe('[REDACTED]');
      expect(redacted['authorization']).toBe('[REDACTED]');
      expect(redacted['password']).toBe('[REDACTED]');
      expect(redacted['safeProperty']).toBe('normal-value');
    });

    it('masks session identifiers partially to preserve debugging context while masking entropy', () => {
      const input = {
        sessionId: 'vyl-sess-e69b5158-2edd-4422-9e11-df3f4dc9241a',
      };
      const redacted = redactSecrets(input) as Record<string, unknown>;
      expect(redacted['sessionId']).toBe('vyl-sess-***c9241a');
    });

    it('redacts embedded bearer tokens inside arbitrary string payloads', () => {
      const input =
        'Call failed with authorization header: Bearer abc123secretToken456 and META_API_KEY=supersecret';
      const redacted = redactSecrets(input);
      expect(redacted).toContain('Bearer [REDACTED_TOKEN]');
      expect(redacted).toContain('META_API_KEY=[REDACTED]');
      expect(redacted).not.toContain('abc123secretToken456');
    });
  });

  describe('HTML Escaping & XSS Protection', () => {
    it('escapes dangerous HTML characters', () => {
      const dangerous = '<script>alert("XSS & Injection")</script> \'quoted\' `backtick` /slash/';
      const safe = escapeHtml(dangerous);
      expect(safe).not.toContain('<script>');
      expect(safe).toContain('&lt;script&gt;');
      expect(safe).toContain('&amp;');
      expect(safe).toContain('&quot;');
      expect(safe).toContain('&#39;');
      expect(safe).toContain('&#x60;');
      expect(safe).toContain('&#x2F;');
    });

    it('handles empty or non-string inputs safely', () => {
      expect(escapeHtml('')).toBe('');
      expect(escapeHtml(null as unknown as string)).toBe('');
      expect(escapeHtml(undefined as unknown as string)).toBe('');
    });
  });

  describe('Security Headers', () => {
    it('provides standard CSP, nosniff, and frame denying headers', () => {
      const headers = getSecurityHeaders();
      expect(headers['X-Content-Type-Options']).toBe('nosniff');
      expect(headers['X-Frame-Options']).toBe('DENY');
      expect(headers['Content-Security-Policy']).toContain("default-src 'self'");
      expect(headers['Content-Security-Policy']).toContain("frame-ancestors 'none'");
    });
  });
});
