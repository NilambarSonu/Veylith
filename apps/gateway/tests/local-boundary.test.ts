import { describe, it, expect } from 'vitest';
import { localBoundaryError } from '../src/http/local-boundary.js';
describe('Local exposure boundary (not user authentication)', () => {
  it('allows native loopback HTTP and exact same-origin browser requests', () => {
    expect(localBoundaryError('127.0.0.1', '127.0.0.1:8787', undefined, 8787)).toBeUndefined();
    expect(localBoundaryError('::1', '[::1]:8787', 'http://[::1]:8787', 8787)).toBeUndefined();
  });
  it.each(['192.0.2.1', '::ffff:192.0.2.1', undefined])(
    'denies synthetic remote address %s regardless of labels',
    (ip) => {
      expect(localBoundaryError(ip, '127.0.0.1:8787', undefined, 8787)).toContain('Remote');
    },
  );
  it.each(['null', 'https://synthetic.invalid', 'http://127.0.0.1:9999'])(
    'denies cross-origin input %s',
    (origin) => {
      expect(localBoundaryError('127.0.0.1', '127.0.0.1:8787', origin, 8787)).toBeDefined();
    },
  );
  it.each(['synthetic.invalid:8787', '127.0.0.1:1', 'user@127.0.0.1:8787', '127.0.0.1:8787/path'])(
    'rejects untrusted Host %s',
    (host) => {
      expect(localBoundaryError('127.0.0.1', host, undefined, 8787)).toBeDefined();
    },
  );
});
