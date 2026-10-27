import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { StdioLogger } from '../src/logger.js';

describe('StdioLogger', () => {
  let stderrOutput: string[] = [];
  let stdoutOutput: string[] = [];
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  let stdoutSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrOutput = [];
    stdoutOutput = [];
    stderrSpy = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: string | Uint8Array) => {
        stderrOutput.push(String(chunk));
        return true;
      });
    stdoutSpy = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk: string | Uint8Array) => {
        stdoutOutput.push(String(chunk));
        return true;
      });
  });

  afterEach(() => {
    stderrSpy.mockRestore();
    stdoutSpy.mockRestore();
  });

  it('routes ALL log levels exclusively to stderr and never stdout', () => {
    const logger = new StdioLogger('debug', true);

    logger.debug('debug message');
    logger.info('info message');
    logger.warn('warn message');
    logger.error('error message');

    // Stdout MUST be 100% clean so JSON-RPC is never corrupted
    expect(stdoutOutput).toHaveLength(0);

    // Stderr contains all four entries
    expect(stderrOutput).toHaveLength(4);
    for (const line of stderrOutput) {
      const parsed = JSON.parse(line);
      expect(parsed.service).toBe('veylith-stdio');
      expect(parsed.ts).toBeDefined();
    }
  });

  it('respects minLevel configuration', () => {
    const logger = new StdioLogger('warn', true);

    logger.debug('debug hidden');
    logger.info('info hidden');
    logger.warn('warn visible');
    logger.error('error visible');

    expect(stderrOutput).toHaveLength(2);
    expect(JSON.parse(stderrOutput[0]!).level).toBe('warn');
    expect(JSON.parse(stderrOutput[1]!).level).toBe('error');
  });

  it('redacts sensitive keys from log objects', () => {
    const logger = new StdioLogger('info', true);

    logger.info('User session established', {
      user: 'alice',
      authorization: 'Bearer super-secret-token',
      api_key: 'sk-1234567890abcdef',
      token: 'jwt-token-string',
      safeData: 'public-value',
    });

    expect(stderrOutput).toHaveLength(1);
    const parsed = JSON.parse(stderrOutput[0]!);
    expect(parsed.data.authorization).toBe('[REDACTED]');
    expect(parsed.data.api_key).toBe('[REDACTED]');
    expect(parsed.data.token).toBe('[REDACTED]');
    expect(parsed.data.safeData).toBe('public-value');
    expect(parsed.data.user).toBe('alice');
  });

  it('scrubs regex secret patterns in message strings', () => {
    const logger = new StdioLogger('info', true);

    logger.info('Attempted auth with sk-ant-api03-abcdef1234567890 token');

    expect(stderrOutput).toHaveLength(1);
    const parsed = JSON.parse(stderrOutput[0]!);
    expect(parsed.msg).toContain('[REDACTED]');
    expect(parsed.msg).not.toContain('abcdef1234567890');
  });
});
