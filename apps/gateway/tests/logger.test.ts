/**
 * Unit tests for gateway logger with secret redaction
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Logger } from '../src/observability/logger.js';

describe('Logger', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  it('emits structured JSON log lines', () => {
    const logger = new Logger('debug');
    logger.info('test message', { key: 'value' });

    expect(consoleSpy).toHaveBeenCalledTimes(1);
    const parsed = JSON.parse(consoleSpy.mock.calls[0]![0] as string) as Record<string, unknown>;
    expect(parsed['level']).toBe('info');
    expect(parsed['msg']).toBe('test message');
    expect(parsed['ts']).toBeDefined();
  });

  it('redacts sensitive fields', () => {
    const logger = new Logger('debug', true);
    logger.info('request', {
      authorization: 'Bearer secret-token',
      method: 'tools/call',
      api_key: 'sk-1234',
      nested: { password: 'hunter2', safe: 'visible' },
    });

    const parsed = JSON.parse(consoleSpy.mock.calls[0]![0] as string) as Record<string, unknown>;
    const data = parsed['data'] as Record<string, unknown>;
    expect(data['authorization']).toBe('[REDACTED]');
    expect(data['api_key']).toBe('[REDACTED]');
    expect(data['method']).toBe('tools/call');
    const nested = data['nested'] as Record<string, unknown>;
    expect(nested['password']).toBe('[REDACTED]');
    expect(nested['safe']).toBe('visible');
  });

  it('respects log level filtering', () => {
    const logger = new Logger('warn');
    logger.debug('should not appear');
    logger.info('should not appear');
    logger.warn('should appear');

    expect(consoleSpy).toHaveBeenCalledTimes(1);
  });

  it('uses console.error for error level', () => {
    const logger = new Logger('debug');
    logger.error('something went wrong');

    expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
    expect(consoleSpy).not.toHaveBeenCalled();
  });
});
