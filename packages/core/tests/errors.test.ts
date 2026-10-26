/**
 * Unit tests for @veylith/core error types
 */

import { describe, it, expect } from 'vitest';
import {
  VeylithError,
  PolicyBlockedError,
  UpstreamError,
  ConfigError,
} from '../src/errors/index.js';

describe('Error hierarchy', () => {
  it('VeylithError has code and message', () => {
    const err = new VeylithError('test', 'TEST_CODE');
    expect(err.message).toBe('test');
    expect(err.code).toBe('TEST_CODE');
    expect(err.name).toBe('VeylithError');
    expect(err).toBeInstanceOf(Error);
  });

  it('PolicyBlockedError has ruleId', () => {
    const err = new PolicyBlockedError('blocked', 'rule-1');
    expect(err.ruleId).toBe('rule-1');
    expect(err.code).toBe('POLICY_BLOCKED');
    expect(err).toBeInstanceOf(VeylithError);
  });

  it('UpstreamError has optional statusCode', () => {
    const err = new UpstreamError('upstream down', 503);
    expect(err.statusCode).toBe(503);
    expect(err.code).toBe('UPSTREAM_ERROR');
    expect(err).toBeInstanceOf(VeylithError);
  });

  it('ConfigError has code CONFIG_ERROR', () => {
    const err = new ConfigError('missing env');
    expect(err.code).toBe('CONFIG_ERROR');
    expect(err).toBeInstanceOf(VeylithError);
  });
});
