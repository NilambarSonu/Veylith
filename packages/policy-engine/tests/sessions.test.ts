import { describe, it, expect, beforeEach } from 'vitest';
import { ClientSessionManager } from '../src/sessions/manager.js';

describe('ClientSessionManager (Phase 2C)', () => {
  let manager: ClientSessionManager;

  beforeEach(() => {
    manager = new ClientSessionManager(3600_000); // 1 hour TTL
  });

  it('creates cryptographically unique sessions with vyl-sess- prefix', () => {
    const s1 = manager.createSession({ clientIdentity: 'client-alice', serverId: 'server-1' });
    const s2 = manager.createSession({ clientIdentity: 'client-bob', serverId: 'server-1' });

    expect(s1.sessionId).toMatch(/^vyl-sess-[0-9a-f-]{36}$/);
    expect(s2.sessionId).toMatch(/^vyl-sess-[0-9a-f-]{36}$/);
    expect(s1.sessionId).not.toBe(s2.sessionId);
    expect(s1.clientIdentity).toBe('client-alice');
    expect(s1.permittedTools).toBe('*');
  });

  it('validates active session and updates lastAccessedAt', () => {
    const session = manager.createSession({ clientIdentity: 'client-alice', serverId: 'server-1' });
    const initialAccess = session.lastAccessedAt;

    const result = manager.validateSession(session.sessionId, 'client-alice');
    expect(result.valid).toBe(true);
    expect(result.session).toBeDefined();
    expect(result.session?.lastAccessedAt).toBeGreaterThanOrEqual(initialAccess);
  });

  it('rejects invalid or forged session ID formats (Criterion F)', () => {
    expect(manager.validateSession('forged-id')).toEqual({
      valid: false,
      reason: 'invalid_format',
    });
    expect(manager.validateSession('')).toEqual({ valid: false, reason: 'invalid_format' });
    expect(manager.validateSession(undefined)).toEqual({ valid: false, reason: 'invalid_format' });
  });

  it('rejects non-existent session IDs with not_found (Criterion F)', () => {
    const fakeId = 'vyl-sess-00000000-0000-0000-0000-000000000000';
    expect(manager.validateSession(fakeId)).toEqual({ valid: false, reason: 'not_found' });
  });

  it('rejects cross-client session hijacking attempts (Criterion G)', () => {
    const session = manager.createSession({ clientIdentity: 'client-alice', serverId: 'server-1' });

    // Bob attempts to use Alice's session
    const hijacked = manager.validateSession(session.sessionId, 'client-bob');
    expect(hijacked.valid).toBe(false);
    expect(hijacked.reason).toBe('identity_mismatch');
  });

  it('enforces session expiration after TTL', () => {
    const shortLivedManager = new ClientSessionManager(10); // 10ms TTL
    const session = shortLivedManager.createSession({
      clientIdentity: 'client-alice',
      serverId: 'server-1',
      ttlMs: 5,
    });

    // Wait 20ms for expiration
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        const res = shortLivedManager.validateSession(session.sessionId);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('expired');
        resolve();
      }, 20);
    });
  });

  it('enforces tool authorization whitelists scoped to session', () => {
    const session = manager.createSession({
      clientIdentity: 'client-alice',
      serverId: 'server-1',
      permittedTools: ['echo', 'add'],
    });

    expect(manager.isToolAuthorized(session.sessionId, 'echo')).toBe(true);
    expect(manager.isToolAuthorized(session.sessionId, 'add')).toBe(true);
    expect(manager.isToolAuthorized(session.sessionId, 'restricted_tool')).toBe(false);
    expect(manager.isToolAuthorized('vyl-sess-non-existent', 'echo')).toBe(false);
  });

  it('enforces resource authorization with exact and prefix wildcard support', () => {
    const session = manager.createSession({
      clientIdentity: 'client-alice',
      serverId: 'server-1',
      permittedResources: ['docs://readme', 'reports/*'],
    });

    expect(manager.isResourceAuthorized(session.sessionId, 'docs://readme')).toBe(true);
    expect(manager.isResourceAuthorized(session.sessionId, 'reports/2026-q1')).toBe(true);
    expect(manager.isResourceAuthorized(session.sessionId, 'secrets://tokens')).toBe(false);
  });

  it('enforces prompt authorization scoped to session', () => {
    const session = manager.createSession({
      clientIdentity: 'client-alice',
      serverId: 'server-1',
      permittedPrompts: ['code_review'],
    });

    expect(manager.isPromptAuthorized(session.sessionId, 'code_review')).toBe(true);
    expect(manager.isPromptAuthorized(session.sessionId, 'system_prompt')).toBe(false);
  });

  it('supports explicit session teardown and destroy', () => {
    const session = manager.createSession({ clientIdentity: 'client-alice', serverId: 'server-1' });
    expect(manager.getActiveSessionsCount()).toBe(1);

    expect(manager.destroySession(session.sessionId)).toBe(true);
    expect(manager.getActiveSessionsCount()).toBe(0);
    expect(manager.validateSession(session.sessionId).valid).toBe(false);
  });
});
