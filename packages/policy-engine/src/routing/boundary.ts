/** Origin-based triage; no vocabulary establishes trust in upstream prose. */
import { createHash } from 'node:crypto';
import type {
  InspectionContext,
  InspectionStage,
  RoutingTrace,
  ToolCapability,
} from '@veylith/core';
import { HeuristicRiskScreener, type ScreenerVerdict } from '../screener/heuristic.js';
export interface RoutingInput {
  stage: InspectionStage;
  target: string;
  data: unknown;
  context?: Partial<InspectionContext>;
  capability?: ToolCapability;
  items?: readonly string[];
  inspectable?: boolean;
}
export interface RoutedScreen {
  verdict: ScreenerVerdict;
  trace: RoutingTrace;
  payload: string;
}
export class BoundaryRouter {
  private readonly screener = new HeuristicRiskScreener();
  private readonly approved = new Map<string, string>();
  private readonly history = new Map<string, { text: string; expiresAt: number }>();
  private readonly counts: Record<string, number> = {};
  constructor(
    readonly maxBytes = 16384,
    readonly maxSessions = 128,
    private readonly sessionIsActive?: (serverId: string, sessionId: string) => boolean,
  ) {}
  private key(serverId: string | undefined, stage: InspectionStage, target: string) {
    return JSON.stringify([serverId ?? '', stage, target]);
  }
  approve(serverId: string, stage: InspectionStage, target: string, content: string): void {
    const key = this.key(serverId, stage, target);
    if (!this.approved.has(key) && this.approved.size >= 256)
      throw new Error('Trusted-content approval limit reached');
    this.approved.set(key, this.hash(content));
  }
  private hash(s: string) {
    return createHash('sha256').update(s).digest('hex');
  }
  private session(ctx: Partial<InspectionContext> | undefined) {
    return ctx?.serverId && ctx.sessionId
      ? JSON.stringify([ctx.serverId, ctx.sessionId])
      : undefined;
  }
  stats() {
    this.prune();
    return {
      ...this.counts,
      retainedSessions: this.history.size,
      approvedContentBindings: this.approved.size,
    };
  }
  clearSession(serverId: string, sessionId: string) {
    this.history.delete(JSON.stringify([serverId, sessionId]));
  }
  /** Retain only delivered untrusted text, not quarantined instructions or trusted echoes. */
  remember(ctx: Partial<InspectionContext>, text: string): void {
    const session = this.session(ctx);
    if (!session || !text) return;
    if (this.sessionIsActive && !this.sessionIsActive(ctx.serverId!, ctx.sessionId!)) return;
    if (!this.history.has(session) && this.history.size >= this.maxSessions)
      this.history.delete(this.history.keys().next().value!);
    const previous = this.history.get(session)?.text ?? '';
    this.history.set(session, {
      text: (previous + text).slice(-4096),
      expiresAt: Date.now() + 60000,
    });
  }
  prune() {
    const now = Date.now();
    for (const [key, value] of this.history)
      if (
        value.expiresAt <= now ||
        (this.sessionIsActive && !this.sessionIsActive(...(JSON.parse(key) as [string, string])))
      )
        this.history.delete(key);
  }
  route(input: RoutingInput): RoutedScreen {
    this.prune();
    const text = typeof input.data === 'string' ? input.data : (JSON.stringify(input.data) ?? '');
    const normalize = (s: string) => s.normalize('NFKC').replace(/\p{Cf}/gu, '');
    const origin = input.stage === 'call_arguments' ? 'client' : 'upstream';
    const finish = (
      decision: RoutingTrace['decision'],
      reason: string,
      verdict: ScreenerVerdict,
      payload = text,
    ): RoutedScreen => {
      this.counts[decision] = (this.counts[decision] ?? 0) + 1;
      this.counts[`reason:${reason}`] = (this.counts[`reason:${reason}`] ?? 0) + 1;
      return {
        trace: {
          decision,
          reason,
          origin:
            reason === 'byte-exact-client-data-echo'
              ? 'client'
              : reason === 'operator-pinned-content-hash'
                ? 'trusted-local'
                : origin,
          capability: input.capability ?? 'UNKNOWN',
          inputBytes: Buffer.byteLength(text),
          contextIncluded: payload !== text,
        },
        verdict,
        payload,
      };
    };
    const ambiguous = (reason: string, payload = text, riskLevel: 'high' | 'medium' = 'medium') => {
      if (Buffer.byteLength(payload) > this.maxBytes)
        return finish('unknown_or_uninspectable', 'aggregate-context-budget-exceeded', {
          type: 'ambiguous',
          riskLevel: 'high',
          suspiciousSignals: ['bounded context exceeded'],
        });
      return finish(
        'needs_semantic_review',
        reason,
        { type: 'ambiguous', riskLevel, suspiciousSignals: [reason] },
        payload,
      );
    };
    if (
      input.inspectable === false ||
      Buffer.byteLength(text) > this.maxBytes ||
      (input.items?.length ?? 0) > 32
    ) {
      return finish(
        'unknown_or_uninspectable',
        input.inspectable === false ? 'unsupported-content-type' : 'inspection-budget-exceeded',
        { type: 'ambiguous', riskLevel: 'high', suspiciousSignals: ['unknown or uninspectable'] },
      );
    }
    const alternatives = [text, normalize(text)];
    if (input.items && input.items.length > 1) alternatives.push(normalize(input.items.join('')));
    const session = this.session(input.context);
    const previous = session ? this.history.get(session)?.text : undefined;
    if (
      previous &&
      input.stage !== 'discovery' &&
      input.stage !== 'resource_discovery' &&
      input.stage !== 'prompt_discovery'
    )
      alternatives.push(normalize(previous + text));
    let existing: ScreenerVerdict = { type: 'clean' };
    for (const candidate of alternatives) {
      const verdict = this.screener.screen(candidate, {
        stage: input.stage,
        capability: input.capability ?? 'UNKNOWN',
      });
      if (verdict.type === 'hard_violation')
        return finish(
          'deterministically_blocked',
          'existing-invariant-on-normalized-aggregate',
          verdict,
        );
      if (verdict.type === 'ambiguous') existing = verdict;
    }
    if (
      input.stage === 'call_response' &&
      input.capability === 'PURE_OR_READ' &&
      input.context?.clientArgumentText?.some((value) => value === text)
    )
      return finish('verified_safe_fast_path', 'byte-exact-client-data-echo', { type: 'clean' });
    const aggregate = input.items && input.items.length > 1 ? input.items.join('\n') : text;
    if (
      this.approved.get(this.key(input.context?.serverId, input.stage, input.target)) ===
      this.hash(text)
    )
      return finish('verified_safe_fast_path', 'operator-pinned-content-hash', { type: 'clean' });
    // Arithmetic / empty data have no free-form instruction channel. Text containing just a
    // JSON number/boolean/null is kept intact and cannot introduce an agent instruction.
    if (/^(?:\s*|\s*(?:-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)\s*)$/.test(text))
      return finish('verified_safe_fast_path', 'non-instructional-scalar', { type: 'clean' });
    const highImpact = input.stage === 'call_arguments' && input.capability !== 'PURE_OR_READ';
    if (highImpact && previous)
      return ambiguous(
        'untrusted-prior-context-before-impactful-call',
        JSON.stringify({ priorUntrustedText: previous, currentArguments: input.data }),
        'high',
      );
    const primitiveOnly = (value: unknown): boolean =>
      value === null ||
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      (Array.isArray(value)
        ? value.every(primitiveOnly)
        : typeof value === 'object' && value !== null && Object.values(value).every(primitiveOnly));
    if (
      input.stage === 'call_arguments' &&
      input.capability === 'PURE_OR_READ' &&
      primitiveOnly(input.data)
    )
      return finish('verified_safe_fast_path', 'structured-client-values', { type: 'clean' });
    if (input.stage === 'call_arguments' && input.capability === 'PURE_OR_READ') {
      if (existing.type === 'ambiguous')
        return ambiguous('client-risk-signal', text, existing.riskLevel);
      return finish('verified_safe_fast_path', 'client-input-to-verified-read-only-capability', {
        type: 'clean',
      });
    }
    const reviewPayload =
      previous && ['call_response', 'resource_content', 'prompt_messages'].includes(input.stage)
        ? JSON.stringify({ priorUntrustedText: previous, currentUntrustedText: aggregate })
        : aggregate;
    if (existing.type === 'ambiguous')
      return ambiguous('existing-risk-signal', reviewPayload, existing.riskLevel);
    return ambiguous(
      highImpact ? 'unverified-or-impactful-arguments' : 'untrusted-natural-language',
      reviewPayload,
      highImpact ? 'high' : 'medium',
    );
  }
}

/** Bound provenance extraction even when callers submit deeply nested objects. */
export function collectClientArgumentText(args: unknown): readonly string[] {
  const result: string[] = [];
  let nodes = 0,
    bytes = 0;
  const visit = (value: unknown, depth: number): void => {
    if (depth > 16 || ++nodes > 2048 || result.length >= 32) return;
    if (typeof value === 'string') {
      const size = Buffer.byteLength(value);
      if (size <= 4096 && bytes + size <= 16384) {
        bytes += size;
        result.push(value);
      }
    } else if (value && typeof value === 'object')
      for (const child of Object.values(value)) visit(child, depth + 1);
  };
  visit(args, 0);
  return result;
}
