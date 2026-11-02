import { randomUUID } from 'node:crypto';
import type {
  InspectionContext,
  RoutingTrace,
  SecurityInspectionResult,
  ToolCapability,
  PolicyAction,
} from '@veylith/core';
import { ModelClassificationSchema } from '@veylith/meta-adapter';
import type { MetaAdapter, SemanticInspectionResult } from '@veylith/meta-adapter';
import { BoundaryRouter } from './boundary.js';
import { InspectionCache } from '../cache/inspection-cache.js';
import type { ToolCapabilityRegistry } from '../capabilities/registry.js';
import type { ClientSessionManager } from '../sessions/manager.js';

export class BoundaryInspector {
  readonly router: BoundaryRouter;
  private active = 0;
  private readonly waiters: Array<() => void> = [];
  private readonly requests = new Map<string, { count: number; expiresAt: number }>();
  private readonly metrics = {
    semanticInvocations: 0,
    semanticCacheHits: 0,
    semanticUnavailable: 0,
    semanticBudgetRejected: 0,
  };
  private readonly cache = new InspectionCache(128, 60000);
  constructor(
    private readonly adapter: MetaAdapter,
    private readonly registry: ToolCapabilityRegistry,
    sessions: ClientSessionManager,
    private readonly policyVersion: string,
    private readonly failClosed: boolean,
    private readonly defaultDecision: PolicyAction = 'allow',
  ) {
    this.router = new BoundaryRouter(16384, 128, (serverId, sessionId) =>
      sessions.hasActiveSession(sessionId, serverId),
    );
  }
  stats() {
    return { ...this.router.stats(), ...this.metrics };
  }
  cacheHit() {
    this.metrics.semanticCacheHits++;
  }
  screen(
    data: unknown,
    stage: InspectionContext['stage'],
    target: string,
    context?: Partial<InspectionContext>,
    capability?: ToolCapability,
    items?: readonly string[],
    inspectable = true,
  ) {
    const r = this.router.route({ data, stage, target, context, capability, items, inspectable });
    return { ...r.verdict, routing: r.trace, payload: r.payload };
  }
  effectiveRoute(trace: RoutingTrace, model: SemanticInspectionResult): RoutingTrace {
    return model.action === 'review'
      ? {
          ...trace,
          decision: 'unknown_or_uninspectable',
          reason:
            model.mode === 'disabled'
              ? 'semantic-disabled'
              : 'semantic-unavailable-or-budget-limited',
        }
      : trace;
  }
  async infer(
    payload: string,
    stage: 'discovery' | 'call_arguments' | 'call_response',
    trace: RoutingTrace,
    requestId: string,
    metadata?: Record<string, unknown>,
  ): Promise<SemanticInspectionResult> {
    const unavailable = (reason: string): SemanticInspectionResult => {
      this.metrics.semanticUnavailable++;
      return {
        flagged: true,
        action: 'review',
        threatCategory: 'none',
        confidence: 0,
        evidence: [],
        explanation: reason,
        mode: this.adapter.mode,
        model: this.adapter.model,
        durationMs: 0,
      };
    };
    if (trace.decision === 'unknown_or_uninspectable')
      return unavailable('Content is unknown or exceeds the bounded inspection contract');
    if (this.adapter.mode === 'disabled')
      return unavailable('Semantic inspection disabled: content was not verified safe');
    const now = Date.now();
    for (const [k, v] of this.requests) if (v.expiresAt <= now) this.requests.delete(k);
    const count = this.requests.get(requestId)?.count ?? 0;
    if (count >= 16 || this.waiters.length >= 128) {
      this.metrics.semanticBudgetRejected++;
      return unavailable('Semantic budget exceeded');
    }
    if (!this.requests.has(requestId) && this.requests.size >= 256)
      this.requests.delete(this.requests.keys().next().value!);
    this.requests.set(requestId, { count: count + 1, expiresAt: now + 60000 });
    if (this.active >= 4) {
      const admitted = await new Promise<boolean>((resolve) => {
        const wake = () => {
          clearTimeout(timer);
          resolve(true);
        };
        const timer = setTimeout(() => {
          const i = this.waiters.indexOf(wake);
          if (i >= 0) this.waiters.splice(i, 1);
          resolve(false);
        }, 1000);
        this.waiters.push(wake);
      });
      if (!admitted) {
        this.metrics.semanticBudgetRejected++;
        return unavailable('Semantic queue deadline exceeded');
      }
    } else this.active++;
    try {
      this.metrics.semanticInvocations++;
      const result = await this.adapter.inspect(payload, stage, metadata);
      if (
        !ModelClassificationSchema.safeParse(result).success ||
        result.mode !== this.adapter.mode ||
        (!result.flagged && result.action !== 'allow') ||
        (result.flagged && result.action === 'allow')
      )
        return unavailable('Malformed or contradictory semantic adapter output');
      return result;
    } catch {
      return unavailable('Semantic adapter outage');
    } finally {
      const next = this.waiters.shift();
      if (next) next();
      else this.active--;
    }
  }
  async classify(
    ctx: InspectionContext,
    target: string,
    pieces: readonly string[],
    inspectable = true,
    prepared?: ReturnType<BoundaryInspector['screen']>,
  ): Promise<SecurityInspectionResult> {
    const start = performance.now();
    const text = pieces.join('\n');
    const capability =
      ctx.stage === 'call_response'
        ? this.registry.resolveCapability(ctx.serverId, target)
        : 'UNKNOWN';
    const r =
      prepared ?? this.screen(text, ctx.stage, target, ctx, capability, pieces, inspectable);
    const common = {
      id: randomUUID(),
      stage: ctx.stage,
      evaluationDurationMs: performance.now() - start,
      routing: r.routing,
    };
    const category = ctx.stage.startsWith('resource')
      ? 'resource_poisoning'
      : ctx.stage.startsWith('prompt')
        ? 'prompt_poisoning'
        : ctx.stage === 'discovery'
          ? 'tool_poisoning'
          : 'malicious_response';
    if (r.type === 'hard_violation')
      return {
        ...common,
        action: 'block',
        origin: 'deterministic',
        threatCategory: category,
        ruleId: r.match.ruleId,
        explanation: `Malicious content intercepted: ${r.match.description}`,
        evidence: [],
        isConfirmedViolation: true,
      };
    if (r.type === 'clean')
      return {
        ...common,
        action: 'allow',
        origin: 'deterministic',
        threatCategory: 'none',
        explanation: `Verified safe fast path: ${r.routing.reason}`,
        evidence: [],
        isConfirmedViolation: false,
      };
    const key = this.cache.generateKey({
      payload: r.payload,
      stage: ctx.stage,
      policyVersion: this.policyVersion,
      modelVersion: `${this.adapter.mode}:${this.adapter.model}`,
      baselineRevision: this.registry.baselineRevision,
      serverId: ctx.serverId,
      clientId: ctx.clientIdentity,
      sessionId: ctx.sessionId,
      toolName: target,
    });
    const cached = this.cache.get(key);
    if (cached) {
      this.cacheHit();
      if (cached.action === 'allow' || (cached.action === 'review' && !this.failClosed))
        this.router.remember(ctx, text);
      return { ...cached, routing: { ...r.routing, reason: 'scoped-semantic-cache-hit' } };
    }
    const model = await this.infer(r.payload, 'call_response', r.routing, ctx.requestId, {
      target,
      stage: ctx.stage,
    });
    const action =
      model.action === 'review' && (this.failClosed || r.riskLevel === 'high')
        ? 'block'
        : model.flagged
          ? model.action
          : this.defaultDecision;
    const result: SecurityInspectionResult = {
      ...common,
      routing: this.effectiveRoute(r.routing, model),
      action,
      origin: model.mode === 'disabled' ? 'deterministic' : model.mode,
      threatCategory: action === 'block' ? category : model.threatCategory,
      explanation:
        model.action === 'review'
          ? `Unverified content quarantined or marked for review: ${model.explanation}`
          : model.explanation,
      evidence: [],
      isConfirmedViolation: model.flagged && model.action === 'block',
      modelId: model.mode === 'disabled' ? undefined : this.adapter.model,
      tokenUsage: model.tokenUsage,
      confidence: model.confidence,
      evaluationDurationMs: performance.now() - start,
    };
    if (model.action !== 'review') this.cache.set(key, result);
    if (result.action === 'allow' || (result.action === 'review' && !this.failClosed))
      this.router.remember(ctx, text);
    return result;
  }
}
