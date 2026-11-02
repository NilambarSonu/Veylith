/**
 * Lightweight Circuit Breaker for Upstream and Semantic Model Calls.
 *
 * Implements:
 *   - CLOSED: Normal operation, forwards calls.
 *   - OPEN: Upstream/model has failed repeatedly; fast-fails without wasting resources or hanging.
 *   - HALF_OPEN: Probes upstream health with bounded attempts to safely recover.
 */

export type CircuitState = 'closed' | 'open' | 'half_open';

export interface CircuitBreakerOptions {
  /** Consecutive failures before opening the circuit (default: 5) */
  readonly failureThreshold?: number;
  /** Cooldown duration in ms before attempting recovery in half_open state (default: 10,000ms) */
  readonly resetTimeoutMs?: number;
  /** Successful consecutive calls in half_open required to close circuit (default: 2) */
  readonly halfOpenSuccessThreshold?: number;
}

export class CircuitBreakerOpenError extends Error {
  constructor(message = 'Circuit breaker is OPEN — upstream requests are temporarily rejected') {
    super(message);
    this.name = 'CircuitBreakerOpenError';
  }
}

export class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly halfOpenSuccessThreshold: number;

  constructor(options?: CircuitBreakerOptions) {
    this.failureThreshold = options?.failureThreshold ?? 5;
    this.resetTimeoutMs = options?.resetTimeoutMs ?? 10000;
    this.halfOpenSuccessThreshold = options?.halfOpenSuccessThreshold ?? 2;
  }

  getState(): CircuitState {
    if (this.state === 'open') {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.resetTimeoutMs) {
        this.state = 'half_open';
        this.successCount = 0;
      }
    }
    return this.state;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    const currentState = this.getState();

    if (currentState === 'open') {
      throw new CircuitBreakerOpenError();
    }

    try {
      const result = await fn();
      this.recordSuccess();
      return result;
    } catch (err) {
      this.recordFailure();
      throw err;
    }
  }

  recordSuccess(): void {
    if (this.state === 'half_open') {
      this.successCount++;
      if (this.successCount >= this.halfOpenSuccessThreshold) {
        this.state = 'closed';
        this.failureCount = 0;
        this.successCount = 0;
      }
    } else if (this.state === 'closed') {
      this.failureCount = 0;
    }
  }

  recordFailure(): void {
    this.lastFailureTime = Date.now();
    this.failureCount++;

    if (this.state === 'half_open') {
      this.state = 'open';
    } else if (this.state === 'closed' && this.failureCount >= this.failureThreshold) {
      this.state = 'open';
    }
  }

  reset(): void {
    this.state = 'closed';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
  }
}
