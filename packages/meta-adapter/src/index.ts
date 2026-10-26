/**
 * @veylith/meta-adapter — Future integration boundary for Meta Muse.
 *
 * Phase 0: This module defines the interface contract only. No live API
 * calls are made. The adapter will be implemented in Phase 1 when
 * semantic risk inspection is added.
 *
 * SECURITY: API calls to Meta must originate on the trusted backend.
 * Never expose the API key to browser-delivered code.
 */

/** The result of a semantic risk inspection by the Meta model. */
export interface SemanticInspectionResult {
  /** Whether the model considers the content risky. */
  readonly flagged: boolean;
  /** Risk categories identified. */
  readonly categories: readonly string[];
  /** Free-form explanation from the model. */
  readonly explanation: string;
  /**
   * Raw confidence score from the model.
   * WARNING: This is NOT a calibrated probability. Do not use it as one
   * without empirical calibration evidence.
   */
  readonly rawScore?: number;
}

/** Interface for the Meta Muse adapter. */
export interface MetaAdapter {
  /**
   * Inspect content for semantic security risks.
   * Phase 0: Always returns a stub result indicating no inspection was performed.
   */
  inspect(content: string): Promise<SemanticInspectionResult>;
}

/**
 * Stub implementation that performs no actual API calls.
 * Used during Phase 0 development.
 */
export class StubMetaAdapter implements MetaAdapter {
  async inspect(_content: string): Promise<SemanticInspectionResult> {
    return {
      flagged: false,
      categories: [],
      explanation: 'Meta Muse integration not yet active (Phase 0 stub)',
    };
  }
}
