/**
 * Veylith error hierarchy.
 *
 * All Veylith-specific errors extend VeylithError so they can be caught
 * and handled uniformly at the gateway boundary.
 */

export class VeylithError extends Error {
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'VeylithError';
    this.code = code;
  }
}

/** Thrown when a policy rule blocks a request. */
export class PolicyBlockedError extends VeylithError {
  public readonly ruleId: string;

  constructor(message: string, ruleId: string) {
    super(message, 'POLICY_BLOCKED');
    this.name = 'PolicyBlockedError';
    this.ruleId = ruleId;
  }
}

/** Thrown when the upstream MCP server is unreachable or returns an error. */
export class UpstreamError extends VeylithError {
  public readonly statusCode?: number;

  constructor(message: string, statusCode?: number) {
    super(message, 'UPSTREAM_ERROR');
    this.name = 'UpstreamError';
    this.statusCode = statusCode;
  }
}

/** Thrown when configuration is invalid or missing. */
export class ConfigError extends VeylithError {
  constructor(message: string) {
    super(message, 'CONFIG_ERROR');
    this.name = 'ConfigError';
  }
}
