/**
 * Gateway request/response envelope types.
 *
 * These represent the Veylith-internal view of an MCP interaction passing
 * through the gateway. They are NOT MCP protocol types — they carry
 * additional metadata for observability and policy evaluation.
 */

/** Metadata attached to every request flowing through the gateway. */
export interface RequestMeta {
  /** Unique identifier for this request, generated at the gateway edge. */
  readonly requestId: string;
  /** ISO-8601 timestamp of when the request entered the gateway. */
  readonly receivedAt: string;
  /** The JSON-RPC method name (e.g. 'tools/call', 'tools/list'). */
  readonly method: string;
  /** For tools/call: the tool name being invoked. */
  readonly toolName?: string;
  /** Source IP/identifier of the requesting client. */
  readonly source?: string;
}

/** A request as seen by the Veylith gateway. */
export interface GatewayRequest {
  readonly meta: RequestMeta;
  /** The raw JSON-RPC request body. Treated as opaque at this layer. */
  readonly body: unknown;
}

/** A response as returned by the Veylith gateway. */
export interface GatewayResponse {
  readonly meta: RequestMeta;
  /** The raw JSON-RPC response body. */
  readonly body: unknown;
  /** Duration of the full gateway round-trip in milliseconds. */
  readonly durationMs: number;
}
