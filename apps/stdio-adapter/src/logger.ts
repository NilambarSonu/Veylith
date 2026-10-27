/**
 * Stdio-Safe Structured Logger for Veylith Stdio Adapter.
 *
 * CRITICAL PROTOCOL INVARIANT:
 * In an MCP stdio transport, stdout is strictly reserved for JSON-RPC 2.0 messages.
 * Any non-protocol data written to stdout will corrupt client JSON-RPC parsing.
 *
 * Therefore, this logger routes ALL output (debug, info, warn, error)
 * EXCLUSIVELY to process.stderr.
 *
 * It also applies strict secret redaction to prevent accidental credential leakage
 * in developer logs or client consoles.
 */

const REDACTED_KEYS = new Set([
  'authorization',
  'cookie',
  'x-api-key',
  'api_key',
  'apikey',
  'password',
  'secret',
  'token',
  'meta_model_api_key',
  'meta_api_key',
  'bearer',
  'private_key',
]);

const SECRET_PATTERNS = [
  /sk-[a-zA-Z0-9_-]{16,}/g,
  /bearer\s+[a-zA-Z0-9_.-]{16,}/gi,
  /ghp_[a-zA-Z0-9]{30,}/g,
];

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class StdioLogger {
  private readonly minLevel: number;
  private readonly redact: boolean;
  private readonly knownSecretValues: Set<string>;
  private readonly stream: { write: (str: string) => boolean | void };

  constructor(
    level: string = 'info',
    redact: boolean = true,
    stream: { write: (str: string) => boolean | void } = process.stderr,
  ) {
    this.minLevel = LEVEL_ORDER[level as LogLevel] ?? LEVEL_ORDER.info;
    this.redact = redact;
    this.stream = stream;
    this.knownSecretValues = new Set<string>();

    // Register active process secrets to redact if present
    const envVarsToScrub = [
      'META_MODEL_API_KEY',
      'META_API_KEY',
      'OPENAI_API_KEY',
      'ANTHROPIC_API_KEY',
      'GITHUB_TOKEN',
    ];
    for (const v of envVarsToScrub) {
      const val = process.env[v];
      if (val && val.length > 5) {
        this.knownSecretValues.add(val);
      }
    }
  }

  debug(msg: string, data?: Record<string, unknown>): void {
    this.log('debug', msg, data);
  }

  info(msg: string, data?: Record<string, unknown>): void {
    this.log('info', msg, data);
  }

  warn(msg: string, data?: Record<string, unknown>): void {
    this.log('warn', msg, data);
  }

  error(msg: string, data?: Record<string, unknown>): void {
    this.log('error', msg, data);
  }

  private log(level: LogLevel, msg: string, data?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < this.minLevel) return;

    const entry: Record<string, unknown> = {
      ts: new Date().toISOString(),
      service: 'veylith-stdio',
      level,
      msg: this.redact ? this.scrubText(msg) : msg,
    };

    if (data) {
      entry['data'] = this.redact ? this.redactSensitive(data) : data;
    }

    // MANDATORY: write strictly to stderr so stdout JSON-RPC stream remains uncorrupted
    this.stream.write(`${JSON.stringify(entry)}\n`);
  }

  private scrubText(text: string): string {
    let result = text;
    for (const secret of this.knownSecretValues) {
      result = result.replaceAll(secret, '[REDACTED]');
    }
    for (const pattern of SECRET_PATTERNS) {
      result = result.replace(pattern, '[REDACTED]');
    }
    return result;
  }

  private redactSensitive(obj: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      if (
        REDACTED_KEYS.has(lowerKey) ||
        /(?:api[_-]?key|secret|token|password|auth|credential|private[_-]?key)/i.test(lowerKey)
      ) {
        result[key] = '[REDACTED]';
      } else if (typeof value === 'string') {
        result[key] = this.scrubText(value);
      } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        result[key] = this.redactSensitive(value as Record<string, unknown>);
      } else if (Array.isArray(value)) {
        result[key] = value.map((item) => {
          if (typeof item === 'string') return this.scrubText(item);
          if (typeof item === 'object' && item !== null) {
            return this.redactSensitive(item as Record<string, unknown>);
          }
          return item;
        });
      } else {
        result[key] = value;
      }
    }
    return result;
  }
}
