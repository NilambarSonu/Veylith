/**
 * Structured logger with secret redaction.
 *
 * Emits JSON-structured log lines. Redacts known sensitive fields
 * from logged objects when redaction is enabled.
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
]);

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class Logger {
  private readonly minLevel: number;
  private readonly redact: boolean;

  constructor(level: string = 'info', redact: boolean = true) {
    this.minLevel = LEVEL_ORDER[level as LogLevel] ?? LEVEL_ORDER.info;
    this.redact = redact;
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
      level,
      msg,
    };

    if (data) {
      entry['data'] = this.redact ? this.redactSensitive(data) : data;
    }

    const writer = level === 'error' ? console.error : console.log;
    writer(JSON.stringify(entry));
  }

  private redactSensitive(obj: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (REDACTED_KEYS.has(key.toLowerCase())) {
        result[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        result[key] = this.redactSensitive(value as Record<string, unknown>);
      } else {
        result[key] = value;
      }
    }
    return result;
  }
}
