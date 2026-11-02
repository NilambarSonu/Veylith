/**
 * Safe HTML escape utility to guarantee zero arbitrary HTML injection.
 */
export function escapeHtml(input: string | null | undefined): string {
  if (input === null || input === undefined) return '';
  return String(input)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/\//g, '&#x2F;')
    .replace(/`/g, '&#x60;');
}

/**
 * Format a float ratio (0.0 - 1.0) into a percentage string (e.g., 70.6%).
 */
export function formatPct(val: number | null | undefined): string {
  if (val === null || val === undefined || Number.isNaN(val)) return '—';
  return `${(val * 100).toFixed(1)}%`;
}

/**
 * Format millisecond latency into clean human readable string.
 */
export function formatLatency(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return '—';
  if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
  if (ms < 1000) return `${ms.toFixed(1)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

/**
 * Format standard integers with thousands separators.
 */
export function formatNumber(num: number | null | undefined): string {
  if (num === null || num === undefined || Number.isNaN(num)) return '0';
  return num.toLocaleString();
}

/**
 * Format byte quantities (e.g., 3.4 MB).
 */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

/**
 * Format ISO timestamps to localized short time string.
 */
export function formatIsoTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toISOString().replace('T', ' ').replace('Z', ' UTC');
  } catch {
    return iso;
  }
}

/**
 * Safe DOM element creator that strictly avoids dangerouslySetInnerHTML.
 */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  children: Array<Node | string> = [],
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'className') {
      element.className = value;
    } else if (key.startsWith('data-')) {
      element.setAttribute(key, value);
    } else {
      element.setAttribute(key, value);
    }
  }
  for (const child of children) {
    if (typeof child === 'string') {
      element.appendChild(document.createTextNode(child));
    } else if (child instanceof Node) {
      element.appendChild(child);
    }
  }
  return element;
}
