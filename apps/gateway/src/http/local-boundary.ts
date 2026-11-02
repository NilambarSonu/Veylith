/** Local transport guard. This does not authenticate people or remote reverse proxies. */
export function localBoundaryError(
  remoteAddress: string | undefined,
  host: string | undefined,
  origin: string | undefined,
  port: number,
): string | undefined {
  if (!remoteAddress || !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(remoteAddress))
    return 'Remote HTTP access is disabled';
  try {
    if (!host) return 'Missing Host header';
    const target = new URL(`http://${host}`);
    if (
      !['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname) ||
      target.username ||
      target.password ||
      target.pathname !== '/' ||
      target.search ||
      target.hash ||
      Number(target.port || 80) !== port
    )
      return 'Host must identify this loopback endpoint';
    if (origin) {
      const source = new URL(origin);
      if (
        source.origin !== origin ||
        !['http:', 'https:'].includes(source.protocol) ||
        source.hostname !== target.hostname ||
        Number(source.port || (source.protocol === 'https:' ? 443 : 80)) !== port
      )
        return 'Cross-origin browser access is disabled';
    }
  } catch {
    return 'Invalid local Host or Origin';
  }
  return undefined;
}
