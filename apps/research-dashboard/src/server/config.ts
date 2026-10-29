import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';

export interface DashboardConfig {
  readonly host: string;
  readonly port: number;
  readonly projectRoot: string;
  readonly labEvidenceDir: string;
  readonly phase2fEvidenceDir: string;
  readonly docsDir: string;
}

function findProjectRoot(): string {
  let current = dirname(fileURLToPath(import.meta.url));
  while (current !== dirname(current)) {
    const pkgPath = resolve(current, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        if (pkg.name === 'veylith') {
          return current;
        }
      } catch {
        // Continue walking up
      }
    }
    current = dirname(current);
  }
  return resolve(process.cwd());
}

export function loadDashboardConfig(): DashboardConfig {
  const host = '127.0.0.1'; // Enforced loopback-only binding
  const envPort = process.env['VEYLITH_DASHBOARD_PORT'] ?? process.env['PORT'];
  const port = envPort ? Number.parseInt(envPort, 10) : 8789;

  if (Number.isNaN(port) || port < 1024 || port > 65535) {
    throw new Error(`Invalid port configuration: ${envPort}. Must be between 1024 and 65535.`);
  }

  // Repository root reliably discovered
  const projectRoot = findProjectRoot();
  const labEvidenceDir = resolve(projectRoot, 'security-lab');
  const phase2fEvidenceDir = resolve(labEvidenceDir, 'phase-2f', 'evidence');
  const docsDir = resolve(projectRoot, 'docs');

  return {
    host,
    port,
    projectRoot,
    labEvidenceDir,
    phase2fEvidenceDir,
    docsDir,
  };
}
