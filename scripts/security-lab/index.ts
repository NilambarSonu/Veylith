import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { verifyManifest } from './integrity.js';
import { report } from './report.js';
const command = process.argv[2] ?? 'development';
verifyManifest();
const directory = process.env['SECURITY_EVAL_OUTPUT'] ?? 'security-lab/results';
mkdirSync(directory, { recursive: true });
if (command === 'report') {
  report(directory);
} else {
  if (!['development', 'holdout'].includes(command))
    throw new Error('Use development, holdout, or report');
  for (const mode of ['direct', 'deterministic-only', 'mock-semantic']) {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [
          '--expose-gc',
          '--import',
          'tsx',
          'scripts/security-lab/worker.ts',
          mode,
          command,
          directory,
          ...process.argv.slice(3),
        ],
        {
          stdio: 'inherit',
          env: {
            PATH: process.env['PATH'],
            HOME: process.env['HOME'],
            TMPDIR: process.env['TMPDIR'],
          },
        },
      );
      child.on('error', reject);
      child.on('exit', (code) =>
        code === 0 ? resolve() : reject(new Error(`${mode} worker exited ${code}`)),
      );
    });
  }
  report(directory);
}
