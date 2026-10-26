# Contributing to Veylith

Thank you for your interest in contributing to Veylith!

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for all contributors.

## Development Workflow

1. All development happens on feature or phase branches (e.g. `dev/phase-0-foundation`).
2. The `main` branch is protected and reserved for verified, stable releases.
3. Install dependencies using `pnpm install`.
4. Ensure code adheres to quality gates before submitting a PR:
   ```bash
   pnpm typecheck
   pnpm lint
   pnpm format:check
   pnpm test:all
   ```

## Security Best Practices

- Never commit credentials, `.env` files, or API keys to the repository.
- Run tests only against safe, local mock servers. No live malicious external network calls during testing.
- Respect the Apache-2.0 license headers and guidelines.
