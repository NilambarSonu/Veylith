# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Veylith takes security seriously. If you discover a security vulnerability within Veylith, please report it responsibly rather than opening a public issue.

### How to Report

Please email security reports to the maintainer:

- **Contact**: Nilambar Behera
- **Repository**: [https://github.com/NilambarSonu/Veylith](https://github.com/NilambarSonu/Veylith)

Please include:

- A description of the vulnerability and its potential impact.
- Step-by-step reproduction instructions or a minimal proof of concept.
- Details regarding the affected environment and package versions.

### Security Invariants

- API credentials and authentication tokens must never be exposed to browser runtimes or logged.
- The default network binding for the gateway is `127.0.0.1`.
- Any external semantic evaluation (e.g. Meta Muse) must originate strictly from the trusted backend.
