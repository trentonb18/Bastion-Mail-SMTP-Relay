# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Bastion Mail SMTP Relay, please report it responsibly.

**Email:** security@bastionhq.me

**Do NOT open a public GitHub issue for security vulnerabilities.**

We will acknowledge your report within 48 hours and provide a timeline for a fix.

## Scope

This relay is designed to be stateless — it should never store email content to disk. If you find a scenario where it does, that is a critical vulnerability.

## Security Design

- All secrets loaded from environment variables, never hardcoded
- DKIM private keys fetched from API over HTTPS, cached in memory for max 5 minutes
- No email content written to disk or logs
- Journal retention limited to 24 hours
- Systemd sandboxing restricts filesystem access
