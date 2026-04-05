# Bastion Mail SMTP Relay

Stateless SMTP relay for BastionHQ's email service. Receives inbound email on port 25 and forwards to the Bastion Mail API. Provides an HTTP API for outbound email sending with DKIM signing.

**Stores nothing.** No email content is saved to disk. Logs are limited to 24h retention with no email body logging.

## Quick Setup

```bash
# On a fresh Ubuntu 24.04 VPS:
curl -sL https://raw.githubusercontent.com/trentonb117/Bastion-Mail-SMTP-Relay/main/setup.sh | sudo bash
```

## Architecture

```
Inbound:  Internet → Port 25 → relay.py → POST to Bastion Mail API
Outbound: Bastion Mail Celery → HTTPS :443 → nginx → relay.py → SMTP to recipient MX
```

## Requirements

- Ubuntu 22.04 or 24.04
- Port 25 open (SMTP)
- DNS A record pointing to this server
- rDNS set to match hostname

## Environment Variables

See `env.example` for all required variables.

## Scaling

Run multiple relay nodes:
1. Create new VPS
2. Run setup.sh with same API_SECRET
3. Add new IP to MX and SPF DNS records

## Security

- SSH key-only auth (passwords disabled)
- UFW firewall (only ports 22, 25, 80, 443)
- fail2ban for SSH brute force protection
- TLS via Let's Encrypt (auto-renewal)
- nginx reverse proxy for HTTPS API
- DKIM keys fetched per-domain from admin API (encrypted at rest)
- 24h log retention, no email content in logs
- Systemd sandboxing (ProtectHome, ReadOnlyPaths, MemoryMax)
