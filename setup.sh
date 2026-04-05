#!/bin/bash
# ============================================================================
# Bastion Mail SMTP Relay — VPS Setup Script
#
# Deploys a stateless SMTP relay on Ubuntu 22.04/24.04.
# The relay stores NOTHING — no emails, no user data, no logs of content.
# It is a pipe: receive SMTP → POST to API, receive API call → send SMTP.
#
# Designed to be disposable — destroy and recreate from this script anytime.
# Run multiple instances behind DNS round-robin for scaling.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/trentonb117/Bastion-Mail/main/smtp-server/setup.sh | sudo bash
#   OR
#   chmod +x setup.sh && sudo ./setup.sh
# ============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[BASTION]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo ./setup.sh"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║  Bastion Mail SMTP Relay Setup       ║"
echo "  ║  Stateless • Secure • Disposable     ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ============================================================================
# Configuration
# ============================================================================

read -p "Hostname (e.g., smtp.bastionhq.me): " HOSTNAME
read -p "Bastion Mail API URL (e.g., https://smtp.bastionhq.me): " API_URL
read -p "API secret (INBOUND_API_SECRET): " API_SECRET
read -p "Email for Let's Encrypt: " LE_EMAIL

[[ -z "$HOSTNAME" ]] && error "Hostname required"
[[ -z "$API_URL" ]] && error "API URL required"
[[ -z "$API_SECRET" ]] && error "API secret required"
[[ -z "$LE_EMAIL" ]] && error "Email required"

SERVER_IP=$(curl -s ifconfig.me)
log "Server IP: $SERVER_IP"

# ============================================================================
# 1. System hardening
# ============================================================================

log "Hardening system..."

# Updates
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq ufw fail2ban curl wget python3 python3-pip python3-venv certbot

# SSH: key-only, no root password login
sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
systemctl restart sshd

# Firewall: only SSH + SMTP
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 25/tcp     # SMTP inbound
ufw allow 80/tcp     # Let's Encrypt challenge only
ufw --force enable

# fail2ban for SSH
cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 3600
findtime = 600
EOF
systemctl enable fail2ban && systemctl restart fail2ban

# Auto security updates
apt-get install -y -qq unattended-upgrades
echo 'Unattended-Upgrade::Automatic-Reboot "false";' > /etc/apt/apt.conf.d/51bastion

# Disable unnecessary services
systemctl disable --now snapd 2>/dev/null || true

# Sysctl hardening
cat >> /etc/sysctl.d/99-bastion.conf << 'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
EOF
sysctl -p /etc/sysctl.d/99-bastion.conf 2>/dev/null

log "System hardened"

# ============================================================================
# 2. TLS certificate
# ============================================================================

log "Obtaining TLS certificate..."
certbot certonly --standalone --non-interactive --agree-tos \
    --email "$LE_EMAIL" -d "$HOSTNAME" 2>/dev/null \
    || warn "Certbot failed — ensure DNS A record points to $SERVER_IP first"

# Auto-renew
echo "0 3 * * * root certbot renew --quiet --deploy-hook 'systemctl restart bastion-relay'" \
    > /etc/cron.d/bastion-certbot

# ============================================================================
# 3. DKIM key
# ============================================================================

log "Generating DKIM key..."
mkdir -p /opt/bastion-relay/dkim
openssl genrsa -out /opt/bastion-relay/dkim/private.key 2048 2>/dev/null
openssl rsa -in /opt/bastion-relay/dkim/private.key -pubout -out /opt/bastion-relay/dkim/public.key 2>/dev/null
chmod 600 /opt/bastion-relay/dkim/private.key

DKIM_PUB=$(grep -v "PUBLIC KEY" /opt/bastion-relay/dkim/public.key | tr -d '\n')

# ============================================================================
# 4. Install relay
# ============================================================================

log "Setting up relay..."

# Create dedicated user (no shell, no home)
useradd -r -s /usr/sbin/nologin -d /opt/bastion-relay bastion 2>/dev/null || true

# Python venv
python3 -m venv /opt/bastion-relay/venv
/opt/bastion-relay/venv/bin/pip install -q aiosmtpd aiohttp requests dnspython dkimpy

# Write the relay script
cat > /opt/bastion-relay/relay.py << 'PYEOF'
#!/usr/bin/env python3
"""
Bastion Mail SMTP Relay — Stateless

- Receives SMTP on port 25, POSTs to API, forgets immediately
- Receives HTTP on port 8025, sends SMTP, forgets immediately
- Stores NOTHING. Logs errors only (no email content).
- Signs outbound with DKIM.
"""

import asyncio
import email
import email.utils
import json
import logging
import os
import smtplib
import sys
import time
from base64 import b64encode
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from aiohttp import web
from aiosmtpd.controller import Controller
import requests

try:
    import dkim
    HAS_DKIM = True
except ImportError:
    HAS_DKIM = False

# Config
API_URL = os.environ["MAIL_API_URL"]
API_SECRET = os.environ["API_SECRET"]
HOSTNAME = os.environ.get("HOSTNAME", "smtp.bastionhq.me")
DKIM_KEY = os.environ.get("DKIM_KEY_PATH", "/opt/bastion-relay/dkim/private.key")
DKIM_SELECTOR = os.environ.get("DKIM_SELECTOR", "bastion")
DKIM_DOMAIN = os.environ.get("DKIM_DOMAIN", "bastionhq.me")

# Logging — errors only, never log email content
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("relay")

# Suppress verbose libs
logging.getLogger("aiosmtpd").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)


# ── Inbound ─────────────────────────────────────────────────────────────

class InboundHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        sender = envelope.mail_from
        recipients = envelope.rcpt_tos
        log.info(f"IN: {sender} -> {recipients}")

        try:
            msg = email.message_from_bytes(envelope.content)

            body_text = ""
            body_html = ""
            attachments = []

            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    disp = str(part.get("Content-Disposition", ""))
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    if "attachment" in disp:
                        attachments.append({
                            "filename": part.get_filename() or "file",
                            "content_type": ct,
                            "data": b64encode(payload).decode(),
                        })
                    elif ct == "text/plain" and not body_text:
                        body_text = payload.decode("utf-8", errors="replace")
                    elif ct == "text/html" and not body_html:
                        body_html = payload.decode("utf-8", errors="replace")
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    t = payload.decode("utf-8", errors="replace")
                    if msg.get_content_type() == "text/html":
                        body_html = t
                    else:
                        body_text = t

            data = {
                "from_address": sender,
                "from_name": email.utils.parseaddr(msg.get("From", ""))[0],
                "to": [a for _, a in email.utils.getaddresses(msg.get_all("To", []))],
                "cc": [a for _, a in email.utils.getaddresses(msg.get_all("Cc", []))],
                "subject": msg.get("Subject", ""),
                "body_text": body_text,
                "body_html": body_html,
                "message_id": msg.get("Message-ID", ""),
                "in_reply_to": msg.get("In-Reply-To", ""),
                "references": msg.get("References", ""),
                "recipients": recipients,
                "attachments": attachments,
            }

            r = requests.post(
                f"{API_URL}/api/v1/inbound/",
                json=data,
                headers={"Authorization": f"Bearer {API_SECRET}"},
                timeout=30,
            )

            if r.status_code in (200, 201):
                log.info(f"IN: delivered ({r.status_code})")
                return "250 OK"
            else:
                log.error(f"IN: API {r.status_code}")
                return "451 Try again later"

        except Exception as e:
            log.error(f"IN: error — {type(e).__name__}: {e}")
            return "451 Try again later"


# ── Outbound ────────────────────────────────────────────────────────────

_dkim_cache = {}  # domain -> {key, selector, expires}

def _get_dkim_key(domain):
    """Fetch DKIM private key from admin API, cached for 5 minutes."""
    now = time.time()
    cached = _dkim_cache.get(domain)
    if cached and cached["expires"] > now:
        return cached["key"], cached["selector"]
    try:
        admin_url = os.environ.get("ADMIN_API_URL", API_URL.replace("mail.", "admin."))
        r = requests.get(
            f"{admin_url}/api/domains/{domain}/dkim/",
            headers={"Authorization": f"Bearer {API_SECRET}"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("use_local_key"):
                # Use local VPS key for default domain
                key_path = os.environ.get("DKIM_KEY_PATH", "/opt/bastion-relay/dkim/private.key")
                if os.path.exists(key_path):
                    with open(key_path, "rb") as f:
                        key = f.read()
                    _dkim_cache[domain] = {"key": key, "selector": data["selector"], "expires": now + 300}
                    return key, data["selector"]
            else:
                key = data["private_key"].encode()
                selector = data["selector"]
                _dkim_cache[domain] = {"key": key, "selector": selector, "expires": now + 300}
                return key, selector
    except Exception as e:
        log.error(f"DKIM key fetch failed for {domain}: {e}")
    # Fallback to local key
    if os.path.exists(DKIM_KEY):
        with open(DKIM_KEY, "rb") as f:
            return f.read(), DKIM_SELECTOR
    return None, None


def _sign_dkim(msg_bytes, from_domain=None):
    """Sign message with DKIM. Fetches per-domain key from API."""
    if not HAS_DKIM:
        return msg_bytes
    if not from_domain:
        from_domain = DKIM_DOMAIN
    key, selector = _get_dkim_key(from_domain)
    if not key:
        return msg_bytes
    try:
        sig = dkim.sign(
            msg_bytes,
            selector.encode() if isinstance(selector, str) else selector,
            from_domain.encode() if isinstance(from_domain, str) else from_domain,
            key,
            include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
        )
        return sig + msg_bytes
    except Exception as e:
        log.error(f"DKIM sign failed for {from_domain}: {e}")
        return msg_bytes


def _resolve_mx(domain):
    """Get the MX host for a domain."""
    import dns.resolver
    try:
        records = dns.resolver.resolve(domain, "MX")
        best = sorted(records, key=lambda r: r.preference)[0]
        return str(best.exchange).rstrip(".")
    except Exception:
        return domain


def _smtp_send(from_addr, to_addr, msg_string):
    """Send to one recipient via their MX."""
    domain = to_addr.split("@")[1]
    mx = _resolve_mx(domain)

    with smtplib.SMTP(mx, 25, timeout=30) as s:
        s.ehlo(HOSTNAME)
        if s.has_extn("STARTTLS"):
            s.starttls()
            s.ehlo(HOSTNAME)
        s.sendmail(from_addr, [to_addr], msg_string)


async def handle_send(request):
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {API_SECRET}":
        return web.json_response({"error": "unauthorized"}, status=401)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "bad json"}, status=400)

    from_addr = data.get("from_address", "")
    from_name = data.get("from_name", "")
    to_list = data.get("to", [])
    cc_list = data.get("cc", [])
    subject = data.get("subject", "")
    body_text = data.get("body_text", "")
    body_html = data.get("body_html", "")

    if not from_addr or not to_list:
        return web.json_response({"error": "from_address and to required"}, status=400)

    log.info(f"OUT: {from_addr} -> {to_list}")

    msg = MIMEMultipart("alternative")
    msg["From"] = f"{from_name} <{from_addr}>" if from_name else from_addr
    msg["To"] = ", ".join(to_list)
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = data.get("message_id") or email.utils.make_msgid(domain=HOSTNAME)

    if data.get("in_reply_to"):
        msg["In-Reply-To"] = data["in_reply_to"]
    if data.get("references"):
        msg["References"] = data["references"]

    if body_text:
        msg.attach(MIMEText(body_text, "plain", "utf-8"))
    if body_html:
        msg.attach(MIMEText(body_html, "html", "utf-8"))

    # DKIM sign using the sender's domain key
    from_domain = from_addr.split("@")[1] if "@" in from_addr else DKIM_DOMAIN
    msg_bytes = _sign_dkim(msg.as_bytes(), from_domain=from_domain)
    msg_string = msg_bytes.decode("utf-8", errors="replace")

    errors = []
    sent = 0
    for addr in to_list + cc_list:
        try:
            _smtp_send(from_addr, addr, msg_string)
            sent += 1
        except Exception as e:
            log.error(f"OUT: failed {addr} — {e}")
            errors.append({"address": addr, "error": str(e)})

    if sent == 0:
        return web.json_response({"status": "failed", "errors": errors}, status=500)
    if errors:
        return web.json_response({"status": "partial", "sent": sent, "errors": errors}, status=207)
    return web.json_response({"status": "sent", "sent": sent})


async def handle_health(request):
    return web.json_response({"status": "ok", "hostname": HOSTNAME, "time": int(time.time())})


# ── Main ────────────────────────────────────────────────────────────────

def main():
    log.info(f"Starting relay: {HOSTNAME}")

    controller = Controller(InboundHandler(), hostname="0.0.0.0", port=25, server_hostname=HOSTNAME)
    controller.start()
    log.info("SMTP listening on :25")

    app = web.Application()
    app.router.add_post("/send", handle_send)
    app.router.add_get("/health", handle_health)

    log.info("HTTP API listening on :8025")
    web.run_app(app, host="127.0.0.1", port=8025)


if __name__ == "__main__":
    main()
PYEOF

chown -R bastion:bastion /opt/bastion-relay
chmod 600 /opt/bastion-relay/relay.py

# ============================================================================
# 5. Environment file (secrets go here, not in the service)
# ============================================================================

read -p "Admin API URL (e.g., https://bastionhq.me): " ADMIN_API_URL
[[ -z "$ADMIN_API_URL" ]] && ADMIN_API_URL="https://bastionhq.me"

cat > /opt/bastion-relay/.env << EOF
MAIL_API_URL=$API_URL
ADMIN_API_URL=$ADMIN_API_URL
API_SECRET=$API_SECRET
HOSTNAME=$HOSTNAME
DKIM_KEY_PATH=/opt/bastion-relay/dkim/private.key
DKIM_SELECTOR=bastion
DKIM_DOMAIN=bastionmail.me
EOF

chmod 600 /opt/bastion-relay/.env
chown bastion:bastion /opt/bastion-relay/.env

# ============================================================================
# 6. Systemd service
# ============================================================================

log "Creating systemd service..."

cat > /etc/systemd/system/bastion-relay.service << EOF
[Unit]
Description=Bastion Mail SMTP Relay
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/bastion-relay
EnvironmentFile=/opt/bastion-relay/.env
ExecStart=/opt/bastion-relay/venv/bin/python /opt/bastion-relay/relay.py
Restart=always
RestartSec=5

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=/opt/bastion-relay /tmp
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# No persistent logging of email content
StandardOutput=journal
StandardError=journal

# Resource limits
LimitNOFILE=65535
MemoryMax=256M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

# Limit journald retention (no long-term log storage)
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/bastion.conf << EOF
[Journal]
MaxRetentionSec=24h
MaxFileSec=6h
SystemMaxUse=50M
EOF

systemctl daemon-reload
systemctl enable bastion-relay
systemctl restart systemd-journald

# ============================================================================
# 7. Nginx reverse proxy (TLS termination for relay HTTP API)
# ============================================================================

log "Installing nginx..."
apt-get install -y -qq nginx

# Disable default site
rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/bastion-relay << EOF
server {
    listen 443 ssl http2;
    server_name $HOSTNAME;

    ssl_certificate /etc/letsencrypt/live/$HOSTNAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$HOSTNAME/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Relay HTTP API — only /send and /health
    location /send {
        proxy_pass http://127.0.0.1:8025/send;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 60s;
    }

    location /health {
        proxy_pass http://127.0.0.1:8025/health;
    }

    # Block everything else
    location / {
        return 404;
    }
}

# Redirect HTTP to HTTPS (except Let's Encrypt challenges)
server {
    listen 80;
    server_name $HOSTNAME;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF

ln -sf /etc/nginx/sites-available/bastion-relay /etc/nginx/sites-enabled/
nginx -t && systemctl enable nginx && systemctl restart nginx

log "Nginx configured — HTTPS on :443 proxying to relay on :8025"

# Update certbot to reload nginx on renewal
echo "0 3 * * * root certbot renew --quiet --deploy-hook 'systemctl restart bastion-relay && systemctl restart nginx'" \
    > /etc/cron.d/bastion-certbot

# ============================================================================
# 8. Start
# ============================================================================

log "Starting relay..."
systemctl start bastion-relay
sleep 2

if systemctl is-active --quiet bastion-relay; then
    log "Relay is running"
else
    warn "Relay failed to start — check: journalctl -u bastion-relay -n 50"
fi

# ============================================================================
# 8. Cleanup — remove setup artifacts
# ============================================================================

# Remove apt cache to minimize disk footprint
apt-get clean -qq

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  Bastion Mail SMTP Relay — Setup Complete        ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
log "Relay: systemctl status bastion-relay"
log "Logs:  journalctl -u bastion-relay -f (24h retention only)"
log ""
log "Ports: 25 (SMTP inbound), 443 (HTTPS API via nginx)"
log "Data stored: NONE"
log ""
log "DNS records needed:"
echo ""
echo "  A record:"
echo "    smtp.bastionhq.me → $SERVER_IP"
echo ""
echo "  MX record:"
echo "    bastionhq.me → smtp.bastionhq.me (priority 10)"
echo ""
echo "  SPF (TXT on bastionhq.me):"
echo "    v=spf1 ip4:$SERVER_IP ~all"
echo ""
echo "  DKIM (TXT on bastion._domainkey.bastionhq.me):"
echo "    v=DKIM1; k=rsa; p=$DKIM_PUB"
echo ""
echo "  DMARC (TXT on _dmarc.bastionhq.me):"
echo "    v=DMARC1; p=quarantine; rua=mailto:dmarc@bastionhq.me"
echo ""
log "To add another relay node:"
log "  1. Create new VPS"
log "  2. Run this script with same API_SECRET"
log "  3. Add its IP to your MX/SPF records"
log ""
log "To destroy: systemctl stop bastion-relay && rm -rf /opt/bastion-relay"
echo ""
