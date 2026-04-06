#!/usr/bin/env python3
"""
Bastion Mail SMTP Relay

A minimal SMTP relay that:
- Receives inbound email on port 25 and forwards to the Bastion Mail API
- Provides an HTTP API on port 8025 for outbound email sending
- Handles TLS, DKIM signing, and basic spam checks

Run on a VPS with ports 25 and 8025 open.
"""

import asyncio
import email
import email.utils
import json
import logging
import os
import smtplib
import ssl
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from base64 import b64decode, b64encode

import aiosmtpd.controller
from aiosmtpd.smtp import SMTP as SMTPServer
from aiohttp import web
import requests

try:
    import dkim
    HAS_DKIM = True
except ImportError:
    HAS_DKIM = False

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------

MAIL_API_URL = os.environ.get("MAIL_API_URL", "https://smtp.bastionhq.me")
ADMIN_API_URL = os.environ.get("ADMIN_API_URL", "https://bastionhq.me")
API_SECRET = os.environ.get("API_SECRET", "") or os.environ.get("INBOUND_API_SECRET", "")

# Crash immediately if API_SECRET is not configured — an empty secret is an open relay
if not API_SECRET:
    print("FATAL: API_SECRET (or INBOUND_API_SECRET) environment variable is not set. "
          "The relay cannot start without a secret.", file=sys.stderr)
    sys.exit(1)
HOSTNAME = os.environ.get("HOSTNAME", os.environ.get("MAIL_HOSTNAME", "smtp.bastionhq.me"))
DKIM_KEY_PATH = os.environ.get("DKIM_KEY_PATH", "/opt/bastion-relay/dkim/private.key")
DKIM_SELECTOR = os.environ.get("DKIM_SELECTOR", "bastion")
DKIM_DOMAIN = os.environ.get("DKIM_DOMAIN", "bastionmail.me")
TLS_CERT = os.environ.get("TLS_CERT", "/etc/letsencrypt/live/smtp.bastionhq.me/fullchain.pem")
TLS_KEY = os.environ.get("TLS_KEY", "/etc/letsencrypt/live/smtp.bastionhq.me/privkey.pem")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8025"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("bastion-relay")


# ---------------------------------------------------------------------------
# Allowed recipient domains (fetched from admin API, cached)
# ---------------------------------------------------------------------------

_allowed_domains_cache = {"domains": set(), "expires": 0.0}

def _get_allowed_domains():
    """Fetch verified recipient domains from the admin API. Cached for 5 minutes.
    Falls back to ALLOWED_DOMAINS env var if API is unavailable."""
    now = time.time()
    if _allowed_domains_cache["expires"] > now and _allowed_domains_cache["domains"]:
        return _allowed_domains_cache["domains"]

    if ADMIN_API_URL and API_SECRET:
        try:
            r = requests.get(
                f"{ADMIN_API_URL}/api/domains/verified/",
                headers={"Authorization": f"Bearer {API_SECRET}"},
                timeout=5,
            )
            if r.status_code == 200:
                data = r.json()
                domains = set(data.get("domains", []))
                if domains:
                    _allowed_domains_cache["domains"] = domains
                    _allowed_domains_cache["expires"] = now + 300
                    log.info("Loaded %d allowed domains from admin API", len(domains))
                    return domains
        except Exception as e:
            log.warning("Could not fetch allowed domains from admin API: %s", e)

    # Fallback: ALLOWED_DOMAINS env var (comma-separated)
    env_domains = os.environ.get("ALLOWED_DOMAINS", "")
    if env_domains:
        domains = set(d.strip() for d in env_domains.split(",") if d.strip())
        _allowed_domains_cache["domains"] = domains
        _allowed_domains_cache["expires"] = now + 300
        return domains

    return set()


# ---------------------------------------------------------------------------
# Inbound SMTP Handler
# ---------------------------------------------------------------------------

class InboundHandler:
    """Receives email via SMTP and forwards to the Bastion Mail API."""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        # Reject mail to unknown domains — prevents open relay abuse
        domain = address.split("@")[1] if "@" in address else ""
        if not domain:
            return "550 Invalid recipient address"
        allowed = _get_allowed_domains()
        if allowed and domain not in allowed:
            log.info("Rejected inbound RCPT to unknown domain: %s", domain)
            return "550 Mailbox unavailable"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        log.info(f"Inbound email from {envelope.mail_from} to {envelope.rcpt_tos}")

        try:
            # Parse the raw email
            msg = email.message_from_bytes(envelope.content)

            # Extract body
            body_text = ""
            body_html = ""
            attachments = []

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    disposition = str(part.get("Content-Disposition", ""))
                    content_id = part.get("Content-ID", "").strip("<>")

                    if "attachment" in disposition:
                        attachments.append({
                            "filename": part.get_filename() or "attachment",
                            "content_type": content_type,
                            "data": b64encode(part.get_payload(decode=True) or b"").decode(),
                            "content_id": content_id,
                            "is_inline": False,
                        })
                    elif content_id or "inline" in disposition:
                        # Inline image/content (referenced by cid: in HTML)
                        payload_data = part.get_payload(decode=True)
                        if payload_data and content_type.startswith(("image/", "application/")):
                            attachments.append({
                                "filename": part.get_filename() or content_id or "inline",
                                "content_type": content_type,
                                "data": b64encode(payload_data).decode(),
                                "content_id": content_id,
                                "is_inline": True,
                            })
                    elif content_type == "text/plain":
                        body_text = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    elif content_type == "text/html":
                        body_html = part.get_payload(decode=True).decode("utf-8", errors="replace")
            else:
                content_type = msg.get_content_type()
                payload = msg.get_payload(decode=True)
                if payload:
                    text = payload.decode("utf-8", errors="replace")
                    if content_type == "text/html":
                        body_html = text
                    else:
                        body_text = text

            # Build recipient lists
            to_addrs = [addr for _, addr in email.utils.getaddresses(msg.get_all("To", []))]
            cc_addrs = [addr for _, addr in email.utils.getaddresses(msg.get_all("Cc", []))]

            # Get sender IP from the SMTP session
            sender_ip = ""
            try:
                sender_ip = session.peer[0] if session.peer else ""
            except Exception:
                pass

            # DKIM verification (needs raw bytes)
            dkim_result = {"result": "none", "detail": "Not checked"}
            try:
                if HAS_DKIM:
                    dkim_valid = dkim.verify(envelope.content)
                    dkim_result = {
                        "result": "pass" if dkim_valid else "fail",
                        "detail": "Signature valid" if dkim_valid else "Signature invalid or missing",
                    }
                else:
                    dkim_result = {"result": "none", "detail": "DKIM library not available"}
            except Exception as e:
                dkim_result = {"result": "error", "detail": str(e)[:200]}

            # Reverse DNS check — with explicit timeout to avoid blocking the event loop
            rdns_result = {"result": "none", "detail": "Not checked"}
            if sender_ip:
                try:
                    import socket
                    old_timeout = socket.getdefaulttimeout()
                    socket.setdefaulttimeout(3)  # 3-second cap on DNS lookups
                    try:
                        hostname = socket.gethostbyaddr(sender_ip)[0]
                        # Verify forward lookup matches
                        forward_ips = socket.gethostbyname_ex(hostname)[2]
                        if sender_ip in forward_ips:
                            rdns_result = {"result": "pass", "detail": f"{sender_ip} → {hostname}", "hostname": hostname}
                        else:
                            rdns_result = {"result": "fail", "detail": f"rDNS {hostname} doesn't resolve back to {sender_ip}", "hostname": hostname}
                    finally:
                        socket.setdefaulttimeout(old_timeout)
                except socket.herror:
                    rdns_result = {"result": "fail", "detail": f"No rDNS record for {sender_ip}"}
                except socket.timeout:
                    rdns_result = {"result": "error", "detail": "rDNS lookup timed out"}
                except Exception as e:
                    rdns_result = {"result": "error", "detail": str(e)[:200]}

            # Build payload for API
            payload = {
                "from_address": envelope.mail_from,
                "from_name": str(email.utils.parseaddr(msg.get("From", ""))[0]),
                "to": to_addrs,
                "cc": cc_addrs,
                "subject": msg.get("Subject", ""),
                "body_text": body_text,
                "body_html": body_html,
                "message_id": msg.get("Message-ID", ""),
                "in_reply_to": msg.get("In-Reply-To", ""),
                "references": msg.get("References", ""),
                "headers": {k: v for k, v in msg.items()},
                "attachments": attachments,
                "recipients": envelope.rcpt_tos,
                "sender_ip": sender_ip,
                "dkim_result": dkim_result,
                "rdns_result": rdns_result,
            }

            # POST to Bastion Mail API
            resp = requests.post(
                f"{MAIL_API_URL}/api/v1/inbound/",
                json=payload,
                headers={
                    "Authorization": f"Bearer {API_SECRET}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )

            if resp.status_code in (200, 201):
                log.info("Inbound email forwarded to API (from=%s, recipients=%d)", envelope.mail_from, len(envelope.rcpt_tos))
                return "250 Message accepted"
            else:
                log.error(f"API returned {resp.status_code}: {resp.text[:200]}")
                return f"451 Temporary failure, try again later"

        except Exception as e:
            log.error(f"Error processing inbound email: {e}", exc_info=True)
            return "451 Temporary failure"


# ---------------------------------------------------------------------------
# DKIM key fetcher (per-domain from admin API, cached)
# ---------------------------------------------------------------------------

_dkim_cache = {}  # domain -> {key, selector, expires}

def _get_dkim_key(domain):
    """Fetch DKIM private key for a domain. Checks admin API first, falls back to local key."""
    import time as _time
    now = _time.time()

    # Check cache (5 min TTL)
    cached = _dkim_cache.get(domain)
    if cached and cached["expires"] > now:
        return cached["key"], cached["selector"]

    # Try admin API for per-domain key
    if ADMIN_API_URL and API_SECRET:
        try:
            r = requests.get(
                f"{ADMIN_API_URL}/api/domains/{domain}/dkim/",
                headers={"Authorization": f"Bearer {API_SECRET}"},
                timeout=5,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("use_local_key"):
                    # Default domain — use local VPS key
                    pass
                elif data.get("private_key"):
                    key = data["private_key"].encode()
                    selector = data.get("selector", DKIM_SELECTOR)
                    _dkim_cache[domain] = {"key": key, "selector": selector, "expires": now + 300}
                    log.info(f"DKIM key fetched from API for {domain}")
                    return key, selector
        except Exception as e:
            log.error(f"DKIM API fetch failed for {domain}: {e}")

    # Fallback: local key
    if os.path.exists(DKIM_KEY_PATH):
        with open(DKIM_KEY_PATH, "rb") as f:
            key = f.read()
        _dkim_cache[domain] = {"key": key, "selector": DKIM_SELECTOR, "expires": now + 300}
        return key, DKIM_SELECTOR

    return None, None


# ---------------------------------------------------------------------------
# Outbound HTTP API
# ---------------------------------------------------------------------------

MAX_REQUEST_BYTES = 50 * 1024 * 1024  # 50 MB — hard cap on inbound HTTP payloads


async def handle_send(request):
    """HTTP endpoint for sending outbound email.

    POST /send
    {
        "from_address": "user@bastionhq.me",
        "from_name": "John Smith",
        "to": ["recipient@example.com"],
        "cc": [],
        "subject": "Hello",
        "body_text": "Plain text body",
        "body_html": "<p>HTML body</p>",
        "reply_to": "",
        "message_id": "<unique-id@bastionhq.me>"
    }
    """
    # Auth check
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {API_SECRET}":
        log.warning("Unauthorized /send attempt from %s", request.remote)
        return web.json_response({"error": "Unauthorized"}, status=401)

    # Reject oversized payloads before reading body
    content_length = request.content_length
    if content_length is not None and content_length > MAX_REQUEST_BYTES:
        return web.json_response({"error": "Payload too large"}, status=413)

    try:
        body = await request.read()
        if len(body) > MAX_REQUEST_BYTES:
            return web.json_response({"error": "Payload too large"}, status=413)
        import json as _json
        data = _json.loads(body)
    except Exception:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    from_address = data.get("from_address", "")
    from_name = data.get("from_name", "")
    to_addrs = data.get("to", [])
    cc_addrs = data.get("cc", [])
    subject = data.get("subject", "")
    body_text = data.get("body_text", "")
    body_html = data.get("body_html", "")

    if not from_address or not to_addrs:
        return web.json_response({"error": "from_address and to are required"}, status=400)

    try:
        # Build MIME message
        msg = MIMEMultipart("alternative")
        msg["From"] = f"{from_name} <{from_address}>" if from_name else from_address
        msg["To"] = ", ".join(to_addrs)
        if cc_addrs:
            msg["Cc"] = ", ".join(cc_addrs)
        msg["Subject"] = subject
        msg["Message-ID"] = data.get("message_id") or email.utils.make_msgid(domain=HOSTNAME)
        msg["Date"] = email.utils.formatdate(localtime=True)

        if data.get("reply_to"):
            msg["In-Reply-To"] = data["reply_to"]

        # Check if there are attachments — if so, wrap in mixed multipart
        attachments = data.get("attachments", [])
        if attachments:
            outer = MIMEMultipart("mixed")
            for h in ("From", "To", "Cc", "Subject", "Message-ID", "Date", "In-Reply-To"):
                if msg[h]:
                    outer[h] = msg[h]
                    del msg[h]
            if body_text:
                msg.attach(MIMEText(body_text, "plain", "utf-8"))
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))
            outer.attach(msg)
            for att in attachments:
                from email import encoders
                part = MIMEBase("application", "octet-stream")
                part.set_payload(b64decode(att.get("data", "")))
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", "attachment", filename=att.get("filename", "attachment"))
                outer.attach(part)
            msg = outer
        else:
            if body_text:
                msg.attach(MIMEText(body_text, "plain", "utf-8"))
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))

        # DKIM sign (fetch per-domain key from admin API, fallback to local)
        msg_bytes = msg.as_bytes()
        if HAS_DKIM:
            from_domain = from_address.split("@")[1] if "@" in from_address else DKIM_DOMAIN
            key_data, selector = _get_dkim_key(from_domain)
            if key_data:
                try:
                    sig = dkim.sign(
                        msg_bytes,
                        selector.encode() if isinstance(selector, str) else selector,
                        from_domain.encode() if isinstance(from_domain, str) else from_domain,
                        key_data,
                        include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
                    )
                    msg_bytes = sig + msg_bytes
                    log.info(f"DKIM signed for {from_domain} (selector: {selector})")
                except Exception as e:
                    log.error(f"DKIM signing failed for {from_domain}: {e}")
            else:
                log.warning(f"No DKIM key available for {from_domain}")

        msg_string = msg_bytes.decode("utf-8", errors="replace")

        # Send via SMTP to each recipient's MX
        all_recipients = to_addrs + cc_addrs
        errors = []

        for recipient in all_recipients:
            try:
                parts = recipient.split("@")
                if len(parts) != 2 or not parts[1]:
                    log.warning("Skipping malformed recipient address: %r", recipient)
                    errors.append({"address": recipient, "error": "Invalid email address format"})
                    continue
                domain = parts[1]
                _send_to_mx(domain, from_address, recipient, msg_string)
                log.info("Sent to %s", recipient)
            except Exception as e:
                log.error("Failed to send to %s: %s", recipient, e)
                errors.append({"address": recipient, "error": str(e)})

        if errors and len(errors) == len(all_recipients):
            return web.json_response({"status": "failed", "errors": errors}, status=500)
        elif errors:
            return web.json_response({"status": "partial", "errors": errors}, status=207)
        else:
            return web.json_response({"status": "sent", "recipients": len(all_recipients)})

    except Exception as e:
        log.error(f"Send error: {e}", exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


def _resolve_ipv4(hostname):
    """Resolve hostname to IPv4 address (skip IPv6 to avoid PTR issues)."""
    import socket
    try:
        results = socket.getaddrinfo(hostname, 25, socket.AF_INET, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]  # First IPv4 address
    except Exception:
        pass
    return hostname


def _send_to_mx(domain, from_addr, to_addr, msg_string):
    """Send email to a recipient by looking up their MX record. Forces IPv4."""
    import dns.resolver

    # Look up MX records
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_hosts = sorted(mx_records, key=lambda r: r.preference)
        mx_host = str(mx_hosts[0].exchange).rstrip(".")
    except Exception:
        mx_host = domain

    # Resolve to IPv4 (avoid IPv6 PTR issues)
    mx_ip = _resolve_ipv4(mx_host)

    # Try STARTTLS first, then plain
    try:
        with smtplib.SMTP(mx_ip, 25, timeout=30, local_hostname=HOSTNAME) as smtp:
            smtp.ehlo(HOSTNAME)
            if smtp.has_extn("STARTTLS"):
                smtp.starttls()
                smtp.ehlo(HOSTNAME)
            smtp.sendmail(from_addr, [to_addr], msg_string)
    except Exception as e:
        # Retry with port 587
        try:
            with smtplib.SMTP(mx_ip, 587, timeout=30, local_hostname=HOSTNAME) as smtp:
                smtp.ehlo(HOSTNAME)
                smtp.starttls()
                smtp.ehlo(HOSTNAME)
                smtp.sendmail(from_addr, [to_addr], msg_string)
        except Exception:
            raise e  # Raise original error


async def handle_health(request):
    return web.json_response({"status": "ok", "hostname": HOSTNAME})


async def handle_cache_clear(request):
    """Force-invalidate the DKIM key cache (and optionally allowed domains cache).
    POST /cache/clear?domain=example.com  — clear one domain
    POST /cache/clear                      — clear all domains
    Requires Bearer API_SECRET.
    """
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {API_SECRET}":
        return web.json_response({"error": "Unauthorized"}, status=401)

    domain = request.rel_url.query.get("domain")
    if domain:
        _dkim_cache.pop(domain, None)
        log.info("DKIM cache cleared for domain: %s", domain)
        return web.json_response({"status": "cleared", "domain": domain})
    else:
        _dkim_cache.clear()
        _allowed_domains_cache["domains"] = set()
        _allowed_domains_cache["expires"] = 0.0
        log.info("DKIM + allowed-domains cache fully cleared")
        return web.json_response({"status": "cleared", "scope": "all"})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info(f"Bastion Mail SMTP Relay starting on {HOSTNAME}")
    log.info(f"SMTP port: {SMTP_PORT}, HTTP port: {HTTP_PORT}")
    log.info(f"API URL: {MAIL_API_URL}")

    # Start inbound SMTP server
    handler = InboundHandler()
    controller = aiosmtpd.controller.Controller(
        handler,
        hostname="0.0.0.0",
        port=SMTP_PORT,
        server_hostname=HOSTNAME,
    )
    controller.start()
    log.info(f"SMTP listening on port {SMTP_PORT}")

    # Start outbound HTTP API — bind to 127.0.0.1 so it's only accessible via the
    # nginx reverse proxy (which handles TLS). Never expose directly to the internet.
    app = web.Application()
    app.router.add_post("/send", handle_send)
    app.router.add_get("/health", handle_health)
    app.router.add_post("/cache/clear", handle_cache_clear)

    http_host = os.environ.get("HTTP_HOST", "127.0.0.1")
    log.info(f"HTTP API listening on {http_host}:{HTTP_PORT}")
    web.run_app(app, host=http_host, port=HTTP_PORT)


if __name__ == "__main__":
    main()
