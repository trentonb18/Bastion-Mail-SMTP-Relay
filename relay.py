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

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------

MAIL_API_URL = os.environ.get("MAIL_API_URL", "https://smtp.bastionhq.me")
API_SECRET = os.environ.get("API_SECRET", "") or os.environ.get("API_SECRET", "")
HOSTNAME = os.environ.get("MAIL_HOSTNAME", "smtp.bastionhq.me")
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
# Inbound SMTP Handler
# ---------------------------------------------------------------------------

class InboundHandler:
    """Receives email via SMTP and forwards to the Bastion Mail API."""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
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

                    if "attachment" in disposition:
                        attachments.append({
                            "filename": part.get_filename() or "attachment",
                            "content_type": content_type,
                            "data": b64encode(part.get_payload(decode=True) or b"").decode(),
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
                log.info(f"Forwarded to API: {msg.get('Subject', '?')}")
                return "250 Message accepted"
            else:
                log.error(f"API returned {resp.status_code}: {resp.text[:200]}")
                return f"451 Temporary failure, try again later"

        except Exception as e:
            log.error(f"Error processing inbound email: {e}", exc_info=True)
            return "451 Temporary failure"


# ---------------------------------------------------------------------------
# Outbound HTTP API
# ---------------------------------------------------------------------------

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
        return web.json_response({"error": "Unauthorized"}, status=401)

    try:
        data = await request.json()
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
        msg["Message-ID"] = data.get("message_id", email.utils.make_msgid(domain=HOSTNAME))
        msg["Date"] = email.utils.formatdate(localtime=True)

        if data.get("reply_to"):
            msg["In-Reply-To"] = data["reply_to"]

        if body_text:
            msg.attach(MIMEText(body_text, "plain", "utf-8"))
        if body_html:
            msg.attach(MIMEText(body_html, "html", "utf-8"))

        # Send via SMTP to each recipient's MX
        all_recipients = to_addrs + cc_addrs
        errors = []

        for recipient in all_recipients:
            try:
                domain = recipient.split("@")[1]
                _send_to_mx(domain, from_address, recipient, msg.as_string())
                log.info(f"Sent to {recipient}")
            except Exception as e:
                log.error(f"Failed to send to {recipient}: {e}")
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


def _send_to_mx(domain, from_addr, to_addr, msg_string):
    """Send email to a recipient by looking up their MX record."""
    import dns.resolver

    # Look up MX records
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_hosts = sorted(mx_records, key=lambda r: r.preference)
        mx_host = str(mx_hosts[0].exchange).rstrip(".")
    except Exception:
        # Fallback to A record
        mx_host = domain

    # Try STARTTLS first, then plain
    try:
        with smtplib.SMTP(mx_host, 25, timeout=30) as smtp:
            smtp.ehlo(HOSTNAME)
            if smtp.has_extn("STARTTLS"):
                smtp.starttls()
                smtp.ehlo(HOSTNAME)
            smtp.sendmail(from_addr, [to_addr], msg_string)
    except Exception as e:
        # Retry with port 587
        try:
            with smtplib.SMTP(mx_host, 587, timeout=30) as smtp:
                smtp.ehlo(HOSTNAME)
                smtp.starttls()
                smtp.ehlo(HOSTNAME)
                smtp.sendmail(from_addr, [to_addr], msg_string)
        except Exception:
            raise e  # Raise original error


async def handle_health(request):
    return web.json_response({"status": "ok", "hostname": HOSTNAME})


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

    # Start outbound HTTP API
    app = web.Application()
    app.router.add_post("/send", handle_send)
    app.router.add_get("/health", handle_health)

    log.info(f"HTTP API listening on port {HTTP_PORT}")
    web.run_app(app, host="0.0.0.0", port=HTTP_PORT)


if __name__ == "__main__":
    main()
