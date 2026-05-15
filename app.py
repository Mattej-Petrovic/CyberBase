"""CyberBase Flask app.

app.py v14
app.py v14 builds on v13
"""

import random
import json
import os
import re
import sys
import hashlib
import secrets
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Any, Optional
from auth_routes import auth_bp, set_current_user_from_session_cookie, api_login_required

from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, g, has_request_context, session
from flask_babel import Babel, get_locale, gettext as _

_BASE_DIR = os.path.dirname(__file__)
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from services.log_analyzer import analyze_log_content, LogAnalyzerError
from services.ai_assistant import handle_ai_request, AiAssistantError, SESSION_COOKIE_NAME
from user_profile import ensure_user_doc
from services.mongo_client import get_db
from firebase_admin_init import verify_id_token

logger = logging.getLogger(__name__)

# Server side idempotency and a short cache to avoid double triggering
_LOG_ANALYZER_CACHE_TTL_SECONDS = 10.0
_LOG_ANALYZER_CACHE: dict[str, tuple[float, dict]] = {}
_LOG_ANALYZER_INFLIGHT: dict[str, threading.Event] = {}
_LOG_ANALYZER_LOCK = threading.Lock()

app = Flask(__name__)
app.json.ensure_ascii = False

_SUPPORTED_LOCALES = ("en", "sv")
_LANG_COOKIE_NAME = "cb_lang"
_LANG_SESSION_KEY = "cb_lang"
_PORT_DETAILS_SV_CACHE: Optional[dict[int, dict[str, Any]]] = None
_FIREBASE_WEB_ENV_MAP = {
    "apiKey": "FIREBASE_API_KEY",
    "authDomain": "FIREBASE_AUTH_DOMAIN",
    "projectId": "FIREBASE_PROJECT_ID",
    "storageBucket": "FIREBASE_STORAGE_BUCKET",
    "messagingSenderId": "FIREBASE_MESSAGING_SENDER_ID",
    "appId": "FIREBASE_APP_ID",
    "measurementId": "FIREBASE_MEASUREMENT_ID",
}


def _normalize_locale_code(raw: str) -> str:
    code = (raw or "").strip().lower().replace("_", "-")
    if code.startswith("sv"):
        return "sv"
    if code.startswith("en"):
        return "en"
    return ""


def _firebase_web_config() -> dict[str, str]:
    cfg: dict[str, str] = {}
    for key, env_name in _FIREBASE_WEB_ENV_MAP.items():
        value = (os.environ.get(env_name) or "").strip()
        if value:
            cfg[key] = value
    return cfg


def _select_locale() -> str:
    saved_cookie = _normalize_locale_code(request.cookies.get(_LANG_COOKIE_NAME) or "")
    if saved_cookie:
        return saved_cookie

    saved_session = _normalize_locale_code(session.get(_LANG_SESSION_KEY) or "")
    if saved_session:
        return saved_session

    return "en"


app.config["BABEL_DEFAULT_LOCALE"] = "en"
app.config["BABEL_SUPPORTED_LOCALES"] = list(_SUPPORTED_LOCALES)
babel = Babel()
babel.init_app(app, locale_selector=_select_locale)

app.register_blueprint(auth_bp)

@app.before_request
def _attach_user():
    set_current_user_from_session_cookie()


@app.before_request
def _attach_profile():
    # Make profile consistently available across templates when authenticated
    from flask import g  # local import to avoid cyclic surprises at import time
    g.profile = None
    user = getattr(g, "user", None)
    if not user:
        return
    try:
        uid = user.get("uid")
        email = user.get("email")
        if not uid:
            return
        doc = ensure_user_doc(uid, email=email)
        g.profile = {
            "display_name": (doc.get("display_name") or (email.split("@")[0] if email and "@" in email else "Account")),
            "avatar_key": (doc.get("avatar_key") or "avatar_01"),
            "is_admin": bool(user.get("admin", False)),
        }
    except Exception:
        # Fail safe: leave g.profile as None. Templates handle fallback.
        g.profile = None


@app.context_processor
def _inject_profile():
    # Expose `profile` to all templates for compatibility with existing usage
    from flask import g
    locale_code = _normalize_locale_code(str(get_locale() or "")) or "en"
    return {
        "profile": getattr(g, "profile", None),
        "current_locale_code": locale_code,
        "firebase_config_json": json.dumps(_firebase_web_config()),
    }


@app.after_request
def _ensure_utf8_html(response):
    if response.mimetype == "text/html":
        response.mimetype_params["charset"] = "utf-8"
    # Baseline browser hardening headers that do not alter app behavior.
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


@app.get("/admin")
def admin_page():
    from flask import g
    if not getattr(g, "user", None):
        return redirect("/login")
    if not bool(g.user.get("admin")):
        # Forbidden for non-admins
        return abort(403)
    return render_template("admin.html")


@app.get("/set-language/<lang_code>")
def set_language(lang_code: str):
    chosen = _normalize_locale_code(lang_code) or "en"
    next_path = (request.args.get("next") or "").strip()
    if (not next_path.startswith("/")) or next_path.startswith("//"):
        next_path = "/"

    if app.secret_key:
        session[_LANG_SESSION_KEY] = chosen

    resp = redirect(next_path)
    resp.set_cookie(
        _LANG_COOKIE_NAME,
        chosen,
        max_age=60 * 60 * 24 * 365,
        samesite="Lax",
        secure=request.is_secure,
    )
    return resp

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def load_json(filename: str) -> Any:
    path = os.path.join(DATA_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_tools() -> Any:
    if _current_locale_code() == "sv":
        sv_path = os.path.join(DATA_DIR, "tools_sv.json")
        if os.path.exists(sv_path):
            return load_json("tools_sv.json")
    return load_json("tools.json")


def load_concepts() -> Any:
    if _current_locale_code() == "sv":
        sv_path = os.path.join(DATA_DIR, "concepts_sv.json")
        if os.path.exists(sv_path):
            return load_json("concepts_sv.json")
    return load_json("concepts.json")


def _load_port_details_sv() -> dict[int, dict[str, Any]]:
    global _PORT_DETAILS_SV_CACHE
    if _PORT_DETAILS_SV_CACHE is not None:
        return _PORT_DETAILS_SV_CACHE

    path = os.path.join(DATA_DIR, "port_details_sv.json")
    if not os.path.exists(path):
        _PORT_DETAILS_SV_CACHE = {}
        return _PORT_DETAILS_SV_CACHE

    raw = load_json("port_details_sv.json")
    out: dict[int, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            try:
                port_num = int(str(k))
            except Exception:
                continue
            if isinstance(v, dict):
                out[port_num] = v
    _PORT_DETAILS_SV_CACHE = out
    return _PORT_DETAILS_SV_CACHE


def load_defend() -> Any:
    if _current_locale_code() == "sv":
        sv_path = os.path.join(DATA_DIR, "defend_sv.json")
        if os.path.exists(sv_path):
            return load_json("defend_sv.json")
    return load_json("defend.json")


def load_devsecops() -> Any:
    if _current_locale_code() == "sv":
        sv_path = os.path.join(DATA_DIR, "devsecops_sv.json")
        if os.path.exists(sv_path):
            return load_json("devsecops_sv.json")
    return load_json("devsecops.json")


def load_attack_flows() -> Any:
    if _current_locale_code() == "sv":
        sv_path = os.path.join(DATA_DIR, "attack_flows_sv.json")
        if os.path.exists(sv_path):
            return load_json("attack_flows_sv.json")
    return load_json("attack_flows.json")


def _current_locale_code() -> str:
    if not has_request_context():
        return "en"
    return _normalize_locale_code(str(get_locale() or "")) or "en"


def load_commands() -> Any:
    if _current_locale_code() == "sv":
        sv_path = os.path.join(DATA_DIR, "commands_sv.json")
        if os.path.exists(sv_path):
            return load_json("commands_sv.json")
    return load_json("commands.json")


def load_quiz() -> Any:
    if _current_locale_code() == "sv":
        sv_path = os.path.join(DATA_DIR, "quiz_sv.json")
        if os.path.exists(sv_path):
            return load_json("quiz_sv.json")
    return load_json("quiz.json")


def slugify(text: str) -> str:
    text = (text or "").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


def _unique_list(values: Any) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    if not isinstance(values, list):
        return out
    for v in values:
        if not v:
            continue
        s = str(v)
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


_PORT_DETAILS: dict[int, dict[str, Any]] = {
    20: {
        "service": "FTP data",
        "transport": "TCP",
        "summary": "Legacy FTP data channel in active mode. Often blocked on modern networks.",
        "what": "TCP port 20 is traditionally the FTP data port in active mode. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. FTP is unusual because it uses two separate TCP connections: a control session on port 21 for commands and replies, and a separate data connection for directory listings and file contents. In active mode the client tells the server which client port to connect back to, and the server initiates the data connection from its local port 20 to that client port. In passive mode the server instead chooses a high port and the client connects to it, which is why FTP is famous for being tricky with firewalls and NAT. So when you see port 20, think active mode transfers and the broader fact that FTP opens extra connections beyond the initial login channel.",
        "why": "When you see port 20 open, it usually means legacy FTP is in play, or a firewall rule is overly permissive. It matters because FTP was designed before encryption was the default, and the two channel design often creates firewall and NAT surprises.",
        "how": ["Client connects to the server control service on port 21 and negotiates an active transfer (PORT or EPRT).", "Server opens a new TCP connection from its port 20 to a client specified address and port.", "The data connection carries the file or listing, then closes, while the control connection stays up."],
        "pitfalls": ["Assuming port 20 always carries data. Many FTP deployments use passive mode where data uses a server chosen high port instead.", "NAT and firewalls dropping the server initiated connection in active mode.", "Treating FTP as one port service and forgetting the extra data flow."],
        "security": ["Prefer SFTP or HTTPS based transfers for the internet. If FTP must exist, restrict it to internal networks.", "Disable active mode unless you have a strong reason and an explicit firewall policy for it.", "Monitor for anonymous access and unexpected uploads and downloads."],
        "alternatives": ["SFTP (SSH, port 22)", "FTPS (FTP over TLS)"],
        "example": "A legacy build server still pulls artifacts from an FTP host. The control session is on 21, but the file itself arrives on a separate connection created by the server, which is why the firewall needs an explicit rule for the active data flow.",
        "references": [],
    },
    21: {
        "service": "FTP control",
        "transport": "TCP",
        "summary": "Classic FTP command channel. The data flow is separate and often uses other ports.",
        "what": "TCP port 21 is the classic FTP control port. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. An FTP server listens on port 21 for the control session where the client logs in and sends commands like list, change directory, and request a file transfer. The control connection is not where file data normally travels. When a transfer starts, FTP creates a second TCP connection for the actual data, either server initiated in active mode or client initiated to a server chosen port in passive mode. That two channel design is the practical reason port 21 often shows up together with other ports in firewall rules. From a security standpoint, an exposed FTP control port usually means credentials and file transfer behavior are reachable from the network, and that is an attractive target for brute force and misconfiguration.",
        "why": "Port 21 exposure is a common finding in scans. It matters because classic FTP sends credentials and data in cleartext unless it is wrapped in TLS, and because the separate data channel can punch holes through firewalls if misconfigured.",
        "how": ["Client opens a TCP connection to port 21 and exchanges commands and replies.", "For each transfer, FTP creates a separate data connection (active mode uses server port 20, passive mode uses a server chosen high port).", "The server enforces permissions and filesystem actions, then closes the data connection after each transfer."],
        "pitfalls": ["Leaving plain FTP reachable from untrusted networks.", "Forgetting passive mode requires a predictable port range to be allowed through firewalls.", "Assuming strong authentication. Many FTP servers are configured with weak or shared accounts."],
        "security": ["Prefer SFTP or HTTPS. If you must use FTP, use explicit FTPS with strong TLS and disable plaintext logins.", "Restrict by IP and require strong credentials and auditing.", "Harden the server and disable anonymous access unless you truly need it."],
        "alternatives": ["SFTP (SSH, port 22)", "FTPS (FTP over TLS)"],
        "example": "You run a vulnerability scan and see port 21 open. A quick check in a packet capture shows USER and PASS in cleartext, which is a clear signal to migrate the workflow to SFTP or to enforce TLS.",
        "references": [],
    },
    22: {
        "service": "SSH",
        "transport": "TCP",
        "summary": "Secure remote login and file transfer foundation. Commonly used for admin access.",
        "what": "TCP port 22 is the default port for SSH. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. An SSH server binds to port 22 and waits in a listening state. When you connect, your client opens a TCP session from an ephemeral source port to the server IP and destination port 22, completes the TCP handshake, and then starts the SSH protocol on top of that connection. SSH negotiates encryption, authenticates the user or key, and then multiplexes one connection into channels for an interactive shell, single command execution, file transfer via SFTP, or port forwarding. That is why scanning for 22 is a common way to find remote administration surfaces. If you understand ports, you can see why moving SSH to a different port reduces noise but does not remove risk: the service is still reachable, just at a different rendezvous point.",
        "why": "SSH is one of the most security sensitive services in most environments. It is powerful by design, so an exposed or weakly protected SSH service is a common entry point. It also shows up everywhere in automation, backups, and server management.",
        "how": ["Client connects and negotiates algorithms for key exchange, encryption, and integrity.", "The server proves its identity with a host key, then the user authenticates with a key or password.", "After authentication, SSH opens one or more channels for shells, commands, port forwarding, or SFTP."],
        "pitfalls": ["Allowing password auth from the internet without rate limiting.", "Reusing keys across many systems or never rotating them.", "Ignoring host key changes, which can hide man in the middle attacks or compromised hosts."],
        "security": ["Prefer key based auth, disable weak ciphers, and restrict by network or VPN.", "Use MFA or short lived certificates where possible, and log all auth events.", "Treat SSH keys as secrets: protect them, rotate them, and remove access when people leave."],
        "alternatives": ["SSM or bastion access", "VPN then SSH on private IPs"],
        "example": "A developer runs git operations against a server. Under the hood, an SSH session authenticates with a key, then the server opens a channel for the git command and returns the results over the encrypted stream.",
        "references": [],
    },
    23: {
        "service": "Telnet",
        "transport": "TCP",
        "summary": "Legacy remote terminal in cleartext. Mostly unsafe except in tightly controlled labs.",
        "what": "TCP port 23 is traditionally used by Telnet for remote terminal access. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A Telnet server listens on port 23, and a client opens a TCP connection from an ephemeral source port to destination port 23. After the handshake, keystrokes and output flow as plain text with no built in encryption. In practice that means usernames, passwords, and commands can be read or modified by anyone who can observe or intercept the traffic on the path. This is why Telnet is largely legacy today and is replaced by SSH on port 22 for secure administration. If you still find 23 open, it often indicates older network gear, lab environments, or misconfigured management interfaces that should be isolated.",
        "why": "Telnet matters because you still find it on old network gear, embedded devices, and lab environments. From a security perspective, an exposed Telnet service is almost always a problem because credentials can be captured and sessions can be hijacked.",
        "how": ["Client connects and immediately starts sending keystrokes and receiving terminal output.", "Optional Telnet option negotiation can adjust terminal behavior, but it does not add confidentiality.", "Authentication and commands run entirely in plaintext unless an external tunnel is used."],
        "pitfalls": ["Using Telnet on shared networks where attackers can sniff traffic.", "Leaving default credentials on devices that expose Telnet.", "Assuming a private VLAN means safe. Many internal threats start inside the network."],
        "security": ["Disable Telnet and use SSH instead.", "If you cannot remove it, restrict to a management network and add strong monitoring.", "Hunt for Telnet in scans and logs because it often indicates outdated devices."],
        "alternatives": ["SSH (22)", "Console or out of band management"],
        "example": "A technician telnets into a switch from a WiFi network. Anyone on the same segment with a sniffer can capture the login and reuse it, which is why modern devices default to SSH.",
        "references": [],
    },
    25: {
        "service": "SMTP relay",
        "transport": "TCP",
        "summary": "Server to server email transfer. Not meant for end user clients.",
        "what": "TCP port 25 is used for SMTP, the protocol that moves email between mail servers. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A sending server opens a TCP connection from an ephemeral source port to a receiving server on destination port 25, completes the handshake, and then exchanges SMTP commands to transfer a message to the next hop. Port 25 is primarily for server to server relay on the open internet. End user clients and applications usually should not send mail directly to random servers on 25, which is why message submission is typically done on port 587 or 465 with authentication. Because abuse is common, many networks restrict outbound 25, and misconfigured servers that accept unauthenticated relay on 25 quickly get used for spam. When you see 25 exposed, the key question is whether it is intentionally a mail exchanger and whether it is hardened, patched, and configured to refuse open relay.",
        "why": "If port 25 is open inbound, your host may be acting as a mail exchanger or a relay. Misconfiguration can turn it into an open relay, which is a fast path to blacklisting. In incident response, unexpected SMTP on 25 is also a common sign of malware trying to exfiltrate data by email.",
        "how": ["A client mail server opens a TCP connection and speaks SMTP commands to deliver a message.", "The server applies policy, spam checks, and routing decisions, then accepts and queues the message.", "The receiving server may forward the message internally or relay it onward to the next hop."],
        "pitfalls": ["Running an open relay or weak anti spam controls.", "Letting applications send email directly on 25 instead of using submission on 587.", "Assuming encryption is automatic. SMTP commonly starts in cleartext unless STARTTLS is negotiated and enforced."],
        "security": ["Use port 587 for authenticated submission and keep 25 for server to server only.", "Require STARTTLS where appropriate and monitor for anomalous volumes.", "Restrict relaying to trusted senders and harden your MTA configuration."],
        "alternatives": ["SMTP submission (587)", "SMTPS submissions (465)"],
        "example": "Your company mail gateway receives mail from the internet on 25. Another MTA connects, negotiates STARTTLS, and transfers a message which is then scanned and delivered to internal mailboxes.",
        "references": [],
    },
    53: {
        "service": "DNS",
        "transport": "UDP and TCP",
        "summary": "Domain Name System queries and responses. UDP for most lookups, TCP for transfers and large replies.",
        "what": "Port 53 is the default port for DNS, and it is a good example of why the transport protocol matters as much as the port number. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. Most everyday DNS lookups use UDP 53: a client sends a small query from an ephemeral source port to the resolver on destination port 53, and the resolver replies back to that source port. TCP 53 is also important. It is used when a response does not fit in a single UDP message, when reliability is required, and for zone transfers between authoritative servers. In real networks this means firewalls often need to allow both UDP and TCP 53 for resolvers and authoritative DNS, even if you only think about the quick UDP query path. Security wise, exposed DNS can be abused for information gathering, amplification attacks if recursion is open, and as a control channel when attackers tunnel data through DNS queries.",
        "why": "DNS is foundational. If DNS is misconfigured or compromised, users get redirected, services fail, and security controls break. In security work, DNS traffic is also a goldmine for detection because it shows what hosts are trying to reach and can reveal tunneling or command and control patterns.",
        "how": ["A client sends a query to a resolver asking for a record such as A, AAAA, or MX.", "The resolver answers from cache or recursively queries authoritative servers and returns the result.", "If the reply is too large or needs reliability, the exchange falls back to TCP for the same port."],
        "pitfalls": ["Exposing an authoritative DNS server without proper hardening or rate limiting.", "Assuming DNS is always UDP and forgetting TCP based transfers and large responses.", "Ignoring split horizon DNS differences between internal and external zones."],
        "security": ["Separate recursive resolvers from authoritative servers and restrict who can query what.", "Use DNSSEC validation where appropriate and monitor for unusual query patterns.", "Protect against amplification abuse with rate limiting and response size controls."],
        "alternatives": ["DNS over TLS (853)", "DNS over HTTPS (443)"],
        "example": "A browser loads a website. It asks the configured resolver for the domain IP over UDP 53. The resolver returns a cached answer, and the browser then connects to the site on 443.",
        "references": [],
    },
    67: {
        "service": "DHCP server",
        "transport": "UDP",
        "summary": "Server side of DHCP. Provides IP configuration to clients on a local network.",
        "what": "UDP port 67 is the well known server port for DHCP. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. DHCP exists because a new machine often does not know its IP address, default gateway, or DNS settings yet. A DHCP server listens on UDP 67 so clients can discover it without prior configuration. Because DHCP uses UDP and often broadcast, there is no connection setup like TCP. A client typically uses UDP 68 and broadcasts a discover message. The server on 67 replies with an offer, the client requests the offered address, and the server acknowledges the lease along with options like router and DNS. When you understand the port roles, you can read packet captures and see the real flow: client side traffic tied to 68, server side replies tied to 67. Security wise, rogue DHCP servers can hand out malicious gateways or DNS servers, so these ports are usually constrained to trusted network segments.",
        "why": "DHCP is a control point for network access. A rogue DHCP server can redirect clients to malicious DNS or gateways. Operationally, DHCP issues look like random connectivity failures, so understanding the flow helps you troubleshoot fast.",
        "how": ["A new client broadcasts a DHCPDISCOVER because it does not yet have an IP address.", "The server replies with a DHCPOFFER, then the client requests the offer and the server acknowledges with DHCPACK.", "The lease is renewed later using unicast where possible, or broadcast if needed."],
        "pitfalls": ["Rogue DHCP servers on the same segment handing out bad gateways or DNS servers.", "Forgetting DHCP usually does not cross routers without a relay agent.", "Leases that are too long or too short creating churn or address exhaustion."],
        "security": ["Use DHCP snooping, trusted ports, or network access controls to prevent rogue servers.", "Log lease assignments and alert on unexpected option changes.", "Segment networks so guest devices cannot influence infrastructure services."],
        "alternatives": ["Static addressing for infrastructure", "IPv6 SLAAC with guardrails"],
        "example": "You plug a laptop into a conference room port. It broadcasts for DHCP, gets an offer from the building DHCP server, and then configures IP, gateway, and DNS within seconds.",
        "references": [],
    },
    68: {
        "service": "DHCP client",
        "transport": "UDP",
        "summary": "Client side of DHCP. Devices use it to request and renew IP configuration.",
        "what": "UDP port 68 is the well known client port for DHCP. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A DHCP client binds to UDP 68 so that replies from servers reliably reach the correct local process during boot. This is especially important because the client may start with no IP address, sending from 0.0.0.0 to a broadcast destination while still needing to receive an offer. In a typical lease flow, the client on 68 broadcasts discover and request messages, and the server on 67 responds with offer and acknowledgement messages that include an address lease plus settings like DNS and default gateway. Because the early exchange can be broadcast and unauthenticated, network controls such as switch port security, DHCP snooping, or trusted VLAN boundaries matter a lot. If an attacker can inject DHCP replies to port 68, they can redirect traffic or break connectivity by handing out bad configuration.",
        "why": "In packet captures, seeing UDP 68 traffic helps you diagnose why a host is not getting an address. From a security view, it also helps detect rogue DHCP behavior and miswired segments.",
        "how": ["Client sends DHCPDISCOVER from 0.0.0.0 to the broadcast address, source port 68.", "Client receives a DHCPOFFER and responds with DHCPREQUEST.", "Client applies the DHCPACK settings and renews later before the lease expires."],
        "pitfalls": ["Clients stuck in a loop because offers are blocked by VLANs, ACLs, or missing relay agents.", "Multiple DHCP servers causing flapping between different configurations.", "Assuming the client is broken when the real issue is upstream switch security or relay configuration."],
        "security": ["Use captures on the access switch or host to confirm the discover and offer flow.", "Lock down DHCP with snooping and trusted uplinks.", "Document which VLANs use which DHCP scopes so mispatching is obvious."],
        "alternatives": ["Static IP for fixed hosts", "IPv6 SLAAC with RA guard"],
        "example": "A VoIP phone boots and immediately sends DHCPDISCOVER from UDP 68. If the switch blocks it due to DHCP snooping misconfig, the phone never gets an IP and appears dead.",
        "references": [],
    },
    80: {
        "service": "HTTP",
        "transport": "TCP",
        "summary": "Default for unencrypted web traffic. Often used for redirects and internal services.",
        "what": "TCP port 80 is the default port for HTTP. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A web server binds to port 80 and listens. When your browser visits an HTTP URL, it opens a TCP connection from an ephemeral source port to destination port 80, completes the TCP handshake, and then sends an HTTP request such as a GET for a path. The server responds with status codes, headers, and content, and the same connection may be reused for multiple requests depending on HTTP version and keep alive settings. Port 80 matters because it is often used for redirects to HTTPS, health checks, or legacy sites, and it is commonly reachable through firewalls. Security wise, plain HTTP has no encryption or integrity. Credentials, session cookies, and content can be observed or modified in transit, so modern deployments typically move real logins and sensitive traffic to HTTPS on port 443.",
        "why": "HTTP matters because many internal dashboards, device admin UIs, and legacy apps still run without encryption. In security terms, plain HTTP leaks cookies and credentials, enables content injection, and makes session hijacking easier.",
        "how": ["Client opens a TCP connection and sends an HTTP request line, headers, and optionally a body.", "Server responds with a status code, headers, and a body such as HTML or JSON.", "Connections may be reused with keep alive, or closed after the response depending on headers and versions."],
        "pitfalls": ["Leaving authentication pages on HTTP and assuming it is fine on an internal network.", "Mixing HTTP and HTTPS resources which creates downgrade and mixed content issues.", "Assuming port 80 is harmless because the main site uses 443. Many hidden admin panels live on 80."],
        "security": ["Redirect to HTTPS and use HSTS on the secure site.", "Block or restrict management interfaces on 80, especially on the internet edge.", "Log and monitor unusual request paths and user agents for scanning behavior."],
        "alternatives": ["HTTPS (443)", "HTTP over a private VPN"],
        "example": "A web server listens on 80 only to issue a 301 redirect to the same host on 443. If you see real app traffic on 80, it is a sign that something is still running without TLS.",
        "references": [],
    },
    110: {
        "service": "POP3",
        "transport": "TCP",
        "summary": "Legacy style mailbox download. Plaintext by default unless upgraded to TLS.",
        "what": "TCP port 110 is used by POP3, a legacy protocol for retrieving email from a mailbox. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A POP3 server listens on 110, and a mail client connects from an ephemeral source port, completes the TCP handshake, and then authenticates and issues commands to list and retrieve messages. The typical POP model is download and optionally delete, meaning the client often pulls mail onto one device rather than keeping state synchronized across devices as IMAP does. Without encryption, POP3 sends credentials and message contents in cleartext, which is why secure variants use TLS via STARTTLS or the implicit TLS port 995. From a security angle, exposed POP3 services are frequent targets for password spraying and credential stuffing, since a successful login can directly expose mailbox content.",
        "why": "POP3 still exists in older mail setups and some devices. For security, plaintext POP3 is a red flag. In operations, POP style workflows can also hide server side retention issues because the mail quickly leaves the server.",
        "how": ["Client connects to the server and authenticates with a username and password.", "Client lists messages, retrieves selected messages, and optionally deletes them.", "Session ends and the server commits deletions, while local mail storage becomes the source of truth."],
        "pitfalls": ["Using plaintext POP3 over untrusted networks.", "Assuming POP3 behaves like IMAP. It is not designed for multi device sync.", "Leaving old accounts enabled because POP clients often run for years without change."],
        "security": ["Prefer POP3S on 995 or IMAPS on 993, or use modern provider APIs.", "Disable plaintext auth and enforce strong passwords and MFA where possible.", "Monitor for brute force attempts and unusual login locations."],
        "alternatives": ["POP3S (995)", "IMAP (143) or IMAPS (993)"],
        "example": "A printer uses POP3 on 110 to fetch jobs from a mailbox. If the connection is not encrypted, anyone with network visibility can capture the mailbox credentials.",
        "references": [],
    },
    123: {
        "service": "NTP",
        "transport": "UDP",
        "summary": "Time synchronization. Small packets, big impact on security and reliability.",
        "what": "UDP port 123 is used by NTP, the time synchronization protocol. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. NTP is typically UDP because the messages are small and periodic. A client sends a request from an ephemeral source port to a server on destination port 123, and the server replies with timestamps that let the client estimate clock offset and network delay. The client then adjusts its clock gradually and repeats the process, sometimes using multiple servers to improve accuracy and resilience. Time is a security dependency: certificates, logs, Kerberos, and incident timelines all assume clocks are close to reality. Exposed or misconfigured NTP can also be abused for reflection and amplification attacks, and attackers may try to shift time to break validation or confuse log analysis, which is why access controls and authenticated modes are relevant.",
        "why": "Time drift causes confusing logs and broken security. Kerberos, TLS, and many API auth schemes assume clocks are close. NTP is also abused in reflection attacks, so exposing open NTP to the internet can create risk.",
        "how": ["Client sends a time request to an NTP server, usually with a small UDP packet.", "Server replies with timestamps that let the client estimate offset and network delay.", "Client disciplines its clock gradually, then repeats periodically and may consult multiple servers."],
        "pitfalls": ["Allowing public NTP servers without rate limiting, enabling amplification abuse.", "Pointing many clients to a single fragile server, creating a single point of failure.", "Assuming time is correct even when virtual machines suspend or networks partition."],
        "security": ["Restrict who can query your NTP servers and prefer authenticated NTP or secure time sources where supported.", "Use multiple upstream sources and monitor offset and stratum health.", "Validate time sync for critical auth systems such as domain controllers."],
        "alternatives": ["Authenticated NTP", "Provider managed time sync"],
        "example": "During an investigation you see log timestamps out of order. The root cause is a failed NTP sync on one server, which is why time health checks are as important as CPU or disk checks.",
        "references": [],
    },
    139: {
        "service": "NetBIOS Session Service",
        "transport": "TCP",
        "summary": "Legacy Windows session layer for SMB over NetBIOS. Mostly replaced by 445.",
        "what": "TCP port 139 is the NetBIOS Session Service, historically used to carry SMB file sharing over NetBIOS on Windows networks. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. In real usage, a client opens a TCP connection to port 139, negotiates a NetBIOS session, and then speaks SMB commands to authenticate, list shares, and read or write files. Modern Windows uses SMB directly over TCP 445 in most environments, but 139 still appears on legacy systems, older device firmware, and misconfigured networks where NetBIOS is enabled. Because file sharing surfaces are high value, open 139 is commonly associated with credential exposure, share enumeration, and lateral movement once an attacker is inside a network. Understanding the port helps you interpret scans: 139 often means legacy Windows file sharing behavior rather than a modern hardened SMB stack.",
        "why": "Port 139 matters because it often signals outdated configuration, legacy devices, or relaxed Windows file sharing exposure. In security scanning, 139 and 445 are high signal ports for lateral movement and credential attacks.",
        "how": ["A client establishes a NetBIOS session and then speaks SMB over that session.", "Name resolution and discovery are often tied to older NetBIOS mechanisms.", "Many environments disable this path and rely on SMB over 445 instead."],
        "pitfalls": ["Leaving NetBIOS enabled across subnets when it is not needed.", "Exposing Windows file sharing to untrusted networks.", "Assuming blocking 445 is enough. Some systems may still accept SMB over 139."],
        "security": ["Disable NetBIOS where possible and use modern SMB settings with signing and hardening.", "Restrict 139 and 445 to trusted segments and monitor authentication attempts.", "Inventory legacy systems that still require NetBIOS and plan a migration."],
        "alternatives": ["SMB over TCP (445)"],
        "example": "A scan finds 139 open on a server. That suggests NetBIOS is enabled and SMB might be reachable via legacy paths, so you review file sharing exposure and tighten firewall rules.",
        "references": [],
    },
    143: {
        "service": "IMAP",
        "transport": "TCP",
        "summary": "Mailbox sync protocol. Plaintext by default unless upgraded with TLS or StartTLS.",
        "what": "TCP port 143 is used by IMAP, an email synchronization protocol. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. An IMAP server listens on 143 and clients connect from ephemeral source ports. After the TCP handshake, the client can upgrade the session to TLS using STARTTLS, then authenticate and synchronize folders and message state such as read flags and deletions. Unlike POP3, IMAP keeps the mailbox on the server and is designed for multiple devices, so clients often fetch headers and only download full bodies when needed. The practical security detail is that port 143 can start in cleartext unless TLS is enforced, which creates risk if clients send credentials before upgrading. That is why many environments prefer IMAPS on port 993 where encryption is established immediately, and why monitoring for brute force on IMAP ports is common.",
        "why": "IMAP is common in enterprises and on legacy deployments. From a security perspective, plaintext IMAP is risky, and misconfigured IMAP can be a target for brute force and credential stuffing.",
        "how": ["Client connects and authenticates, then lists folders and message metadata.", "Client fetches message bodies on demand and updates flags such as read or deleted.", "If STARTTLS is supported and required, the connection upgrades to TLS before credentials are sent."],
        "pitfalls": ["Allowing plaintext auth without enforcing STARTTLS.", "Assuming IMAP means all mail is safe on the server. Retention still depends on backup and policy.", "Leaving old clients that do not support modern auth methods."],
        "security": ["Prefer IMAPS on 993 or enforce STARTTLS with strong cipher suites.", "Enable rate limiting and monitor for auth anomalies.", "Consider modern OAuth based auth where supported by your provider."],
        "alternatives": ["IMAPS (993)"],
        "example": "A mobile mail app uses IMAP to keep inbox state consistent. Each time you mark a message as read, the client sends an IMAP command and the server updates the flag for all devices.",
        "references": [],
    },
    161: {
        "service": "SNMP",
        "transport": "UDP",
        "summary": "Network device monitoring. Reads counters and sometimes writes config, depending on permissions.",
        "what": "UDP port 161 is used by SNMP, which allows management systems to query network devices for metrics and status. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. An SNMP agent listens on UDP 161. A monitoring system sends a request from an ephemeral source port to destination port 161 asking for specific object identifiers, and the device replies with values such as interface counters, CPU, memory, and device identity information. Some deployments also allow write operations that change configuration, which makes access control critical. Older SNMP versions use community strings and no encryption, so anyone who can reach port 161 and guess the string may enumerate your network or worse. In practice, defenders restrict 161 to management networks and prefer SNMPv3 with authentication and privacy so traffic and credentials are not exposed.",
        "why": "SNMP is everywhere in network operations. Security wise, older SNMP versions use weak community strings and lack encryption. Exposed SNMP can leak network topology and device information, and write access can be catastrophic.",
        "how": ["A monitoring system sends an SNMP GET or GETNEXT to a device, asking for specific OIDs.", "The device replies with values and status codes, usually over UDP.", "For configuration changes, an SNMP SET may be used if the access control allows it."],
        "pitfalls": ["Using SNMPv1 or v2c with default community strings like public or private.", "Allowing SNMP from broad networks instead of only from monitoring servers.", "Forgetting that UDP based protocols can be spoofed or abused for reflection if misconfigured."],
        "security": ["Prefer SNMPv3 with authentication and privacy enabled.", "Restrict UDP 161 to management networks and a small set of monitoring hosts.", "Audit community strings and disable write access unless it is required and controlled."],
        "alternatives": ["SNMPv3", "Vendor APIs over HTTPS"],
        "example": "A monitoring platform polls a switch every minute on UDP 161, reading interface counters. If the community string leaks, an attacker can enumerate the entire device and sometimes change settings.",
        "references": [],
    },
    162: {
        "service": "SNMP trap",
        "transport": "UDP",
        "summary": "Asynchronous alerts from devices to management systems.",
        "what": "UDP port 162 is used for SNMP traps and informs, which are unsolicited alert messages sent from devices to a management system. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. Instead of being polled, a device can push an event to the manager on destination port 162 when something happens such as link down, temperature alarms, or authentication failures. Because this is UDP, there is no connection setup, and reliability depends on the network and on whether informs with acknowledgements are used. Operationally, traps are great for fast signal, but they are also easy to spoof if you accept them from anywhere, and they can create alert storms during outages. Understanding the port role makes it easier to debug monitoring gaps: if traps are missing, look for blocked UDP 162, misconfigured destinations, or overloaded collectors.",
        "why": "Traps are useful for fast detection, but they are also easy to spoof if you do not control where they come from. Misrouted traps can leak internal details, and missing traps can create blind spots if you rely on them too much.",
        "how": ["A device detects an event and sends a trap message to the configured manager IP and port 162.", "The manager parses the OIDs and maps them to an alert or ticket.", "Some variants use inform messages that expect an acknowledgement, improving reliability."],
        "pitfalls": ["Accepting traps from any source, enabling spoofed alerts or noise flooding.", "Assuming traps are reliable. UDP delivery can drop under congestion.", "Not aligning trap configuration with monitoring and incident workflows."],
        "security": ["Allow traps only from known device IP ranges and prefer SNMPv3 where possible.", "Combine traps with polling so you detect failures even if traps are lost.", "Log and rate limit trap processing to avoid alert storms."],
        "alternatives": ["Syslog (514)", "Streaming telemetry over TLS"],
        "example": "A router interface goes down and immediately sends an SNMP trap to the NMS on 162, which creates an alert. If the trap never arrives, polling still shows the interface state change.",
        "references": [],
    },
    389: {
        "service": "LDAP",
        "transport": "TCP and UDP",
        "summary": "Directory lookups and authentication plumbing. Often tied to Active Directory.",
        "what": "Port 389 is used for LDAP, a directory protocol that many enterprise identity systems depend on. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. Directory servers listen on 389 so applications can bind, search for users and groups, and read attributes that drive authorization decisions. Most LDAP traffic is over TCP because it involves request and response exchanges and can include larger payloads. UDP 389 also exists for CLDAP, a connectionless variant used in some discovery and lookup scenarios, which is why scans sometimes show both. A typical real flow is: the client connects to port 389, performs a bind (often with a service account), runs searches using filters, and may upgrade to TLS with StartTLS before sending credentials if configured correctly. Security wise, an exposed directory port can leak your entire org structure and enable credential attacks, so environments usually restrict 389 to trusted application networks and require StartTLS or use LDAPS on 636.",
        "why": "Directory services are high value targets. Exposing LDAP without encryption can leak credentials and directory structure. Misconfigured LDAP access also enables privilege escalation through group discovery and weak service accounts.",
        "how": ["Client connects and performs a bind operation to authenticate or to establish an anonymous session if allowed.", "Client performs searches for users, groups, or attributes using LDAP filters.", "Optionally, the connection upgrades to TLS using StartTLS, or you use LDAPS on 636 for implicit TLS."],
        "pitfalls": ["Allowing simple bind over cleartext where passwords can be captured.", "Granting directory read access too broadly, leaking sensitive attributes.", "Confusing LDAP with Kerberos. LDAP is often used for lookups even when Kerberos does the main auth."],
        "security": ["Use StartTLS or LDAPS and require strong authentication.", "Restrict who can query the directory and monitor bind failures and unusual search patterns.", "Harden service accounts and remove unnecessary anonymous binds."],
        "alternatives": ["LDAPS (636)", "StartTLS on 389"],
        "example": "An application needs to check group membership. It binds to LDAP, searches for the user DN, then queries group attributes to decide whether to allow access.",
        "references": [],
    },
    443: {
        "service": "HTTPS",
        "transport": "TCP and UDP",
        "summary": "Encrypted web traffic. Most commonly TCP, and increasingly UDP for HTTP over QUIC.",
        "what": "Port 443 is the default port for HTTPS, meaning HTTP carried inside a TLS protected channel. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. In the common TCP based case, the client opens a TCP connection to destination port 443, performs the TCP handshake, then performs a TLS handshake where the server proves its identity with a certificate and both sides derive encryption keys. Only then do HTTP requests and responses flow inside the encrypted tunnel, often with connection reuse for many requests. Modern web stacks also use HTTP over QUIC, known as HTTP/3, which runs over UDP on port 443. That is why you may see both TCP 443 and UDP 443 involved in web traffic. Port 443 matters because it is the most common externally reachable service on the internet, so it is both a business critical entry point and a favorite hiding place for tunneling and command and control. Encryption protects transport confidentiality, but application vulnerabilities, weak authentication, and misconfiguration are still the real risks on 443.",
        "why": "Port 443 is the most common external exposure on the internet. Security posture depends on TLS configuration, certificate hygiene, and application security. In investigations, 443 traffic can be legitimate web use or it can hide tunneling, proxies, and command and control.",
        "how": ["Client opens a TCP connection and performs a TLS handshake to agree on keys and verify the certificate.", "Inside the encrypted tunnel, the client sends HTTP requests and receives responses.", "Modern stacks may use HTTP/2 or HTTP/3, and can reuse connections for many requests."],
        "pitfalls": ["Assuming HTTPS means safe. The transport is encrypted but the application can still be vulnerable.", "Weak TLS settings, expired certificates, or missing certificate validation in clients.", "Exposing admin endpoints on 443 because it feels normal, without access controls."],
        "security": ["Use strong TLS configurations and automate certificate rotation.", "Apply web security controls such as WAF rules, rate limiting, and robust authentication.", "Inspect logs for unusual paths, user agents, and request volumes. Encryption does not remove the need for visibility."],
        "alternatives": ["mTLS for internal APIs", "Private network exposure via VPN"],
        "example": "A user visits a site. The browser verifies the certificate during the TLS handshake, then sends an HTTP GET. Even though the traffic is encrypted, the server logs still show the request path and status code.",
        "references": [],
    },
    465: {
        "service": "SMTPS submissions",
        "transport": "TCP",
        "summary": "Implicit TLS email submission. Common with clients that require encryption from the first byte.",
        "what": "TCP port 465 is commonly used for SMTP message submission with implicit TLS. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A submission server listens on 465 and expects encryption immediately. The client connects from an ephemeral source port, completes the TCP handshake, and then starts the TLS handshake before sending any SMTP commands. After the TLS channel is established, the client authenticates and submits messages for delivery. The key practical difference from STARTTLS based submission is that encryption starts from the first byte, which reduces downgrade risk if clients and servers are configured correctly. From a security perspective, 465 should not behave like open internet relay on port 25. It is usually an authenticated service for users and apps, so abuse prevention, rate limits, and credential hygiene matter as much as TLS.",
        "why": "You will see 465 in mail client configurations and some hosted providers. For security, implicit TLS can reduce downgrade risk if clients and servers are configured correctly. Operationally, it is still submission, not server to server relay, so it pairs with authentication and policy controls.",
        "how": ["Client connects and immediately negotiates TLS before sending any SMTP commands.", "Client authenticates, then submits a message using SMTP commands inside the encrypted session.", "Server applies submission policies such as rate limits and sender identity checks."],
        "pitfalls": ["Confusing 465 with port 25 relay rules and exposing it as a relay service.", "Allowing weak authentication just because the transport is encrypted.", "Misconfigured TLS that allows old versions or weak ciphers."],
        "security": ["Treat 465 as submission: require authentication and enforce sending policies.", "Harden TLS, prefer modern versions, and monitor for auth abuse.", "Block it from the public internet unless you intentionally provide mail submission for users."],
        "alternatives": ["SMTP submission (587)"],
        "example": "A mail app uses port 465 because it expects TLS immediately. After the TLS handshake completes, the app authenticates and submits outgoing mail to the provider.",
        "references": [],
    },
    514: {
        "service": "Syslog",
        "transport": "UDP and TCP",
        "summary": "Common logging transport. UDP 514 is traditional, but reliable and TLS variants exist.",
        "what": "Port 514 is widely associated with syslog, a common way devices ship log messages to a central collector. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. Traditionally syslog uses UDP 514: each event is sent as an independent datagram from a sender source port to destination port 514, which keeps overhead low but means messages can be dropped or arrive out of order under congestion. Some deployments use TCP 514 for better delivery behavior, and secure syslog is often done via a TLS wrapped variant on other ports. In practice, the syslog collector parses, timestamps, and forwards events into SIEM and alerting pipelines, so the port often represents your visibility layer. Security wise, unauthenticated syslog can leak sensitive events or allow spoofed log entries if anyone can send to the collector, which is why access control and trusted sender lists are crucial.",
        "why": "Central logging is core to detection and troubleshooting. Syslog itself is often unauthenticated and unencrypted, so exposure can leak sensitive events or allow log spoofing. For defenders, open syslog listeners are also a signal to harden and restrict access.",
        "how": ["A device formats an event into a syslog message and sends it to the collector, often over UDP 514.", "The collector parses, timestamps, and stores the message, then forwards it to SIEM or alerting pipelines.", "If reliability is needed, TCP based syslog or buffered forwarding is used instead of raw UDP."],
        "pitfalls": ["Sending syslog over UDP across untrusted networks where messages can be read or altered.", "Assuming UDP delivery is reliable during incidents when networks are congested.", "Accepting syslog from any source, enabling spoofed events and noise."],
        "security": ["Restrict who can send to your syslog collector and prefer authenticated, encrypted transports where possible.", "Buffer on the sender or use TCP to reduce loss during spikes.", "Normalize and validate sources so spoofed logs are easier to detect."],
        "alternatives": ["Syslog over TLS", "Agent based logging"],
        "example": "A firewall sends deny events to a log server on 514. During a DDoS, UDP drops spike and you lose visibility, which is why many teams use buffering or TCP for critical logs.",
        "references": [],
    },
    587: {
        "service": "SMTP submission",
        "transport": "TCP",
        "summary": "Authenticated email submission from clients and applications. Preferred for outbound mail from users.",
        "what": "TCP port 587 is the standard port for SMTP message submission, meaning mail sent from users or applications to their outgoing mail server. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A submission server listens on 587 and a client connects from an ephemeral source port. After the TCP handshake, the two sides exchange SMTP commands, and the session typically upgrades to TLS using STARTTLS before credentials are sent. The client then authenticates and submits the message, and the server applies policy and relays it onward. This is different from port 25, which is mainly server to server relay, and from port 465, which expects TLS immediately rather than negotiating an upgrade. From a security view, 587 is designed for authentication and abuse controls. If it is misconfigured as an open relay or if credentials are weak, attackers can use it to send spam or to impersonate users.",
        "why": "Using 587 reduces spam risk because you can enforce authentication, rate limits, and sender policy. In security reviews, applications that send email should use submission rather than trying to speak directly to the open internet on port 25.",
        "how": ["Client connects and issues SMTP commands to identify itself and negotiate capabilities.", "Client upgrades to TLS with STARTTLS when required, then authenticates and submits the message.", "Server enforces submission rules and relays the message onward to recipients."],
        "pitfalls": ["Using 25 for application outbound mail and then getting blocked by networks or blacklisted.", "Failing to require TLS, allowing downgrade attacks on opportunistic STARTTLS.", "Hardcoding credentials in apps without rotation or secrets management."],
        "security": ["Require authentication and enforce rate limits and sender policies.", "Require TLS and validate certificates on clients where possible.", "Use app specific credentials or OAuth and rotate secrets."],
        "alternatives": ["SMTPS submissions (465)", "Provider mail API over HTTPS"],
        "example": "A web application sends password reset emails. It connects to the provider on 587, negotiates STARTTLS, authenticates with a service account, and submits the message for delivery.",
        "references": [],
    },
    636: {
        "service": "LDAPS",
        "transport": "TCP",
        "summary": "LDAP over implicit TLS. Common for secure directory binds and searches.",
        "what": "TCP port 636 is used for LDAPS, which is LDAP with TLS from the first byte. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A directory server listens on 636 for clients that require encryption immediately, rather than connecting on 389 and negotiating StartTLS. The real flow is: TCP handshake, then TLS handshake with certificate validation, then LDAP bind and directory operations inside the encrypted session. This protects credentials and directory attributes in transit, but it does not automatically make directory access safe. Permissions, service account scope, and monitoring still determine how much data is exposed if an account is compromised. Operationally, certificate trust matters a lot here. If clients cannot validate the LDAPS certificate, authentication can fail at scale or users may learn to ignore warnings.",
        "why": "Secure directory traffic prevents credential theft and attribute leakage. LDAPS is common in enterprise apps that integrate with directories. Misconfigured LDAPS certificates can break authentication at scale, so understanding it matters operationally too.",
        "how": ["Client connects and starts a TLS handshake immediately, validating the server certificate.", "Client performs an LDAP bind inside the encrypted channel.", "Client runs searches and reads attributes, then closes the connection or reuses it for multiple operations."],
        "pitfalls": ["Using self signed certificates without proper trust distribution, causing client failures.", "Treating LDAPS as automatically safe while still allowing weak binds or broad reads.", "Opening 636 to networks that should never query the directory."],
        "security": ["Use certificates issued by a trusted internal PKI and automate renewal.", "Restrict access to known application subnets and monitor bind patterns.", "Harden directory permissions so services only read what they need."],
        "alternatives": ["StartTLS on 389"],
        "example": "An internal service verifies user group membership. It connects to 636, validates the directory certificate, then performs an LDAP search over the encrypted channel.",
        "references": [],
    },
    989: {
        "service": "FTPS data",
        "transport": "TCP",
        "summary": "Implicit FTPS data channel. Less common than explicit FTPS on 21 with negotiated TLS.",
        "what": "TCP port 989 is associated with the data channel for implicit FTPS in some deployments. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. FTPS is FTP with TLS, but FTP keeps its classic two connection design: one channel for control commands and another for data. In older implicit FTPS setups, the control channel used port 990 and the data channel used port 989, with TLS expected immediately on those ports. Many modern environments prefer explicit FTPS on port 21 where TLS is negotiated, or SFTP on port 22, because it simplifies firewalling and reduces the number of moving parts. The real world implication is that even when encryption is present, FTP style data connections can still require extra ports and careful NAT handling, so seeing 989 open should trigger a check that the transfer method is still necessary and properly restricted.",
        "why": "This port matters because FTPS still inherits FTP's separate data channel behavior. Even when encrypted, it can be painful with firewalls and NAT. When you see 989 open, validate whether the service is required and whether a simpler transfer method would reduce attack surface.",
        "how": ["Client and server establish a TLS protected control and data relationship according to the FTPS mode used.", "Data transfers occur over a dedicated connection that may use port 989 in implicit setups.", "Firewalls must still allow the negotiated data flows, often across dynamic ranges."],
        "pitfalls": ["Assuming FTPS is a single port service and forgetting the extra data connection.", "Misconfigured TLS that allows old versions or weak ciphers.", "Leaving legacy implicit FTPS open when modern clients use explicit FTPS or SFTP."],
        "security": ["Prefer SFTP or HTTPS based transfers for simplicity and fewer firewall surprises.", "If FTPS is required, document and restrict the port ranges and enforce strong TLS.", "Monitor for brute force and unusual transfer patterns."],
        "alternatives": ["Explicit FTPS on 21", "SFTP (22)"],
        "example": "A partner insists on implicit FTPS. Your firewall team has to allow a predictable set of ports and confirm that the data channel really negotiates as expected, otherwise transfers fail intermittently.",
        "references": [],
    },
    990: {
        "service": "FTPS control",
        "transport": "TCP",
        "summary": "Implicit FTPS control channel. Legacy approach to FTP over TLS.",
        "what": "TCP port 990 is associated with the control channel for implicit FTPS. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. With implicit FTPS, a server listens on 990 and the client expects to start a TLS handshake immediately after the TCP connection is established. Once the secure tunnel is up, the client authenticates and sends FTP control commands inside the encrypted channel. File contents and directory listings still travel over separate data connections, often using configured passive ranges rather than a single fixed port. Because this two channel behavior is easy to misconfigure, many teams prefer SFTP or HTTPS based transfer flows. If 990 is exposed, treat it like any internet facing authentication service: it can be brute forced, it needs strong TLS and account hygiene, and it should be restricted to known partners where possible.",
        "why": "Port 990 is important because it often appears on legacy appliances and partner integrations. Security wise, it is better than plaintext FTP, but it still brings FTP complexity and may expand firewall exposure for data channels.",
        "how": ["Client connects and performs a TLS handshake immediately.", "Client authenticates and issues FTP control commands inside the encrypted session.", "Data transfers use separate connections and may use configured port ranges rather than a single fixed port."],
        "pitfalls": ["Assuming implicit FTPS is the default everywhere. Many clients and servers prefer explicit FTPS on 21.", "Opening wide port ranges for passive data without restricting who can connect.", "Leaving anonymous or weak accounts enabled because the transport is encrypted."],
        "security": ["Prefer SFTP or explicit FTPS on 21 with strong TLS policies.", "Restrict port ranges and IP sources, and log all access.", "Regularly review accounts and disable anonymous access unless required."],
        "alternatives": ["Explicit FTPS on 21", "SFTP (22)"],
        "example": "A scan shows 990 open. You confirm it is an old file transfer integration, then reduce exposure by restricting the source IPs and moving to SFTP on a private network.",
        "references": [],
    },
    993: {
        "service": "IMAPS",
        "transport": "TCP",
        "summary": "IMAP over implicit TLS. Standard secure mailbox sync port.",
        "what": "TCP port 993 is used by IMAPS, meaning IMAP with implicit TLS. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A mail server listens on 993 and clients connect expecting encryption immediately. The session begins with a TCP handshake and then a TLS handshake, after which the client authenticates and synchronizes folders, headers, and message flags. The practical advantage over plain IMAP on 143 is that encryption is established before any credentials are sent, which avoids STARTTLS downgrade and misordering issues when clients are misconfigured. From a security perspective, IMAPS protects data in transit but does not stop account compromise, so rate limiting, MFA, and monitoring for unusual mailbox access are still essential.",
        "why": "IMAPS is common for secure email access. It matters because mailboxes contain sensitive data, and because credential theft is often followed by mailbox access. Strong auth and monitoring are as important as encryption.",
        "how": ["Client connects and negotiates TLS immediately, validating the server certificate.", "Client authenticates and synchronizes folders, headers, and message flags.", "Client fetches message bodies as needed and keeps the server as the source of truth."],
        "pitfalls": ["Relying on weak passwords because the transport is encrypted.", "Leaving legacy auth methods enabled when modern providers support stronger approaches.", "Ignoring certificate trust issues that lead to users clicking through warnings."],
        "security": ["Enforce strong authentication and MFA where possible, plus rate limiting.", "Monitor for suspicious logins and mailbox access patterns.", "Keep TLS configuration modern and automate certificate renewal."],
        "alternatives": ["IMAP with STARTTLS (143)"],
        "example": "A user reads email on two devices. Both connect to 993, authenticate, and see the same folder state because IMAP tracks message flags on the server.",
        "references": [],
    },
    995: {
        "service": "POP3S",
        "transport": "TCP",
        "summary": "POP3 over implicit TLS. Secure mailbox download, still simpler than IMAP.",
        "what": "TCP port 995 is used by POP3S, meaning POP3 with implicit TLS. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A server listens on 995 and the client establishes a TCP session, then a TLS session, before authenticating. After that, the client lists and retrieves messages, typically downloading them to local storage rather than keeping server side state synchronized like IMAP. That model is why POP is still used for simple setups and legacy clients, but it also means retention and incident response depend on where mail is stored and backed up. Security wise, POP3S removes cleartext credentials on the wire, but weak passwords, lack of MFA, and exposed services still make port 995 a common target for credential attacks.",
        "why": "POP3S matters because some devices and older clients still rely on POP. From a defender perspective, secure transport helps, but you still need to protect accounts from brute force and to consider retention and backup implications.",
        "how": ["Client connects and negotiates TLS immediately.", "Client authenticates, lists messages, retrieves them, and may delete them from the server.", "Client stores messages locally and ends the session."],
        "pitfalls": ["Using POP for multi device scenarios and then losing mail state consistency.", "Weak account security leading to mailbox compromise.", "Assuming TLS solves everything. Server side policy and monitoring are still required."],
        "security": ["Prefer IMAPS when you need multi device sync, or provider APIs for apps.", "Enforce strong passwords and MFA and monitor failed logins.", "Disable legacy plaintext POP3 on 110."],
        "alternatives": ["IMAPS (993)", "Modern mail APIs over HTTPS"],
        "example": "An old mail client supports only POP3S. It connects to 995, authenticates, downloads new mail, and archives it locally, which is why server retention may not reflect what the user still has.",
        "references": [],
    },
    1433: {
        "service": "MS SQL Server",
        "transport": "TCP",
        "summary": "Default Microsoft SQL Server listener. Often moved or proxied in hardened environments.",
        "what": "TCP port 1433 is the default listener for Microsoft SQL Server in many deployments. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A SQL Server instance binds to 1433 so client applications can find the database engine. A client connects from an ephemeral source port, completes the TCP handshake, negotiates the SQL Server protocol, authenticates, and then sends queries while receiving result sets over the same session. Many applications use connection pooling, so a small number of long lived connections can carry many transactions, which is why you may see steady traffic even when user activity is bursty. From a security perspective, database ports represent high value data access. Exposing 1433 beyond the application tier increases brute force risk, expands lateral movement paths, and can turn one compromised host into a data breach.",
        "why": "Database ports are high value. If 1433 is exposed beyond what is necessary, attackers can brute force credentials, exploit unpatched vulnerabilities, or pivot into the data layer. Even internally, over permissive access to the database tier increases blast radius.",
        "how": ["Client opens a TCP connection and negotiates the SQL Server protocol and session settings.", "Client authenticates, then sends queries and receives result sets over the same connection.", "Connections are often pooled by applications for performance, keeping sessions open."],
        "pitfalls": ["Exposing 1433 directly to the internet.", "Using shared or weak database accounts and embedding credentials in code.", "Assuming network reachability equals authorization. Many breaches start with lateral movement into the database tier."],
        "security": ["Restrict access to application subnets and use firewalls or private endpoints.", "Patch regularly and disable unused features.", "Monitor for failed logins, unusual query patterns, and data exfiltration signals."],
        "alternatives": ["Managed database with private endpoints", "Database proxy"],
        "example": "An application server connects to SQL Server on 1433 using a pooled connection. If a workstation can also reach 1433, an attacker who compromises the workstation may attempt credential stuffing against the database.",
        "references": [],
    },
    1521: {
        "service": "Oracle SQL*Net",
        "transport": "TCP",
        "summary": "Oracle listener port for database connections. Configuration can vary by environment.",
        "what": "TCP port 1521 is commonly used by Oracle Database listeners. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. The Oracle listener process binds to 1521 and accepts incoming client sessions. A client connects from an ephemeral source port, completes the TCP handshake, negotiates the Oracle Net protocol, authenticates, and then runs queries and transactions over the established session. In large environments, a listener can front multiple database instances and services, so the exact behavior depends on configuration, but the port still represents the entry point to the data tier. Security wise, open 1521 is frequently scanned, and unpatched listeners or weak credentials can expose sensitive databases. The safest stance is tight network segmentation, strong authentication, and monitoring for unusual connection patterns.",
        "why": "Like all database ports, 1521 is sensitive. It can expose service metadata and become a target for brute force and exploit attempts. Many environments keep Oracle listeners on private networks and mediate access through application tiers.",
        "how": ["Client connects to the listener and negotiates the Oracle Net protocol.", "Client identifies the desired service, then authenticates and establishes a session.", "Queries and results flow over the session, often with connection pooling at the application layer."],
        "pitfalls": ["Exposing the listener to broad networks or the internet.", "Leaving default accounts or weak passwords in place.", "Assuming the listener port equals one database. Multiple services can be reachable behind one listener."],
        "security": ["Restrict network access to the listener and enforce strong auth and encryption options where supported.", "Patch and harden the database and listener configuration.", "Monitor for enumeration and abnormal connection attempts."],
        "alternatives": ["Private listener behind app tier", "Database gateway"],
        "example": "A reporting app connects to an Oracle listener on 1521 using a service name. The listener routes the session to the correct database instance, which is why access control should be enforced at both network and database layers.",
        "references": [],
    },
    1723: {
        "service": "PPTP",
        "transport": "TCP",
        "summary": "Legacy VPN control channel. The data plane uses GRE and the security model is outdated.",
        "what": "TCP port 1723 is used by PPTP, a legacy VPN protocol, and it shows that a port can represent only one piece of a larger tunnel. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. PPTP uses TCP 1723 for the control channel where the client and server negotiate tunnel setup and authentication. The actual user data is carried separately using GRE, which is IP protocol 47, not TCP or UDP, so a working PPTP connection typically requires both TCP 1723 and GRE to pass through firewalls and NAT. In practice, a client first establishes the control connection to port 1723, the tunnel is created, and then PPP frames are encapsulated inside GRE for the data path. Security wise, PPTP is considered obsolete due to known cryptographic weaknesses, so seeing 1723 open often indicates legacy remote access that should be migrated to modern VPNs.",
        "why": "PPTP matters mainly as a risk signal. Its cryptographic choices are outdated and it is widely discouraged. If you find PPTP enabled, you should assume it exists for legacy reasons and prioritize a migration to a modern VPN.",
        "how": ["Client connects to 1723 to set up a control session and negotiate PPP parameters.", "A GRE tunnel carries the encapsulated data traffic.", "Authentication and encryption depend on the chosen PPP mechanisms, which are weak by modern standards."],
        "pitfalls": ["Assuming PPTP is secure because it is called a VPN.", "Blocking only 1723 and forgetting GRE is required for the tunnel.", "Leaving it enabled for compatibility long after it is needed."],
        "security": ["Prefer modern VPNs such as WireGuard or IPsec based solutions.", "If PPTP cannot be removed immediately, restrict it to a small internal use case and plan a timeline to retire it.", "Monitor for connections and disable weak auth methods."],
        "alternatives": ["WireGuard", "IPsec IKEv2", "OpenVPN"],
        "example": "A remote user connects to a legacy PPTP server. The control session is on 1723, but the traffic itself is inside GRE. Many firewalls treat this combination differently, which is one reason PPTP causes support tickets.",
        "references": [],
    },
    2049: {
        "service": "NFS",
        "transport": "TCP and UDP",
        "summary": "Network File System. Often depends on additional RPC services and strict network scoping.",
        "what": "Port 2049 is used by NFS, the Network File System, for sharing filesystems over the network. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. An NFS server listens on 2049 so clients can mount exports and perform file operations remotely as if they were local. A client connects, negotiates the NFS version and settings, and then performs reads, writes, and metadata operations as remote procedure calls over the session. Depending on NFS version and environment, other RPC related services may be involved for discovery and locking, which can expand the set of required flows beyond a single port. From a security view, NFS can expose large volumes of data if exports are too permissive, and historically some deployments relied on network trust more than strong authentication, so segmentation and least privilege exports matter.",
        "why": "NFS is powerful and risky if exposed broadly. It can leak files, enable unauthorized writes, and become a pivot point. In cloud and data center networks, NFS is often restricted to specific subnets and backed by strong identity controls and export policies.",
        "how": ["Client contacts the NFS server on 2049 and negotiates the NFS version and options.", "Client mounts exported paths and performs file operations as RPC calls.", "Access decisions depend on export configuration, client identity mapping, and sometimes Kerberos based auth."],
        "pitfalls": ["Exposing NFS exports to broad networks or to untrusted clients.", "Assuming user identity is enforced when exports are configured with weak mapping.", "Forgetting that NFS performance and reliability depend on network latency and proper locking behavior."],
        "security": ["Restrict NFS to private networks and only the clients that need it.", "Use strong export policies and consider Kerberos based security modes where available.", "Monitor mounts and access patterns and inventory exposed exports."],
        "alternatives": ["SMB with signing", "Object storage APIs"],
        "example": "A compute cluster mounts a shared dataset from an NFS server. If a workstation can also reach 2049, an attacker might mount the export and copy data, so network scoping is as important as permissions.",
        "references": [],
    },
    3306: {
        "service": "MySQL",
        "transport": "TCP",
        "summary": "Default MySQL database port. Often used by apps and admin tools.",
        "what": "TCP port 3306 is the default port for MySQL. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A MySQL server binds to 3306 and client applications connect from ephemeral source ports. After the TCP handshake, the MySQL protocol handshake exchanges capabilities and authentication data, and then the client sends SQL queries while the server returns result sets. In real applications, connection pools keep sessions open for performance, so database exposure is often long lived and predictable, which helps defenders baseline normal behavior. Security wise, 3306 should rarely be reachable from end user networks or the internet. If it is exposed, attackers can brute force accounts, exploit vulnerable server versions, or abuse overly privileged application credentials to exfiltrate data.",
        "why": "Database services are critical assets. Exposed MySQL ports invite brute force and exploit attempts. Even inside a network, broad access to 3306 increases the impact of a compromised host, so segmentation and least privilege matter.",
        "how": ["Client opens a connection and negotiates the MySQL handshake, including capability flags.", "Client authenticates and then sends queries and receives results over the session.", "Applications often use connection pools, so one compromised app node can access the data layer continuously."],
        "pitfalls": ["Allowing remote root access or using shared admin accounts.", "Exposing 3306 to the internet or to user VLANs.", "Skipping TLS on database connections when traversing untrusted networks or shared infrastructure."],
        "security": ["Restrict access to application subnets and require strong authentication and least privilege users.", "Enable TLS for client connections where appropriate and patch the server regularly.", "Monitor for unusual logins, long running queries, and data dump patterns."],
        "alternatives": ["Database proxy", "Managed MySQL with private networking"],
        "example": "A web app connects to MySQL on 3306 from an app subnet. If a developer laptop can also reach 3306, credential theft on that laptop can lead directly to database access.",
        "references": [],
    },
    3389: {
        "service": "RDP",
        "transport": "TCP",
        "summary": "Windows Remote Desktop. High value target for brute force and ransomware operators.",
        "what": "TCP port 3389 is the default port for Remote Desktop Protocol, which provides an interactive remote session to Windows systems. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. An RDP service listens on 3389, and a client connects from an ephemeral source port to start a session. After the TCP handshake, the client and server negotiate security and session parameters, and with Network Level Authentication the user authenticates before the full desktop session is created. The session then carries screen updates, clipboard, file redirection, and input events. Because RDP is full remote control, it is a high value target. Exposed 3389 is heavily scanned and is associated with password spraying, brute force, and exploitation of unpatched vulnerabilities. In practice, safe designs place RDP behind VPN or jump hosts, enforce MFA, and monitor for failed logins and unusual session creation.",
        "why": "RDP exposure is a major risk factor. Attackers brute force credentials, exploit unpatched flaws, or buy leaked credentials, then use RDP for interactive control. Even internally, excessive RDP access can speed up lateral movement.",
        "how": ["Client connects and negotiates session parameters and encryption.", "User authenticates, ideally with Network Level Authentication before the full desktop session is established.", "The session carries screen updates, input, clipboard, and sometimes drive mapping and file transfer features."],
        "pitfalls": ["Publishing RDP directly to the internet without MFA and strong access control.", "Allowing weak passwords or shared accounts.", "Leaving clipboard and drive redirection enabled where it is not needed."],
        "security": ["Use VPN or a bastion host, enforce MFA, and restrict by IP and device posture.", "Enable NLA and keep Windows patched.", "Monitor logons, lockout events, and unusual session durations or geographies."],
        "alternatives": ["Remote management via VPN", "Privileged access workstations", "SSM or bastion solutions"],
        "example": "An MSP exposes RDP to manage servers. After a password leak, an attacker logs in and deploys ransomware. The safer design is VPN plus MFA and a jump host with tight auditing.",
        "references": [],
    },
    5432: {
        "service": "PostgreSQL",
        "transport": "TCP",
        "summary": "Default PostgreSQL listener. Often protected behind app tiers and private networks.",
        "what": "TCP port 5432 is the default port for PostgreSQL. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. The Postgres server listens on 5432 and clients connect from ephemeral source ports. The flow is: TCP handshake, protocol and parameter negotiation, authentication, then SQL queries and result sets over the established session. As with other databases, applications often use connection pools and long lived sessions, which can hide the true number of user actions behind a small set of connections. Security wise, 5432 is a direct path to data. Exposing it too broadly enables brute force, credential reuse attacks, and data exfiltration if application roles are over privileged. Network segmentation plus least privilege roles and monitoring are the practical controls.",
        "why": "PostgreSQL often holds business critical data. Exposing 5432 broadly can allow credential attacks and data exfiltration. Many incidents start with a single compromised host that can reach the database tier, so segmentation and least privilege are crucial.",
        "how": ["Client connects and negotiates protocol version and session settings.", "Client authenticates, then sends queries and receives results.", "Applications frequently reuse pooled connections, so a single app node can make many requests quickly."],
        "pitfalls": ["Exposing 5432 to the internet or user networks.", "Running with superuser level credentials in applications.", "Ignoring TLS and role based permissions when traffic crosses shared networks."],
        "security": ["Restrict network access and enforce least privilege roles.", "Enable TLS and patch regularly, including extensions.", "Monitor for unusual login attempts and large data exports."],
        "alternatives": ["Private endpoints", "Database proxy"],
        "example": "A CI pipeline runs migrations against Postgres on 5432. If that port is reachable from developer laptops, a compromised laptop could attempt the same credentials, so access should be restricted to the CI runner network.",
        "references": [],
    },
    5900: {
        "service": "VNC",
        "transport": "TCP",
        "summary": "Remote desktop protocol. Security depends heavily on configuration and tunneling.",
        "what": "TCP port 5900 is commonly used by VNC, a remote desktop and screen sharing protocol. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A VNC server binds to 5900, and a client connects from an ephemeral source port. After the TCP handshake, the two sides negotiate protocol options and authentication, then the server streams screen updates while the client sends mouse and keyboard events. Many VNC implementations historically offered weak encryption or none, so the safe posture is to treat VNC as an internal only service or to wrap it in a secure tunnel such as SSH or a VPN. From a security perspective, exposed 5900 is a common finding in scans and can lead to unauthorized desktop access if passwords are weak or the service is misconfigured.",
        "why": "VNC is a frequent finding in internal scans and on lab systems. Exposed VNC can lead to full interactive control, so it is treated as a high impact service similar to RDP. Even with encryption, weak passwords and lack of MFA remain a problem.",
        "how": ["Client connects and negotiates the VNC protocol and supported authentication methods.", "User authenticates and the server streams framebuffer updates while receiving input events.", "If VNC is tunneled, the VNC traffic rides inside SSH or a VPN rather than being directly exposed."],
        "pitfalls": ["Running VNC without encryption or with default passwords.", "Exposing 5900 beyond a management network.", "Assuming a tunneled setup is safe while leaving the tunnel endpoints poorly protected."],
        "security": ["Require a VPN or SSH tunnel, enforce strong auth, and restrict by network.", "Disable unused VNC servers and patch regularly.", "Monitor for repeated auth failures and new listening services."],
        "alternatives": ["RDP with NLA", "Remote support tools with MFA"],
        "example": "A Linux workstation runs VNC for remote support. The team disables direct 5900 exposure and requires SSH port forwarding, so only authenticated SSH users can reach the VNC server.",
        "references": [],
    },
    6379: {
        "service": "Redis",
        "transport": "TCP",
        "summary": "In memory data store. Dangerous when exposed because it often assumes trusted networks.",
        "what": "TCP port 6379 is the default port for Redis, an in memory data store often used for caching, sessions, and queues. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. A Redis server binds to 6379 and clients connect from ephemeral source ports, complete the TCP handshake, and then issue simple commands like GET and SET to read and write keys. Redis is fast partly because the protocol is simple and assumes a trusted network environment by default. That assumption is the security problem: if port 6379 is reachable from untrusted networks, attackers can often read data, change configuration, or abuse Redis features for persistence and lateral movement. In real deployments, the port should be reachable only from the application tier, protected with authentication and ACLs where available, and monitored for unusual commands and access patterns.",
        "why": "Redis exposure is high risk because an attacker can often read sensitive cached data, manipulate application behavior, or abuse administrative commands. Publicly exposed Redis has been used for cryptomining, data theft, and ransomware style attacks.",
        "how": ["Client connects and sends commands such as GET, SET, and PUBLISH over a persistent TCP connection.", "The server processes commands in memory and returns small responses very quickly.", "Optional persistence and replication may connect additional nodes, expanding the attack surface if not segmented."],
        "pitfalls": ["Binding Redis to 0.0.0.0 without authentication or network controls.", "Assuming a non default port or obscure hostname provides security.", "Leaving dangerous commands enabled when they are not needed."],
        "security": ["Keep Redis on private networks, require authentication, and use TLS where supported.", "Restrict commands and configure ACLs to limit what clients can do.", "Monitor for unexpected keys, replication changes, and high CPU patterns that indicate abuse."],
        "alternatives": ["Managed Redis with private networking", "Memcached or app level caches with guardrails"],
        "example": "A web app stores session tokens in Redis. If 6379 is exposed to the internet, an attacker can enumerate keys and steal sessions, so the correct design is private subnets plus ACLs and auth.",
        "references": [],
    },
    8080: {
        "service": "HTTP alt",
        "transport": "TCP",
        "summary": "Common alternate HTTP port for proxies, app servers, and admin panels.",
        "what": "TCP port 8080 is a very common alternative HTTP port used by proxies, application servers, and development or admin interfaces. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. Teams often choose 8080 when port 80 is reserved, when running behind a reverse proxy, or when a product ships a secondary web UI. The network behavior is the same as HTTP on 80: the client connects from an ephemeral source port, completes the TCP handshake, then sends HTTP requests and receives responses. The important real world detail is that 8080 does not guarantee it is safe or internal. Many forgotten admin panels and debug endpoints live here, sometimes with weaker authentication than the main site. So when 8080 is open, the right question is which web service it is, who should reach it, and whether it is patched and access controlled like any other internet facing web surface.",
        "why": "8080 matters because it is a common place where hidden admin panels live. Attackers scan it constantly. Internally, teams also use it for staging services, which can leak data if firewall rules are too relaxed.",
        "how": ["Client connects and speaks HTTP similar to port 80.", "The service might be a proxy, a web app, or a management UI, often with different authentication than the main site.", "Some environments use 8080 as a backend port behind a load balancer that terminates TLS elsewhere."],
        "pitfalls": ["Assuming 8080 is only internal and leaving weak default credentials.", "Exposing backend services directly without TLS or authentication.", "Forgetting to restrict it when a temporary debug server becomes permanent."],
        "security": ["Treat 8080 as a first class web exposure: authenticate, patch, and log it.", "Restrict management UIs to VPN or admin networks.", "Inventory what runs on 8080 and remove dead services."],
        "alternatives": ["HTTP on 80", "HTTPS on 443"],
        "example": "A Kubernetes ingress controller exposes an internal status page on 8080. If that port is reachable from user networks, it may leak routes and service names, so you restrict it to the cluster admin network.",
        "references": [],
    },
    8443: {
        "service": "HTTPS alt",
        "transport": "TCP",
        "summary": "Common alternate HTTPS port, often for management consoles and application servers.",
        "what": "TCP port 8443 is a common alternative HTTPS port, often used for management consoles, developer tools, and application servers. A port is a transport layer number used together with an IP address and a protocol such as TCP or UDP to direct traffic to the correct service on a host. A server process binds a socket to a port and listens, while a client typically chooses an ephemeral source port for outbound connections. The combination of source and destination IP addresses, source and destination ports, and the transport protocol uniquely identifies a flow so the operating system can keep many conversations separate. Firewalls, NAT, and scanners talk about ports because the destination port is the stable rendezvous point that exposes a service to the network. It usually behaves like HTTPS on 443: the client connects from an ephemeral source port, completes a TCP handshake, performs a TLS handshake with certificate validation, and then exchanges HTTP requests and responses inside the encrypted channel. The reason this port matters is practical: products sometimes put a privileged admin UI on 8443, separate from the public site on 443, and those interfaces may have default credentials or weaker hardening. If 8443 is reachable, treat it as a first class web exposure. Verify who can access it, ensure modern TLS and strong authentication, and do not rely on security controls that only cover standard ports.",
        "why": "8443 is relevant because many admin interfaces ship with default credentials and self signed certificates. Attackers look for it in scans. From a defender view, it is a place to check for forgotten management UIs that bypass your normal security controls.",
        "how": ["Client connects and performs a TLS handshake similar to any HTTPS service.", "HTTP requests then flow inside the encrypted channel, often for admin or application endpoints.", "Certificate trust and TLS configuration determine how safe the transport layer is."],
        "pitfalls": ["Using self signed certificates and training users to click through warnings.", "Leaving vendor default passwords on management consoles.", "Assuming security controls on 443 apply here too. Many proxies and WAFs only cover standard ports."],
        "security": ["Apply the same TLS and authentication standards as 443 and keep software patched.", "Restrict access to management interfaces via VPN or allowlists.", "Monitor for scanning and login attempts and disable unused consoles."],
        "alternatives": ["HTTPS on 443 behind a reverse proxy", "mTLS for admin endpoints"],
        "example": "A device exposes a web admin UI on 8443 with a self signed cert. You place it behind a VPN and rotate credentials, then replace the certificate with one from your internal CA.",
        "references": [],
    },
}


def _get_port_details(port_num: Optional[int]) -> dict[str, Any]:
    if port_num is None:
        return {}
    en_details = _PORT_DETAILS.get(port_num, {})
    if _current_locale_code() != "sv":
        return en_details
    sv_details = _load_port_details_sv().get(port_num, {})
    if isinstance(sv_details, dict) and sv_details:
        return sv_details
    return en_details


def _build_port_learn(item: dict[str, Any]) -> dict[str, Any]:
    """Build 'learn' content for Ports pages (content only, no routing or layout changes)."""
    port_num = item.get("port")
    details: dict[str, Any] = _get_port_details(port_num)

    def _get_text(key: str, fallback: str = "") -> str:
        return (details.get(key) or item.get(key) or fallback or "").strip()

    learn: dict[str, Any] = {
        "what": _get_text("what", item.get("intro", "")),
        "why": _get_text("why", ""),
        "how": details.get("how") or [],
        "pitfalls": details.get("pitfalls") or [],
        "security": details.get("security") or [],
        "example": _get_text("example", ""),
        # NOTE: Intentionally no selfTest and no deepDive for Ports pages.
    }

    # Optional references for future use (not rendered in the Concepts page template today).
    refs = details.get("references") or []
    if refs:
        learn["references"] = refs

    return learn




def _ensure_learn(item: dict[str, Any], key: str) -> dict[str, Any]:
    if item.get("learn") and isinstance(item.get("learn"), dict):
        return item

    learn: dict[str, Any] = {"overview": "", "why": "", "how": [], "pitfalls": [], "references": []}
    learn["overview"] = item.get("summary") or item.get("desc") or item.get("intro") or ""

    if key == "frameworksAndStandards":
        learn["why"] = "Frameworks help you structure security work, prioritize controls, and communicate progress."
        learn["how"] = _unique_list(
            [
                "Use it to pick controls based on risk and assets.",
                "Map to policies, procedures, and technical safeguards.",
                "Measure maturity and track improvements over time.",
            ]
        )
        learn["pitfalls"] = _unique_list(
            [
                "Treating compliance as security.",
                "Copying controls without context or asset understanding.",
            ]
        )
    elif key == "principlesAndIdentity":
        learn["why"] = "Identity is the new perimeter. Strong identity design reduces blast radius and improves auditability."
        learn["how"] = _unique_list(
            [
                "Apply least privilege and strong authentication.",
                "Use lifecycle controls: joiner, mover, leaver.",
                "Log and review privileged access.",
            ]
        )
        learn["pitfalls"] = _unique_list(
            [
                "Long lived admin accounts.",
                "Weak password only access for sensitive systems.",
            ]
        )
    elif key == "networkingAndProtocols":
        learn["why"] = "Networking fundamentals help you interpret traffic, understand exposure, and triage incidents faster."
        learn["how"] = _unique_list(
            [
                "Learn common protocols and where they appear.",
                "Use packet captures to validate assumptions.",
                "Map services to ports and flows.",
            ]
        )
        learn["pitfalls"] = _unique_list(
            [
                "Assuming a port always equals a specific service.",
                "Ignoring encryption, proxies, and tunneling.",
            ]
        )

    learn["references"] = _unique_list(item.get("references") or [])
    item["learn"] = learn
    return item


def _apply_concept_learn_override(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        return item

    title = (item.get("name") or item.get("title") or "").strip().lower()

    if title == "least privilege":
        item["learn"] = {
            "overview": "Grant only the permissions needed to complete a task, and nothing more.",
            "why": "Reduces blast radius, limits lateral movement, and prevents accidental misuse.",
            "how": [
                "Use roles and groups instead of direct user grants.",
                "Prefer time bound privileged access where possible.",
                "Review access regularly and remove unused permissions.",
            ],
            "pitfalls": [
                "Granting admin rights for convenience.",
                "Never removing access when job roles change.",
            ],
            "references": _unique_list(item.get("references") or []),
        }

    return item


def _snippet(text: str, n: int = 120) -> str:
    s = (text or "").strip()
    s = re.sub(r"\s+", " ", s)
    if len(s) <= n:
        return s
    return s[: n - 1].rstrip() + "..."


def _limit(items: Any, n: int = 10) -> list[Any]:
    if not isinstance(items, list):
        return []
    return items[:n]


def _pick_n(items: list[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    if not items:
        return []
    if len(items) <= n:
        copy = list(items)
        random.shuffle(copy)
        return copy
    return random.sample(items, n)


@app.route("/")
def home():
    tools = load_tools()
    concepts = load_concepts()
    defend = load_defend()
    devsecops = load_devsecops()
    commands = load_commands()
    attack_flows_data = load_attack_flows()

    cli = tools.get("cliTools", []) or []
    gui = tools.get("guiTools", []) or []
    det = tools.get("detectionTool") or None
    det_list = tools.get("detectionTools", []) or []

    tools_count = len(cli) + len(gui) + (1 if det else 0) + (len(det_list) if isinstance(det_list, list) else 0)
    commands_count = len(commands) if isinstance(commands, list) else 0

    concepts_count = 0
    if isinstance(concepts, dict):
        for v in concepts.values():
            if isinstance(v, list):
                concepts_count += len(v)

    defend_count = 0
    if isinstance(defend, dict):
        for v in defend.values():
            if isinstance(v, list):
                defend_count += len(v)

    candidates: list[dict[str, Any]] = []

    if isinstance(commands, list):
        for c in commands:
            if not isinstance(c, dict):
                continue
            name = c.get("name") or _("Command")
            desc = c.get("description") or c.get("command") or ""
            candidates.append(
                {
                    "kind": _("Command"),
                    "title": name,
                    "desc": desc,
                    "href": "/command-library#cmd-" + slugify(str(name)),
                }
            )

    tools_data = tools if isinstance(tools, dict) else {}

    for t in tools_data.get("cliTools", []) or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not tid:
            continue
        candidates.append(
            {
                "kind": _("Tool (CLI)"),
                "title": t.get("name") or _("Tool"),
                "desc": t.get("description") or t.get("desc") or "",
                "href": f"/tools/{tid}",
            }
        )

    for t in tools_data.get("guiTools", []) or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not tid:
            continue
        candidates.append(
            {
                "kind": _("Tool (GUI)"),
                "title": t.get("name") or _("Tool"),
                "desc": t.get("description") or t.get("desc") or "",
                "href": f"/tools/{tid}",
            }
        )

    det2 = tools_data.get("detectionTool") or {}
    if isinstance(det2, dict) and det2.get("id"):
        suggests = det2.get("description") or det2.get("desc") or ""
        candidates.append(
            {
                "kind": _("Tool (Detection)"),
                "title": det2.get("name") or _("Tool"),
                "desc": suggests,
                "href": f"/tools/{det2.get('id')}",
            }
        )

    for t in tools_data.get("detectionTools", []) or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not tid:
            continue
        candidates.append(
            {
                "kind": _("Tool (Detection)"),
                "title": t.get("name") or _("Tool"),
                "desc": t.get("description") or t.get("desc") or "",
                "href": f"/tools/{tid}",
            }
        )

    concept_mapping = {
        "frameworksAndStandards": "frameworks-and-standards",
        "principlesAndIdentity": "principles-and-identity",
        "networkingAndProtocols": "networking-and-protocols",
        "ports": "ports",
        "otSecurity": "ot-security",
    }
    if isinstance(concepts, dict):
        for key, cat_slug in concept_mapping.items():
            items = concepts.get(key, []) or []
            if not isinstance(items, list):
                continue
            for it in items:
                if not isinstance(it, dict):
                    continue
                cid_val = it.get("id")
                if key == "ports":
                    cid_val = it.get("port")
                if cid_val is None:
                    continue
                title = it.get("title") or it.get("name") or _("Concept")
                desc = it.get("summary") or it.get("desc") or it.get("intro") or ""
                candidates.append(
                    {
                        "kind": _("Concept"),
                        "title": title,
                        "desc": desc,
                        "href": f"/concepts/{cat_slug}/{cid_val}",
                    }
                )

    defend_mapping = {
        "detectionAndLogging": "detection-and-logging",
        "hardening": "hardening",
    }
    if isinstance(defend, dict):
        for key, section in defend_mapping.items():
            block = defend.get(key, []) or []
            if not isinstance(block, list):
                continue
            for it in block:
                if not isinstance(it, dict):
                    continue
                tid = it.get("id")
                if not tid:
                    continue
                candidates.append(
                    {
                        "kind": _("Defend"),
                        "title": it.get("title") or it.get("name") or _("Defend"),
                        "desc": it.get("intro") or "",
                        "href": f"/defend/{section}/{tid}",
                    }
                )

    if isinstance(devsecops, dict):
        for category in devsecops.get("sections", []) or []:
            if not isinstance(category, dict):
                continue
            section_id = category.get("id")
            if not section_id:
                continue
            for topic in category.get("topics", []) or []:
                if not isinstance(topic, dict):
                    continue
                topic_id = topic.get("id")
                if not topic_id:
                    continue
                candidates.append(
                    {
                        "kind": _("DevSecOps"),
                        "title": topic.get("title") or _("DevSecOps"),
                        "desc": topic.get("summary") or topic.get("intro") or category.get("summary") or "",
                        "href": f"/devsecops/{section_id}/{topic_id}",
                    }
                )

    if isinstance(attack_flows_data, dict):
        for atk in attack_flows_data.get("attacks", []) or []:
            if not isinstance(atk, dict):
                continue
            slug = atk.get("slug")
            if not slug:
                continue
            candidates.append(
                {
                    "kind": _("Attack Flow"),
                    "title": atk.get("name") or _("Attack Flow"),
                    "desc": atk.get("short_description") or "",
                    "href": f"/attack-flows/{slug}",
                }
            )

    quick_picks = _pick_n(candidates, 3)

    attack_flows_count = len(attack_flows_data.get("attacks", [])) if isinstance(attack_flows_data, dict) else 0

    return render_template(
        "home.html",
        tools_count=tools_count,
        commands_count=commands_count,
        concepts_count=concepts_count,
        defend_count=defend_count,
        attack_flows_count=attack_flows_count,
        quick_picks=quick_picks,
    )


@app.route("/toolbox")
def toolbox_hub():
    tools = load_tools()
    return render_template("tools_landing.html", tools=tools)


@app.route("/tools")
def tools_redirect():
    return redirect(url_for("toolbox_hub"))


def _find_tool_by_id(tools_data: dict[str, Any], tool_id: str) -> Optional[dict[str, Any]]:
    tool_id = (tool_id or "").strip()
    if not tool_id:
        return None

    for t in tools_data.get("cliTools", []) or []:
        if isinstance(t, dict) and t.get("id") == tool_id:
            return {**t, "kind": "CLI"}

    for t in tools_data.get("guiTools", []) or []:
        if isinstance(t, dict) and t.get("id") == tool_id:
            return {**t, "kind": "GUI"}

    det3 = tools_data.get("detectionTool") or {}
    if isinstance(det3, dict) and det3.get("id") == tool_id:
        return {**det3, "kind": "Detection"}

    for t in tools_data.get("detectionTools", []) or []:
        if isinstance(t, dict) and t.get("id") == tool_id:
            return {**t, "kind": "Detection"}

    return None


@app.route("/tools/<tool_id>")
def tool_view(tool_id: str):
    tools = load_tools()
    tool = _find_tool_by_id(tools, tool_id) if isinstance(tools, dict) else None
    if not tool:
        return render_template("tool_view.html", tool={}, not_found=True), 404
    return render_template("tool_view.html", tool=tool)


@app.route("/command-library")
def command_library():
    commands = load_commands()
    return render_template("commands.html", commands=commands)


@app.route("/cmd_lib")
def cmd_lib_page():
    commands = load_commands()
    return render_template("cmd_lib.html", commands=commands)


@app.route("/cheatsheet")
def cheatsheet_legacy_redirect():
    return redirect(url_for("cmd_lib_page"), code=301)


@app.route("/api/commands")
def api_commands():
    return jsonify(load_commands())


@app.route("/api/search")
def api_search():
    q = (request.args.get("q") or "").strip()
    empty = {"commands": [], "tools": [], "concepts": [], "ports": [], "devsecops": [], "defend": [], "attack_flows": []}
    if not q:
        return jsonify(empty)

    ql = q.lower()

    def match_any(text: Any, *parts: Any) -> bool:
        s = str(text or "").lower()
        if ql in s:
            return True
        for p in parts:
            if ql in str(p or "").lower():
                return True
        return False

    results: dict[str, list[dict[str, Any]]] = {
        "commands": [],
        "tools": [],
        "concepts": [],
        "ports": [],
        "devsecops": [],
        "defend": [],
        "attack_flows": [],
    }

    try:
        commands = load_commands()
        if isinstance(commands, list):
            for c in commands:
                if not isinstance(c, dict):
                    continue
                name = c.get("name") or ""
                if match_any(name, c.get("description"), c.get("command")):
                    results["commands"].append(
                        {
                            "title": name,
                            "category": _("Command"),
                            "href": "/command-library#cmd-" + slugify(str(name)),
                            "snippet": _snippet(str(c.get("description") or c.get("command") or "")),
                        }
                    )

        tools = load_tools()

        def add_tool(t: dict[str, Any], kind: str):
            tid = t.get("id")
            if not tid:
                return
            name = t.get("name") or ""
            if match_any(name, t.get("description"), t.get("desc")):
                results["tools"].append(
                    {
                        "title": name,
                        "category": _("Tool - %(kind)s", kind=kind),
                        "href": f"/tools/{tid}",
                        "snippet": _snippet(str(t.get("description") or t.get("desc") or "")),
                    }
                )

        if isinstance(tools, dict):
            for t in tools.get("cliTools", []) or []:
                if isinstance(t, dict):
                    add_tool(t, "CLI")
            for t in tools.get("guiTools", []) or []:
                if isinstance(t, dict):
                    add_tool(t, "GUI")
            det4 = tools.get("detectionTool") or {}
            if isinstance(det4, dict) and det4.get("id"):
                add_tool(det4, "Detection")
            for t in tools.get("detectionTools", []) or []:
                if isinstance(t, dict):
                    add_tool(t, "Detection")

        concepts = load_concepts()
        mapping = [
            ("frameworksAndStandards", _("Concept - Frameworks"), "frameworks-and-standards", "id"),
            ("principlesAndIdentity", _("Concept - Principles"), "principles-and-identity", "id"),
            ("networkingAndProtocols", _("Concept - Networking"), "networking-and-protocols", "id"),
            ("otSecurity", _("Concept - OT Security"), "ot-security", "id"),
        ]
        if isinstance(concepts, dict):
            for key, cat_label, cat_slug, id_field in mapping:
                for it in concepts.get(key, []) or []:
                    if not isinstance(it, dict):
                        continue
                    title = it.get("title") or it.get("name") or ""
                    if match_any(title, it.get("summary"), it.get("desc"), it.get("intro")):
                        cid_val = it.get(id_field)
                        if cid_val is None:
                            continue
                        results["concepts"].append(
                            {
                                "title": title,
                                "category": cat_label,
                                "href": f"/concepts/{cat_slug}/{cid_val}",
                                "snippet": _snippet(str(it.get("summary") or it.get("desc") or it.get("intro") or "")),
                            }
                        )

            for it in concepts.get("ports", []) or []:
                if not isinstance(it, dict):
                    continue
                port = it.get("port")
                title = f"Port {port}: {it.get('name') or ''}".strip()
                if match_any(title, it.get("desc"), str(port)):
                    if port is None:
                        continue
                    results["ports"].append(
                        {
                            "title": title,
                            "category": _("Concept - Ports"),
                            "href": f"/concepts/ports/{port}",
                            "snippet": _snippet(str(it.get("desc") or "")),
                        }
                    )

        defend = load_defend()
        if isinstance(defend, dict):
            for it in defend.get("detectionAndLogging", []) or []:
                if not isinstance(it, dict):
                    continue
                title = it.get("title") or ""
                if match_any(title, it.get("intro"), it.get("why")):
                    results["defend"].append(
                        {
                            "title": title,
                            "category": _("Defend - Detection"),
                            "href": f"/defend/detection-and-logging/{it.get('id')}",
                            "snippet": _snippet(str(it.get("intro") or "")),
                        }
                    )
            for it in defend.get("hardening", []) or []:
                if not isinstance(it, dict):
                    continue
                title = it.get("title") or ""
                if match_any(title, it.get("intro"), it.get("why")):
                    results["defend"].append(
                        {
                            "title": title,
                            "category": _("Defend - Hardening"),
                            "href": f"/defend/hardening/{it.get('id')}",
                            "snippet": _snippet(str(it.get("intro") or "")),
                        }
                    )

        devsecops = load_devsecops()
        if isinstance(devsecops, dict):
            for category in devsecops.get("sections", []) or []:
                if not isinstance(category, dict):
                    continue
                section_id = category.get("id")
                if not section_id:
                    continue
                for it in category.get("topics", []) or []:
                    if not isinstance(it, dict):
                        continue
                    title = it.get("title") or ""
                    if match_any(title, it.get("summary"), it.get("intro"), category.get("title"), category.get("summary")):
                        results["devsecops"].append(
                            {
                                "title": title,
                                "category": _("DevSecOps"),
                                "href": f"/devsecops/{section_id}/{it.get('id')}",
                                "snippet": _snippet(str(it.get("summary") or it.get("intro") or category.get("summary") or "")),
                            }
                        )

        attack_flows_data = load_attack_flows()
        if isinstance(attack_flows_data, dict):
            for atk in attack_flows_data.get("attacks", []) or []:
                if not isinstance(atk, dict):
                    continue
                title = atk.get("name") or ""
                if match_any(title, atk.get("short_description"), atk.get("mitre_id")):
                    results["attack_flows"].append(
                        {
                            "title": title,
                            "category": _("Attack Flows"),
                            "href": f"/attack-flows/{atk.get('slug')}",
                            "snippet": _snippet(str(atk.get("short_description") or "")),
                        }
                    )

    except Exception:
        return jsonify(empty)

    results["commands"] = _limit(results["commands"], 10)
    results["tools"] = _limit(results["tools"], 10)
    results["concepts"] = _limit(results["concepts"], 10)
    results["ports"] = _limit(results["ports"], 10)
    results["devsecops"] = _limit(results["devsecops"], 10)
    results["defend"] = _limit(results["defend"], 10)
    results["attack_flows"] = _limit(results["attack_flows"], 10)

    return jsonify(results)



def _cb_get_client_ip(req) -> str:
    """Best effort client IP extraction for rate limiting.

    Note: X-Forwarded-For can be spoofed unless your reverse proxy overwrites it.
    """
    xff = (req.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    xri = (req.headers.get("X-Real-IP") or "").strip()
    ip = xff or xri or (req.remote_addr or "").strip()
    return ip or "unknown"


@app.route("/api/ai", methods=["POST"])
def api_ai():
    """AI assistant endpoint for the right side drawer.

    Modes
    - explain_command: page_url, snippet_text
    - explain_selection: page_url, snippet_text
    - chat: page_url, message_text, optional context
    """

    authz = (request.headers.get("Authorization") or "").strip()
    id_token = ""
    if authz.lower().startswith("bearer "):
        id_token = authz[7:].strip()
    auth_required_message = _("Please log in to use the AI assistant.")
    if not id_token:
        return jsonify({"ok": False, "error": {"code": "AUTH_REQUIRED", "message": auth_required_message}}), 401
    try:
        decoded = verify_id_token(id_token)
        user_id = (decoded or {}).get("uid")
        if not user_id:
            return jsonify({"ok": False, "error": {"code": "AUTH_REQUIRED", "message": auth_required_message}}), 401
    except Exception:
        return jsonify({"ok": False, "error": {"code": "AUTH_REQUIRED", "message": auth_required_message}}), 401

    payload = request.get_json(silent=True) or {}
    mode = (payload.get("mode") or "").strip()
    page_url = (payload.get("page_url") or "").strip()

    page_topic = (payload.get("page_topic") or "").strip()
    syntax_text = payload.get("syntax_text") or ""

    snippet_text = payload.get("snippet_text") or ""

    message_text = payload.get("message_text") or ""
    context = payload.get("context") or []
    if not isinstance(context, list):
        context = []

    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    is_new_session = False
    if not session_id:
        session_id = secrets.token_hex(16)
        is_new_session = True

    debug = str(os.getenv("AI_ASSISTANT_DEBUG") or "").strip().lower() in ("1", "true", "yes")

    try:
        rate_id = _cb_get_client_ip(request)
        result = handle_ai_request(
            session_id=rate_id,
            mode=mode,
            page_url=page_url,
            page_topic=page_topic,
            snippet_text=snippet_text,
            syntax_text=syntax_text,
            message_text=message_text,
            context=context,
            fallback_language=_normalize_locale_code(str(get_locale() or "")) or "en",
            debug=debug,
        )

        status = 200
        if not result.get("ok"):
            code = (result.get("error") or {}).get("code")
            if code in ("cooldown", "daily_limit"):
                status = 429

        resp = jsonify(result)
        resp.status_code = status

    except AiAssistantError as e:
        logger.exception("AI endpoint handled error code=%s status=%s", e.code, e.http_status)
        if e.code == "bad_mode":
            resp = jsonify({"ok": False, "error": {"code": "bad_mode", "message": _("Invalid AI mode.")}})
            resp.status_code = e.http_status
        else:
            resp = jsonify({"ok": False, "error": {"code": "server_error", "message": _("AI request failed.")}})
            resp.status_code = e.http_status

    except Exception:  # pragma: no cover
        logger.exception("AI endpoint error")
        resp = jsonify({"ok": False, "error": {"code": "server_error", "message": _("AI request failed.")}})
        resp.status_code = 500

    if is_new_session:
        resp.set_cookie(
            SESSION_COOKIE_NAME,
            session_id,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="Lax",
            secure=request.is_secure,
        )

    return resp


# ========= New AI chat logging endpoints ========= #

def _now_utc() -> datetime:
    return datetime.utcnow()


def _gen_session_id() -> str:
    return secrets.token_hex(16)


# Settings are no longer used; logging is always on when authenticated.


@app.post("/api/ai/chat")
def api_ai_chat():
    # Require Authorization: Bearer <ID_TOKEN>
    authz = (request.headers.get("Authorization") or "").strip()
    id_token = ""
    if authz.lower().startswith("bearer "):
        id_token = authz[7:].strip()
    auth_required_message = _("Please log in to use the AI assistant.")
    if not id_token:
        return jsonify({"error": "AUTH_REQUIRED", "message": auth_required_message}), 401

    try:
        decoded = verify_id_token(id_token)
        user_id = (decoded or {}).get("uid")
        if not user_id:
            return jsonify({"error": "AUTH_REQUIRED", "message": auth_required_message}), 401
    except Exception:
        return jsonify({"error": "AUTH_REQUIRED", "message": auth_required_message}), 401

    payload = request.get_json(silent=True) or {}
    prompt = (payload.get("prompt") or "").strip()
    session_id = (payload.get("sessionId") or "").strip()
    page_path = (payload.get("pagePath") or "").strip()
    model = (payload.get("model") or "").strip()

    if not prompt:
        return jsonify({"error": _("Missing prompt")}), 400

    try:
        safe_page = (page_path or "")
        if len(safe_page) > 120:
            safe_page = safe_page[:119] + "..."
        logger.info("AI_CHAT start userId=%s sessionId=%s page=%s", user_id, (session_id or "<new>"), safe_page)
    except Exception:
        logger.info("AI_CHAT start userId=%s sessionId=%s", user_id, (session_id or "<new>"))

    # Context from prior messages if available (best-effort, DB optional)
    context_msgs: list[dict] = []
    if not session_id:
        session_id = _gen_session_id()

    sessions = None
    db_for_logging_name = None
    try:
        db = get_db()
        db_for_logging_name = getattr(db, "name", None) or "<unknown>"
        sessions = db["ai_chat_sessions"]
        prev = sessions.find_one({"userId": user_id, "sessionId": session_id}, {"messages": 1})
        if prev and isinstance(prev.get("messages"), list):
            for m in prev["messages"][-6:]:
                role = m.get("role")
                content = m.get("content")
                if role in ("user", "assistant") and content:
                    context_msgs.append({"role": role, "content": str(content)[:400]})
    except Exception:
        logger.warning("Mongo unavailable while building chat context; proceeding without it")

    # Call Gemini using existing helper to keep UX text formatting stable
    debug = str(os.getenv("AI_ASSISTANT_DEBUG") or "").strip().lower() in ("1", "true", "yes")
    started = time.time()
    try:
        result = handle_ai_request(
            session_id=_cb_get_client_ip(request),
            mode="chat",
            page_url=page_path,
            page_topic="",
            message_text=prompt,
            context=context_msgs,
            fallback_language=_normalize_locale_code(str(get_locale() or "")) or "en",
            debug=debug,
        )
    except AiAssistantError as e:
        logger.exception("/api/ai/chat handled error code=%s status=%s", e.code, e.http_status)
        return jsonify({"error": _("AI request failed.")}), e.http_status
    except Exception:
        logger.exception("/api/ai/chat failure")
        return jsonify({"error": _("AI request failed.")}), 502

    finished = time.time()
    reply = (result or {}).get("text") or ""

    try:
        logger.info("AI_CHAT gemini ok latencyMs=%d", int((finished - started) * 1000))
    except Exception:
        pass

    # Always attempt to log chat; if DB unavailable, return reply with logged=false
    logged_success = False
    try:
        if sessions is not None and reply:
            now = _now_utc()
            expires_at = now + timedelta(days=30)

            # Pre-write target logging
            try:
                logger.info(
                    "AI_CHAT mongo target db=%s collection=%s userId=%s sessionId=%s",
                    db_for_logging_name or "<unknown>",
                    "ai_chat_sessions",
                    user_id,
                    session_id,
                )
            except Exception:
                pass

            result = sessions.update_one(
                {"userId": user_id, "sessionId": session_id},
                {
                    "$setOnInsert": {
                        "userId": user_id,
                        "sessionId": session_id,
                        "createdAt": now,
                        "expiresAt": expires_at,
                    },
                    "$set": {
                        "updatedAt": now,
                        **({"pagePath": page_path} if page_path else {}),
                        **({"model": model} if model else {}),
                        "stats": {
                            "latencyMs": int((finished - started) * 1000),
                            "promptChars": len(prompt),
                            "responseChars": len(reply),
                        },
                    },
                    "$push": {
                        "messages": {
                            "$each": [
                                {"role": "user", "content": prompt, "createdAt": now},
                                {"role": "assistant", "content": reply, "createdAt": now},
                            ],
                            "$slice": -40,
                        }
                    },
                },
                upsert=True,
            )

            matched = getattr(result, "matched_count", None)
            modified = getattr(result, "modified_count", None)
            upserted = getattr(result, "upserted_id", None)
            logger.info(
                "AI_CHAT mongo write ok sessionId=%s matchedCount=%s modifiedCount=%s upsertedId=%s",
                session_id,
                str(matched),
                str(modified),
                str(upserted),
            )
            logged_success = True
    except Exception:
        logger.exception("AI_CHAT mongo write failed userId=%s sessionId=%s", user_id, session_id)

    return jsonify({"sessionId": session_id, "reply": reply, "logged": bool(logged_success)})


@app.get("/api/ai/settings")
def api_ai_get_settings():
    return jsonify({"error": "Not Found"}), 404


@app.post("/api/ai/settings")
def api_ai_set_settings():
    return jsonify({"error": "Not Found"}), 404


@app.post("/api/ai/delete-history")
@api_login_required
def api_ai_delete_history():
    user = getattr(g, "user", None)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = user.get("uid")
    try:
        db = get_db()
        res = db["ai_chat_sessions"].delete_many({"userId": user_id})
        logger.info("Deleted %s chat sessions for user %s", res.deleted_count, user_id)
        return jsonify({"ok": True})
    except Exception:
        logger.exception("Failed to delete ai_chat_sessions")
        return jsonify({"error": "Delete failed"}), 500


@app.route("/concepts")
def concepts_hub():
    concepts = load_concepts()
    return render_template("concepts_hub.html", concepts=concepts)


@app.route("/devsecops")
def devsecops_hub():
    devsecops = load_devsecops()
    return render_template("devsecops_hub.html", devsecops=devsecops)


@app.route("/resource-hub")
def resource_hub():
    return render_template("resource_hub.html")

@app.route("/knowledge-base")
def knowledge_base_legacy():
    return redirect(url_for('resource_hub'), code=301)

@app.route("/concepts/<cat>/<cid>")
def concept_detail(cat: str, cid: str):
    try:
        data = load_concepts()
        mapping = {
            "frameworks-and-standards": (_("Frameworks and Standards"), "frameworksAndStandards", "id"),
            "principles-and-identity": (_("Principles and Identity"), "principlesAndIdentity", "id"),
            "networking-and-protocols": (_("Networking and Protocols"), "networkingAndProtocols", "id"),
            "ports": (_("Ports"), "ports", "port"),
            "ot-security": (_("OT Security"), "otSecurity", "id"),
        }

        if cat not in mapping:
            return (
                render_template(
                    "concept_detail.html",
                    item={},
                    title=_("Not found"),
                    category=_("Concepts"),
                    not_found=True,
                    is_ports=False,
                ),
                404,
            )

        title_cat, key, id_field = mapping[cat]
        items = data.get(key) or []
        item = next((x for x in items if str(x.get(id_field)) == str(cid)), None)

        if not item:
            return (
                render_template(
                    "concept_detail.html",
                    item={},
                    title=_("Not found"),
                    category=title_cat,
                    not_found=True,
                    is_ports=False,
                ),
                404,
            )

        if key == "ports":
            port_num = _as_int(item.get("port"))
            details = _get_port_details(port_num)

            service = details.get("service") or item.get("name") or _("Service")
            port_str = str(item.get("port") or "")
            title = _("Port %(port)s: %(service)s", port=port_str, service=service)

            item = {
                **item,
                "summary": details.get("summary") or item.get("desc") or item.get("summary") or "",
                "intro": details.get("summary") or item.get("desc") or item.get("intro") or "",
            }
            item["learn"] = _build_port_learn(item)
            item["references"] = _unique_list((item.get("references") or []) + (item["learn"].get("references") or []))

            where_when = (
                _("You will see this in scans, firewall rules, vulnerability reports, and service configs. ")
                + _("Treat open ports as exposure points and verify the service is expected, hardened, and restricted.")
            )

            return render_template(
                "concept_detail.html",
                item=item,
                title=title,
                category=title_cat,
                where_when=where_when,
                not_found=False,
                is_ports=True,
            )

        item = _apply_concept_learn_override(item)
        item = _ensure_learn(item, key)

        where_when = item.get("where") or item.get("when") or item.get("used") or ""
        if not where_when:
            if key == "frameworksAndStandards":
                where_when = _(
                    "Used in governance, risk, and compliance work: control selection, audits, reporting, and security roadmaps."
                )
            elif key == "principlesAndIdentity":
                where_when = _(
                    "Used when designing and operating access control, authentication, authorization, and identity lifecycle."
                )
            elif key == "networkingAndProtocols":
                where_when = _(
                    "Shows up in packet captures, network diagrams, firewall rules, and system or network logs."
                )
            elif key == "otSecurity":
                where_when = _(
                    "Relevant in industrial environments, critical infrastructure, and wherever IT networks connect to operational technology systems."
                )

        return render_template(
            "concept_detail.html",
            item=item,
            title=item.get("name", _("Concept")),
            category=title_cat,
            where_when=where_when,
            not_found=False,
            is_ports=False,
        )

    except Exception:
        logger.exception("Concept detail failed cat=%s cid=%s", cat, cid)
        return render_template("error.html", error=_("Something went wrong.")), 500


@app.route("/defend")
def defend_hub():
    defend = load_defend()
    return render_template("defend_hub.html", defend=defend)


@app.route("/devsecops/<section>/<topic>")
def devsecops_detail(section: str, topic: str):
    devsecops = load_devsecops()
    categories = devsecops.get("sections", []) if isinstance(devsecops, dict) else []
    category_item = next((x for x in categories if str(x.get("id")) == str(section)), None)

    if not category_item:
        return (
            render_template(
                "devsecops_detail.html",
                item={},
                title=_("Not found"),
                category=_("DevSecOps"),
                section_id=section,
                not_found=True,
            ),
            404,
        )

    topics = category_item.get("topics", []) if isinstance(category_item, dict) else []
    item = next((x for x in topics if str(x.get("id")) == str(topic)), None)
    category_title = category_item.get("title") or _("DevSecOps")

    if not item:
        return (
            render_template(
                "devsecops_detail.html",
                item={},
                title=_("Not found"),
                category=category_title,
                section_id=section,
                not_found=True,
            ),
            404,
        )

    return render_template(
        "devsecops_detail.html",
        item=item,
        title=item.get("title", _("DevSecOps")),
        category=category_title,
        section_id=section,
        not_found=False,
    )


@app.route("/defend/<section>/<topic>")
def defend_detail(section: str, topic: str):
    defend = load_defend()
    mapping = {
        "detection-and-logging": (_("Detection and Logging"), "detectionAndLogging"),
        "hardening": (_("Hardening"), "hardening"),
    }

    if section not in mapping:
        return (
            render_template(
                "defend_detail.html",
                item={},
                title=_("Not found"),
                category=_("Defend"),
                not_found=True,
            ),
            404,
        )

    title_section, key = mapping[section]
    items = defend.get(key, [])
    item = next((x for x in items if str(x.get("id")) == str(topic)), None)

    if not item:
        return (
            render_template(
                "defend_detail.html",
                item={},
                title=_("Not found"),
                category=title_section,
                not_found=True,
            ),
            404,
        )

    return render_template(
        "defend_detail.html",
        item=item,
        title=item.get("title", _("Defend")),
        category=title_section,
        not_found=False,
    )


@app.route("/attack-flows")
def attack_flows_hub():
    data = load_attack_flows()
    attacks = data.get("attacks", []) if isinstance(data, dict) else []
    return render_template("attack_flows_hub.html", attacks=attacks)


@app.route("/attack-flows/<slug>")
def attack_flow_detail(slug: str):
    data = load_attack_flows()
    attacks = data.get("attacks", []) if isinstance(data, dict) else []
    attack = next((a for a in attacks if str(a.get("slug")) == str(slug)), None)

    if not attack:
        return (
            render_template(
                "attack_flow_detail.html",
                attack={},
                title=_("Not found"),
                not_found=True,
            ),
            404,
        )

    attacks_map = {a.get("slug"): {"name": a.get("name", ""), "icon": a.get("icon", "")} for a in attacks}
    return render_template(
        "attack_flow_detail.html",
        attack=attack,
        attacks_map=attacks_map,
        title=attack.get("name", _("Attack Flows")),
        not_found=False,
    )


def _log_analyzer_fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _log_analyzer_cleanup(now: float) -> None:
    # Evict old cache entries so it does not grow
    expired: list[str] = []
    for k, (ts, _) in _LOG_ANALYZER_CACHE.items():
        if now - ts > _LOG_ANALYZER_CACHE_TTL_SECONDS:
            expired.append(k)
    for k in expired:
        _LOG_ANALYZER_CACHE.pop(k, None)


def _log_analyzer_run_guarded(*, fingerprint: str, log_text: str, locale_code: str) -> dict:
    """Short cache and in flight guard to avoid double triggering."""

    cache_key = f"{fingerprint}|{locale_code}"
    now = time.monotonic()
    with _LOG_ANALYZER_LOCK:
        _log_analyzer_cleanup(now)

        cached = _LOG_ANALYZER_CACHE.get(cache_key)
        if cached and now - cached[0] <= _LOG_ANALYZER_CACHE_TTL_SECONDS:
            logger.info("[LogAnalyzer] cache_hit fp=%s locale=%s", fingerprint[:12], locale_code)
            return cached[1]

        event = _LOG_ANALYZER_INFLIGHT.get(cache_key)
        if event is None:
            event = threading.Event()
            _LOG_ANALYZER_INFLIGHT[cache_key] = event
            is_owner = True
        else:
            is_owner = False

    if not is_owner:
        # Wait briefly for the in progress analysis
        logger.info("[LogAnalyzer] inflight_wait fp=%s locale=%s", fingerprint[:12], locale_code)
        event.wait(timeout=8.0)
        now2 = time.monotonic()
        with _LOG_ANALYZER_LOCK:
            cached2 = _LOG_ANALYZER_CACHE.get(cache_key)
            if cached2 and now2 - cached2[0] <= _LOG_ANALYZER_CACHE_TTL_SECONDS:
                logger.info("[LogAnalyzer] inflight_return fp=%s locale=%s", fingerprint[:12], locale_code)
                return cached2[1]
        raise LogAnalyzerError(
            user_message=_("Analysis is already running for the same log. Please try again in a moment."),
            status_code=409,
        )

    # Owner runs the analysis
    try:
        findings = analyze_log_content(log_text)
        result = {"findings": findings}
        now3 = time.monotonic()
        with _LOG_ANALYZER_LOCK:
            _LOG_ANALYZER_CACHE[cache_key] = (now3, result)
        return result
    finally:
        with _LOG_ANALYZER_LOCK:
            ev = _LOG_ANALYZER_INFLIGHT.pop(cache_key, None)
            if ev:
                ev.set()


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    if request.method == "GET":
        return render_template("analyze.html")

    try:
        # Handle file uploads (expects JSON response for frontend fetch API)
        if "file" in request.files:
            uploaded = request.files.get("file")
            if not uploaded or not uploaded.filename:
                return jsonify({"error": _("No file provided.")}), 400

            data = uploaded.read() or b""
            # Enforce 5MB max (same as UI)
            if len(data) > 5 * 1024 * 1024:
                return jsonify({"error": _("File too large (max 5MB).")}), 413

            fp = _log_analyzer_fingerprint(data)
            req_id = request.headers.get("X-LogAnalyzer-Request-ID")
            if req_id:
                logger.info("[LogAnalyzer] request file req_id=%s fp=%s", req_id, fp[:12])

            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                # Fallback decode
                text = data.decode(errors="replace")

            locale_code = _normalize_locale_code(str(get_locale() or "")) or "en"
            result = _log_analyzer_run_guarded(fingerprint=fp, log_text=text, locale_code=locale_code)
            return jsonify(result), 200

        # Handle JSON body for text analysis (AJAX)
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            raw = payload.get("log_text") or payload.get("log_content") or ""
            if not isinstance(raw, str) or not raw.strip():
                return jsonify({"error": _("Missing log text.")}), 400

            # UI limit: max 200k characters
            if len(raw) > 200_000:
                return jsonify({"error": _("Input too large (max 200,000 characters).")}), 413

            fp = _log_analyzer_fingerprint(raw.encode("utf-8", errors="ignore"))
            req_id = request.headers.get("X-LogAnalyzer-Request-ID") or payload.get("request_id")
            if req_id:
                logger.info("[LogAnalyzer] request text req_id=%s fp=%s", req_id, fp[:12])
            locale_code = _normalize_locale_code(str(get_locale() or "")) or "en"
            result = _log_analyzer_run_guarded(fingerprint=fp, log_text=raw, locale_code=locale_code)
            return jsonify(result), 200

        # Fallback: traditional form post renders the page with results
        content = request.form.get("log_content") or ""
        result_list = analyze_log_content(content)
        return render_template("analyze.html", result=result_list, log_content=content)
    except LogAnalyzerError as e:
        return jsonify({"error": e.to_display_string()}), e.status_code
    except Exception:
        return jsonify({"error": _("Unexpected analyzer error.")}), 500


@app.route("/analyze-text", methods=["POST"])
def analyze_text():
    try:
        payload = request.get_json(silent=True) or {}
        raw = payload.get("log_text") or payload.get("log_content") or ""
        if not isinstance(raw, str) or not raw.strip():
            return jsonify({"error": _("Missing log text.")}), 400

        if len(raw) > 200_000:
            return jsonify({"error": _("Input too large (max 200,000 characters).")}), 413

        fp = _log_analyzer_fingerprint(raw.encode("utf-8", errors="ignore"))
        req_id = request.headers.get("X-LogAnalyzer-Request-ID") or payload.get("request_id")
        if req_id:
            logger.info("[LogAnalyzer] request analyze-text req_id=%s fp=%s", req_id, fp[:12])
        locale_code = _normalize_locale_code(str(get_locale() or "")) or "en"
        result = _log_analyzer_run_guarded(fingerprint=fp, log_text=raw, locale_code=locale_code)
        return jsonify(result), 200
    except LogAnalyzerError as e:
        return jsonify({"error": e.to_display_string()}), e.status_code
    except Exception:
        return jsonify({"error": _("Unexpected analyzer error.")}), 500


@app.route("/quiz", methods=["GET"])
def quiz():
    data = {}
    try:
        data = load_quiz()
    except Exception:
        data = {"quizzes": []}
    return render_template("quiz.html", quiz=data)


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error="Page not found"), 404


@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    app.run(debug=True)

