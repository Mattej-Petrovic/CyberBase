import json
import re
import time
from pathlib import Path

from deep_translator import GoogleTranslator

SRC = Path("data/quiz.json")
DST = Path("data/quiz_sv.json")
CACHE = Path("scripts/quiz_sv_translate_cache_v2.json")

SKIP_KEYS = {"id", "type", "_version"}
SKIP_VALUES = {"mcq", "scenario"}

TOPIC_OVERRIDES = {
    "Network Basics": "Nätverksgrunder",
    "Ports": "Portar",
    "Frameworks and Standards": "Ramverk och standarder",
    "Principles and Identity": "Principer och identitet",
    "Command Reference Basics": "Grunder i kommandoreferens",
    "Detection and Logging": "Detektering och loggning",
    "Hardening": "Härdning",
    "Web App Security": "Webbapplikationssäkerhet",
    "Cloud Security Fundamentals": "Grunder i molnsäkerhet",
    "Incident Response Scenarios": "Scenarier för incidenthantering",
    "SOC Analyst Triage": "SOC-analytikertriage",
    "Malware and Endpoint Defense": "Skadlig kod och endpointförsvar",
    "Vulnerability Management": "Sårbarhetshantering",
}

POST_REPLACEMENTS = {
    "Hårdning": "Härdning",
    "hårdning": "härdning",
    "Ansökan": "Applikation",
    "ansökan": "applikation",
    "slutpunkt": "endpoint",
    "Slutpunkt": "Endpoint",
    "slutpunkter": "endpoints",
    "med största sannolikhet": "troligen",
}

PRESERVE_TERMS = sorted(
    {
        "curl",
        "dig",
        "ping",
        "traceroute",
        "nmap",
        "tcpdump",
        "wireshark",
        "Wireshark",
        "Burp Suite",
        "OWASP ZAP",
        "Suricata",
        "Zeek",
        "Sysmon",
        "PowerShell",
        "WebAuthn",
        "Kibana",
        "Splunk",
        "Sigma",
        "YARA",
        "OpenSSL",
        "JWT",
        "CSP",
        "SOC",
        "SIEM",
        "EDR",
        "TCP",
        "UDP",
        "TLS",
        "HTTP",
        "HTTPS",
        "DNS",
        "NTP",
        "ICMP",
        "ARP",
        "BGP",
        "DHCP",
        "SNMP",
        "SSH",
        "RDP",
        "SMB",
        "LDAP",
        "LDAPS",
        "Kerberos",
        "OAuth",
        "SAML",
        "MFA",
        "NIST",
        "ISO",
        "CIS Controls",
        "MITRE ATT&CK",
        "CVE",
        "CVSS",
        "SBOM",
        "APIPA",
        "IPsec",
        "IKE",
        "VLAN",
        "MTU",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
        "PTR",
        "SRV",
        "IPv4",
        "IPv6",
        "OSI",
        "MAC",
        "CPU",
        "URL",
        "API",
        "VPN",
        "PKI",
        "AES",
        "RSA",
        "HMAC",
        "TOTP",
        "FIDO2",
    },
    key=len,
    reverse=True,
)

PRESERVE_PATTERNS = [
    re.compile(r"\b\d{1,5}/(?:TCP|UDP)\b"),
    re.compile(r"\b(?:[A-Z]{2,}(?:/[A-Z]{2,})?)\b"),
    re.compile(r"\b(?:src_ip|dst_ip|source_ip|dest_ip)\b"),
    re.compile(r"\B-[A-Za-z0-9]+\b"),
    re.compile(r"`[^`]+`"),
]


def should_skip(path: tuple, value: str) -> bool:
    if value in SKIP_VALUES:
        return True
    if path and isinstance(path[-1], str) and path[-1] in SKIP_KEYS:
        return True
    return False


def protect_terms(text: str) -> tuple[str, dict[str, str]]:
    keep: dict[str, str] = {}
    idx = 0
    out = text

    def put_token(raw: str) -> str:
        nonlocal idx
        token = f"__TERM_{idx}__"
        idx += 1
        keep[token] = raw
        return token

    for term in PRESERVE_TERMS:
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])")
        out = pattern.sub(lambda m: put_token(m.group(0)), out)

    for pat in PRESERVE_PATTERNS:
        while True:
            m = pat.search(out)
            if not m:
                break
            token = put_token(m.group(0))
            out = out[: m.start()] + token + out[m.end() :]

    return out, keep


def unprotect_terms(text: str, keep: dict[str, str]) -> str:
    out = text
    for token, raw in keep.items():
        out = out.replace(token, raw)
    return out


def polish_sv(text: str) -> str:
    out = text
    for src, dst in POST_REPLACEMENTS.items():
        out = out.replace(src, dst)

    out = out.replace("Auktoritativ namnserver", "Auktoritativ DNS-server")
    out = out.replace("loggar för åtkomst till webbservern", "webbserverns åtkomstloggar")
    out = re.sub(r"\s+([,.:;!?])", r"\1", out)
    out = re.sub(r"\s{2,}", " ", out).strip()
    return out


def collect_strings(node, path=(), out=None):
    if out is None:
        out = []
    if isinstance(node, dict):
        for k, v in node.items():
            collect_strings(v, path + (k,), out)
        return out
    if isinstance(node, list):
        for i, v in enumerate(node):
            collect_strings(v, path + (i,), out)
        return out
    if isinstance(node, str):
        out.append((path, node))
    return out


def translate_masked(strings: list[str], existing: dict[str, str]) -> dict[str, str]:
    translated: dict[str, str] = dict(existing)
    if not strings:
        return translated

    translator = GoogleTranslator(source="en", target="sv")
    chunk_size = 40
    total = len(strings)
    for i in range(0, total, chunk_size):
        chunk = strings[i : i + chunk_size]
        translated_chunk = None
        for attempt in range(1, 5):
            try:
                translated_chunk = translator.translate_batch(chunk)
                break
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(1.5 * attempt)

        for src, dst in zip(chunk, translated_chunk or []):
            translated[src] = dst
        CACHE.write_text(json.dumps(translated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"translated {min(i + chunk_size, total)}/{total}")
    return translated


def main():
    data = json.loads(SRC.read_text(encoding="utf-8"))
    collected = collect_strings(data)

    unique: list[str] = []
    seen = set()
    for path, value in collected:
        if value in seen:
            continue
        seen.add(value)
        if should_skip(path, value):
            continue
        if value in TOPIC_OVERRIDES:
            continue
        unique.append(value)

    masked_map: dict[str, str] = {}
    keep_map: dict[str, dict[str, str]] = {}
    masked_unique: list[str] = []
    masked_seen = set()
    for s in unique:
        masked, keep = protect_terms(s)
        masked_map[s] = masked
        keep_map[s] = keep
        if masked not in masked_seen:
            masked_seen.add(masked)
            masked_unique.append(masked)

    cache: dict[str, str] = {}
    if CACHE.exists():
        try:
            cache = json.loads(CACHE.read_text(encoding="utf-8"))
        except Exception:
            cache = {}

    remaining = [s for s in masked_unique if s not in cache]
    print("unique source strings:", len(unique))
    print("unique masked strings:", len(masked_unique))
    print("cached:", len(cache), "remaining:", len(remaining))

    translated_masked = translate_masked(remaining, cache) if remaining else cache

    translated_map: dict[str, str] = {}
    for s in unique:
        masked = masked_map[s]
        t = translated_masked.get(masked, masked)
        t = unprotect_terms(t, keep_map[s])
        t = polish_sv(t)
        translated_map[s] = t

    def transform(node, path=()):
        if isinstance(node, dict):
            return {k: transform(v, path + (k,)) for k, v in node.items()}
        if isinstance(node, list):
            return [transform(v, path + (i,)) for i, v in enumerate(node)]
        if isinstance(node, str):
            if should_skip(path, node):
                return node
            if node in TOPIC_OVERRIDES:
                return TOPIC_OVERRIDES[node]
            return translated_map.get(node, node)
        return node

    sv = transform(data)
    sv["_version_note"] = (
        "v2 utökar varje ämne till en frågebank med 30 frågor och stödjer "
        "slumpmässigt urval av 10 frågor per omgång."
    )
    DST.write_text(json.dumps(sv, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("wrote", DST)


if __name__ == "__main__":
    main()
