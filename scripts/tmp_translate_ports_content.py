#!/usr/bin/env python3
"""Generate Swedish Ports content for Concepts pages.

Outputs:
- data/port_details_sv.json
- updates data/concepts_sv.json -> ports[].desc
"""

from __future__ import annotations

import ast
import json
import re
import time
from pathlib import Path
from typing import Any

from deep_translator import GoogleTranslator

ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "app.py"
EN_CONCEPTS_PATH = ROOT / "data" / "concepts.json"
SV_CONCEPTS_PATH = ROOT / "data" / "concepts_sv.json"
SV_PORT_DETAILS_PATH = ROOT / "data" / "port_details_sv.json"

SKIP_KEYS = {"service", "transport", "references"}
MAX_TRANSLATE_CHUNK = 3200

PRESERVE_TOKENS = [
    "TCP",
    "UDP",
    "IP",
    "IPv4",
    "IPv6",
    "IPsec",
    "IKEv2",
    "IKE",
    "ESP",
    "GRE",
    "NAT",
    "NLA",
    "FTP",
    "FTPS",
    "SFTP",
    "SSH",
    "Telnet",
    "SMTP",
    "SMTPS",
    "STARTTLS",
    "DNS",
    "DHCP",
    "HTTP",
    "HTTPS",
    "IMAP",
    "IMAPS",
    "POP3",
    "POP3S",
    "LDAP",
    "LDAPS",
    "SMB",
    "RDP",
    "VNC",
    "NFS",
    "MySQL",
    "PostgreSQL",
    "Redis",
    "PPTP",
    "TLS",
    "MFA",
    "SYN",
    "ACK",
    "RST",
    "FIN",
    "ECN",
    "MTA",
    "MX",
    "AAAA",
    "CA",
    "SSM",
    "Git",
    "SCP",
    "DoH",
    "DoT",
]

POST_REPLACEMENTS = {
    "transportlagernummer": "transportlagernummer",
    "ephemeral": "ephemeral",
    "källport": "källport",
    "destination port": "destinationsport",
    "destinationport": "destinationsport",
    "source port": "källport",
    "källporten": "källporten",
    "förenklat": "förenklat",
    "sprängradie": "spridningsradie",
    "brute force": "brute force",
    "vulnerability": "sårbarhet",
    "Lager 2": "Layer 2",
    "lager 2": "Layer 2",
    "moln": "moln",
    "Aangripare": "Angripare",
    "A-klienten": "Klienten",
    "A serverprocessen": "En serverprocess",
    "As med andra databaser": "Precis som med andra databaser",
    "Aefter": "Efter",
    "filöverföringsstiftelse": "grund för filöverföring",
    "IP config": "IP-konfiguration",
    "brute force-referenser": "bruteforce-angrepp med läckta autentiseringsuppgifter",
    "undersökning": "skanning",
    "Exposed": "Exponerad",
    "A server": "En server",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def extract_port_details_from_app(path: Path) -> dict[int, dict[str, Any]]:
    src = path.read_text(encoding="utf-8")
    mod = ast.parse(src)
    for node in mod.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "_PORT_DETAILS":
            value = ast.literal_eval(node.value)
            out: dict[int, dict[str, Any]] = {}
            if isinstance(value, dict):
                for k, v in value.items():
                    if isinstance(k, int) and isinstance(v, dict):
                        out[k] = v
            return out
    raise RuntimeError("Could not extract _PORT_DETAILS from app.py")


def protect_tokens(text: str) -> tuple[str, dict[str, str]]:
    out = text
    mapping: dict[str, str] = {}
    for idx, token in enumerate(sorted(PRESERVE_TOKENS, key=len, reverse=True)):
        placeholder = f"__KEEP_{idx}__"
        if token in out:
            out = out.replace(token, placeholder)
            mapping[placeholder] = token
    return out, mapping


def restore_tokens(text: str, mapping: dict[str, str]) -> str:
    out = text
    for placeholder, token in mapping.items():
        out = out.replace(placeholder, token)
    return out


def split_chunks(text: str, max_len: int = MAX_TRANSLATE_CHUNK) -> list[str]:
    if len(text) <= max_len:
        return [text]
    parts = re.split(r"(?<=[.!?])\s+", text)
    chunks: list[str] = []
    cur = ""
    for part in parts:
        if not part:
            continue
        candidate = (cur + " " + part).strip() if cur else part
        if len(candidate) <= max_len:
            cur = candidate
            continue
        if cur:
            chunks.append(cur)
        if len(part) <= max_len:
            cur = part
            continue
        # Hard split fallback for extremely long segments.
        for i in range(0, len(part), max_len):
            chunks.append(part[i : i + max_len])
        cur = ""
    if cur:
        chunks.append(cur)
    return chunks


def apply_style_fixes(text: str) -> str:
    out = text
    for old, new in POST_REPLACEMENTS.items():
        out = out.replace(old, new)
    out = re.sub(r"\s+", " ", out).strip()
    return out


def translate_text(translator: GoogleTranslator, cache: dict[str, str], text: str) -> str:
    src = (text or "").strip()
    if not src:
        return text
    if src in cache:
        return cache[src]
    if src.startswith("http://") or src.startswith("https://"):
        cache[src] = src
        return src

    protected, token_map = protect_tokens(src)
    pieces = split_chunks(protected)
    translated_pieces: list[str] = []
    for piece in pieces:
        translated_piece = piece
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                translated_piece = translator.translate(piece)
                break
            except Exception as exc:  # pragma: no cover
                last_error = exc
                time.sleep(0.7 * (attempt + 1))
        if last_error and translated_piece == piece:
            print(f"WARN: keep EN chunk due translation failure: {piece[:80]}")
        translated_pieces.append(translated_piece)

    out = " ".join(translated_pieces)
    out = restore_tokens(out, token_map)
    out = apply_style_fixes(out)
    cache[src] = out
    return out


def translate_node(translator: GoogleTranslator, cache: dict[str, str], node: Any, key: str | None = None) -> Any:
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for k, v in node.items():
            if k in SKIP_KEYS:
                out[k] = v
                continue
            out[k] = translate_node(translator, cache, v, k)
        return out
    if isinstance(node, list):
        return [translate_node(translator, cache, item, key) for item in node]
    if isinstance(node, str):
        return translate_text(translator, cache, node)
    return node


def main() -> None:
    translator = GoogleTranslator(source="en", target="sv")
    cache: dict[str, str] = {}

    port_details_en = extract_port_details_from_app(APP_PATH)
    port_details_sv: dict[str, Any] = {}
    for port, details in sorted(port_details_en.items()):
        translated = translate_node(translator, cache, details)
        # Keep service labels as standard identifiers in English.
        translated["service"] = details.get("service")
        translated["transport"] = details.get("transport")
        port_details_sv[str(port)] = translated
        print(f"translated port details: {port}")

    save_json(SV_PORT_DETAILS_PATH, port_details_sv)

    concepts_en = load_json(EN_CONCEPTS_PATH)
    concepts_sv = load_json(SV_CONCEPTS_PATH)
    en_ports = concepts_en.get("ports") or []
    sv_ports = concepts_sv.get("ports") or []
    sv_by_port = {int(p.get("port")): p for p in sv_ports if isinstance(p, dict) and p.get("port") is not None}

    for en_item in en_ports:
        if not isinstance(en_item, dict):
            continue
        port = int(en_item.get("port"))
        sv_item = sv_by_port.get(port)
        if not sv_item:
            continue
        en_desc = str(en_item.get("desc") or "")
        sv_item["desc"] = translate_text(translator, cache, en_desc)
        # Keep standard service name identifiers unchanged.
        sv_item["name"] = en_item.get("name")
        print(f"translated concepts ports desc: {port}")

    save_json(SV_CONCEPTS_PATH, concepts_sv)
    print(f"done. unique translated strings: {len(cache)}")


if __name__ == "__main__":
    main()
