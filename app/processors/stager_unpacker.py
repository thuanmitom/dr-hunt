"""Static, recursive de-obfuscation of ClickFix / PowerShell / mshta stagers.

Nothing is ever executed. Each round normalises the text (string concatenation, backtick and
caret escapes, char-code arrays, reversed strings) and decodes embedded layers (-EncodedCommand,
FromBase64String, atob, gzip/deflate, single-byte XOR, hex). IOCs are collected from every layer,
because droppers often carry the C2 only in an intermediate layer.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
import zlib
from dataclasses import dataclass, field

import tldextract

MAX_DEPTH = 8
MAX_TEXT_BYTES = 1_000_000
MAX_DECOMPRESSED = 2_000_000
PREVIEW = 240

_PSL = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)

# --- normalisation patterns ----------------------------------------------------------------
_CONCAT = re.compile(r"""(['"])((?:(?!\1).)*)\1\s*\+\s*(['"])((?:(?!\3).)*)\3""")
_BACKTICK = re.compile(r"`(?=[A-Za-z0-9\-])")
_CARET = re.compile(r"\^(?=[A-Za-z0-9/\\:\-.])")
_PS_CHAR = re.compile(r"\[char\]\s*(0x[0-9a-fA-F]+|\d{1,6})", re.I)
_CHAR_ARRAY = re.compile(
    r"(?:\[char\[\]\]\s*\(|String\.fromCharCode\s*\()\s*((?:(?:0x[0-9a-fA-F]+|\d{1,6})\s*,\s*){3,}(?:0x[0-9a-fA-F]+|\d{1,6}))\s*\)",
    re.I,
)
_QUOTED = re.compile(r"""(['"])([^'"\n]{8,})\1""")

# --- decoding patterns -----------------------------------------------------------------------
_B64 = r"[A-Za-z0-9+/]{16,}={0,2}"
_PS_ENC = re.compile(rf"\s-(?:e|ec|en|enc|enco|encodedcommand)\s+['\"]?({_B64})", re.I)
_FROM_B64 = re.compile(rf"(?:FromBase64String|atob)\s*\(\s*['\"]({_B64})['\"]\s*\)", re.I)
_BARE_B64 = re.compile(rf"(?<![A-Za-z0-9+/])({_B64})(?![A-Za-z0-9+/=])")
_XOR_KEY = re.compile(r"-bxor\s*(0x[0-9a-fA-F]{1,2}|\d{1,3})", re.I)
_HEX_BLOB = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){24,})(?![0-9a-fA-F])")

# --- IOC patterns ------------------------------------------------------------------------------
_URL = re.compile(r"\b(?:h[xt]{2}ps?|ftp)\[?:\]?//[^\s'\"`<>()\[\]{}|\\^]+", re.I)
_DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]))+[a-z][a-z0-9-]{1,62})\b", re.I)
_IPV4 = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")
# TLDs that collide with file extensions — only trusted when seen inside a URL.
_AMBIGUOUS_TLDS = frozenset({"zip", "mov", "sh", "py", "pl", "ps", "md", "rs", "cs", "so", "exe", "dll", "bat", "js"})
# .NET namespaces that look like hostnames ("System.Net", "System.IO").
_NAMESPACE_NOISE = frozenset({"system.net", "system.io", "system.text", "system.web", "microsoft.win32"})


@dataclass(frozen=True, slots=True)
class Layer:
    depth: int
    technique: str
    sha256: str
    preview: str


@dataclass
class UnpackResult:
    layers: list[Layer] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def final_text_preview(self) -> str:
        return self.layers[-1].preview if self.layers else ""


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return ok / len(text)


def _bytes_to_text(data: bytes) -> str | None:
    """Pick UTF-16LE (PowerShell) or UTF-8 / Latin-1, whichever yields readable script text."""
    candidates = []
    if len(data) >= 4 and data[1:2] == b"\x00" and data[3:4] == b"\x00":
        candidates.append(data.decode("utf-16-le", errors="ignore"))
    candidates.append(data.decode("utf-8", errors="ignore"))
    for text in candidates:
        if len(text) >= 4 and _printable_ratio(text) >= 0.9:
            return text
    return None


def _decompress(data: bytes) -> bytes | None:
    for wbits in (31, 15, -15):  # gzip, zlib, raw deflate
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(data, MAX_DECOMPRESSED)
            if out and (d.eof or len(out) >= MAX_DECOMPRESSED):
                return out
        except zlib.error:
            continue
    return None


def _b64decode(blob: str) -> bytes | None:
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _bytes_layers(data: bytes, xor_keys: list[int]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if (inflated := _decompress(data)) is not None and (text := _bytes_to_text(inflated)):
        found.append(("gzip/deflate", text))
    if text := _bytes_to_text(data):
        found.append(("base64", text))
    # XOR with a key declared in the script is always tried: XOR-ed ASCII often stays printable,
    # so "looks like text" alone cannot tell the encoded and decoded forms apart.
    for key in xor_keys:
        if text := _bytes_to_text(bytes(b ^ key for b in data)):
            found.append((f"xor:{key:#04x}", text))
    if not found:  # bounded single-byte brute force, accepted only if it reveals a URL
        for key in range(1, 256):
            text = _bytes_to_text(bytes(b ^ key for b in data))
            if text and _URL.search(text):
                found.append((f"xor-bruteforce:{key:#04x}", text))
                break
    return found


def normalise(text: str) -> str:
    prev = None
    out = text
    for _ in range(50):  # concatenation can nest; iterate to a fixed point
        if out == prev:
            break
        prev = out
        out = _CONCAT.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), out)
    out = _BACKTICK.sub("", out)
    out = _CARET.sub("", out)
    out = _CHAR_ARRAY.sub(lambda m: "'" + "".join(chr(int(x.strip(), 0)) for x in m.group(1).split(",")) + "'", out)
    if _PS_CHAR.search(out):
        out = re.sub(
            r"(?:\[char\]\s*(?:0x[0-9a-fA-F]+|\d{1,6})\s*\+?\s*){2,}",
            lambda m: "'" + "".join(chr(int(v, 0)) for v in _PS_CHAR.findall(m.group(0))) + "'",
            out,
            flags=re.I,
        )

    def _unreverse(m: re.Match[str]) -> str:
        s = m.group(2)
        r = s[::-1]
        return m.group(1) + r + m.group(1) if re.search(r"(?:ptth|sptth|//:)", s, re.I) else m.group(0)

    return _QUOTED.sub(_unreverse, out)


def _decode_candidates(text: str) -> list[tuple[str, str]]:
    xor_keys = [int(k, 0) & 0xFF for k in _XOR_KEY.findall(text)]
    blobs: list[tuple[str, str]] = [("encodedcommand", b) for b in _PS_ENC.findall(text)]
    blobs += [("frombase64", b) for b in _FROM_B64.findall(text)]
    seen = {b for _, b in blobs}
    blobs += [("bare-base64", b) for b in _BARE_B64.findall(text) if b not in seen and len(b) >= 40]
    out: list[tuple[str, str]] = []
    for technique, blob in blobs:
        data = _b64decode(blob)
        if not data:
            continue
        for sub, decoded in _bytes_layers(data, xor_keys):
            out.append((technique if sub == "base64" else f"{technique}+{sub}", decoded))
    for hex_blob in _HEX_BLOB.findall(text):
        for sub, decoded in _bytes_layers(bytes.fromhex(hex_blob), xor_keys):
            out.append((f"hex+{sub}", decoded))
    return out


def refang(text: str) -> str:
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[:]", ":")
    return re.sub(r"\bh[x]{2}p", "http", text, flags=re.I)


def extract_iocs(text: str) -> tuple[set[str], set[str], set[str]]:
    text = refang(text)
    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    for raw in _URL.findall(text):
        url = re.sub(r"^h[xt]{2}p", "http", raw, flags=re.I).replace("[:]", ":").replace("[.]", ".")
        url = url.rstrip(".,;'\")")
        urls.add(url)
        host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0].split(":")[0].lower()
        try:
            if ipaddress.ip_address(host).is_global:
                ips.add(host)
            continue
        except ValueError:
            pass
        if _PSL(host).suffix:
            domains.add(host)
    for raw in _DOMAIN.findall(text):
        host = raw.lower().replace("[.]", ".")
        ext = _PSL(host)
        if not ext.suffix or not ext.domain:
            continue
        if host in _NAMESPACE_NOISE:
            continue
        if host.rsplit(".", 1)[-1] in _AMBIGUOUS_TLDS and host.count(".") < 2:
            continue  # "payload.zip", "exploit.py": filenames, not hosts
        domains.add(host)
    for raw in _IPV4.findall(text):
        if ipaddress.ip_address(raw).is_global:
            ips.add(raw)
    return urls, domains, ips


def unpack(text: str, *, max_depth: int = MAX_DEPTH) -> UnpackResult:
    result = UnpackResult()
    if len(text.encode("utf-8", errors="ignore")) > MAX_TEXT_BYTES:
        text = text[:MAX_TEXT_BYTES]
        result.truncated = True

    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    seen: set[str] = set()
    frontier: list[tuple[str, str]] = [("input", text)]

    for depth in range(max_depth + 1):
        next_frontier: list[tuple[str, str]] = []
        for technique, layer_text in frontier:
            norm = normalise(layer_text)
            digest = hashlib.sha256(norm.encode("utf-8", errors="ignore")).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            label = technique if norm == layer_text else f"{technique}+normalise"
            result.layers.append(Layer(depth, label, digest, norm[:PREVIEW]))
            u, d, i = extract_iocs(norm)
            urls |= u
            domains |= d
            ips |= i
            next_frontier.extend(_decode_candidates(norm))
        if not next_frontier:
            break
        if depth == max_depth:
            result.truncated = True
        frontier = next_frontier

    result.urls, result.domains, result.ips = sorted(urls), sorted(domains), sorted(ips)
    return result
