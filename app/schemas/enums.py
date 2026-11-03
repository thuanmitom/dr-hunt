"""Enumerations shared by the Pydantic data contracts and the SQLAlchemy models.

Values are part of the wire contract — append new members, never rename existing ones.
"""

from __future__ import annotations

from enum import StrEnum


class AttackVector(StrEnum):
    IDENTITY_AITM_INFOSTEALER = "identity_aitm_infostealer"  # V1: AiTM / device-code / OAuth / stealer logs
    EDGE_DEVICE_EXPLOIT = "edge_device_exploit"  # V2: 0/N-day on VPN, firewall, web edge
    CLICKFIX_FILELESS = "clickfix_fileless"  # V3: fake CAPTCHA, Win+R clipboard hijack
    LOTS_RMM_TUNNEL = "lots_rmm_tunnel"  # V4: trusted-site abuse, rogue RMM, tunnels
    BYOVD_DLL_SIDELOAD = "byovd_dll_sideload"  # V5: vulnerable drivers, DLL side-loading
    SUPPLY_CHAIN_SEO = "supply_chain_seo"  # V6: malicious packages, fake PoCs, SEO/ads


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntelSource(StrEnum):
    CERTSTREAM = "certstream"
    URLSCAN = "urlscan"
    TELEGRAM_CTI = "telegram_cti"
    LEAK_API = "leak_api"
    GITHUB = "github"
    NUCLEI_TEMPLATES = "nuclei_templates"
    CISA_KEV = "cisa_kev"
    EPSS = "epss"
    OSV = "osv"
    LOLRMM = "lolrmm"
    LOLDRIVERS = "loldrivers"
    HIJACKLIBS = "hijacklibs"
    MALWAREBAZAAR = "malwarebazaar"
    SHODAN = "shodan"
    RSS = "rss"
    MANUAL = "manual"


class EventStatus(StrEnum):
    NEW = "new"
    PROCESSING = "processing"
    CLUSTERED = "clustered"
    DISCARDED = "discarded"  # whitelisted, out of scope, duplicate signal
    FAILED = "failed"


class ClusterStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"  # confidence decayed below floor / TTL passed
    SUPPRESSED = "suppressed"  # analyst-marked false positive
    MERGED = "merged"  # folded into another cluster (see merged_into_id)


class DeliveryMode(StrEnum):
    PUSH = "push"  # HuntCompiler POSTs to the tenant webhook (requires inbound exposure)
    PULL = "pull"  # tenant SOAR polls GET /api/v1/packs (outbound-only from the LAN)


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    RETRYING = "retrying"
    DELIVERED = "delivered"
    DEAD_LETTER = "dead_letter"
    AWAITING_PULL = "awaiting_pull"
    PULLED = "pulled"
    SKIPPED = "skipped"  # below tenant threshold, vector disabled, or expired before delivery


class TargetScope(StrEnum):
    """Logical host scope. The SOAR resolves it to its own agent groups — HuntCompiler never
    learns internal hostnames or group names (Zero-Internal-Access)."""

    ALL_ENDPOINTS = "all_endpoints"
    WINDOWS_SERVERS = "windows_servers"
    DEVELOPER_WORKSTATIONS = "developer_workstations"
    SYSADMIN_WORKSTATIONS = "sysadmin_workstations"
    EDGE_ADJACENT_SERVERS = "edge_adjacent_servers"
    IDENTITY_PLANE = "identity_plane"  # sign-in / audit logs, not endpoints


class ScopePlaceholder(StrEnum):
    """Tokens a compiled query may contain as ``${HC_<NAME>}``; substituted by the SOAR
    with values that only exist inside the tenant (e.g. internal IPs of the VPN appliance)."""

    EDGE_DEVICE_INTERNAL_IPS = "EDGE_DEVICE_INTERNAL_IPS"
    DMZ_HOST_IPS = "DMZ_HOST_IPS"
    AFFECTED_UPNS = "AFFECTED_UPNS"  # resolved by the SOAR from affected_accounts[].ref
    AFFECTED_SAM_ACCOUNTS = "AFFECTED_SAM_ACCOUNTS"


class DigestStatus(StrEnum):
    """Telegram digest attempt (not part of the wire contract)."""

    SENDING = "sending"
    SENT = "sent"  # only sent rows define the next window
    FAILED = "failed"
    PREVIEW = "preview"  # /digest: never moves the cursor
