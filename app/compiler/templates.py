"""Deterministic hunting tasks per vector. They exist so that a pack never depends on the LLM:
if the model is disabled, out of budget, or poisoned, these still ship."""

from __future__ import annotations

from typing import Any

import yaml

from app.compiler.translate import translate
from app.schemas.enums import AttackVector, ScopePlaceholder, TargetScope
from app.schemas.hunting_pack import HuntingTask

MAX_IOCS_PER_TASK = 200
EDGE_PORTS = [445, 3389, 5985, 5986, 389, 636]

MITRE_DEFAULTS: dict[AttackVector, list[str]] = {
    AttackVector.IDENTITY_AITM_INFOSTEALER: ["T1557", "T1539", "T1528"],
    AttackVector.EDGE_DEVICE_EXPLOIT: ["T1190", "T1021"],
    AttackVector.CLICKFIX_FILELESS: ["T1204.004", "T1059.001"],
    AttackVector.LOTS_RMM_TUNNEL: ["T1219", "T1572"],
    AttackVector.BYOVD_DLL_SIDELOAD: ["T1068", "T1574.002"],
    AttackVector.SUPPLY_CHAIN_SEO: ["T1195.002", "T1608.006"],
}


def _rule(title: str, logsource: dict[str, str], detection: dict[str, Any], tags: list[str]) -> str:
    doc = {"title": title, "status": "stable", "author": "OutSight HuntCompiler (template)",
           "logsource": logsource, "detection": detection, "level": "high", "tags": tags}  # fmt: skip
    return yaml.safe_dump(doc, sort_keys=False)


def _task(task_id: str, description: str, sigma_yaml: str, lookback: int, telemetry: list[str],
          scope: TargetScope = TargetScope.ALL_ENDPOINTS, kql: str | None = None,
          placeholders: list[ScopePlaceholder] | None = None) -> HuntingTask:  # fmt: skip
    result = translate(sigma_yaml, kql_override=kql)
    if result.queries is None:
        raise RuntimeError(f"template {task_id} failed to compile: {result.issues}")
    return HuntingTask(task_id=task_id, description=description, lookback_days=lookback, sigma_yaml=sigma_yaml,
                       compiled_queries=result.queries, target_scope=scope, required_telemetry=telemetry,
                       scope_placeholders=placeholders or [])  # fmt: skip


def ioc_sighting_tasks(domains: list[str], ips: list[str], lookback: int) -> list[HuntingTask]:
    domains, ips = sorted(set(domains))[:MAX_IOCS_PER_TASK], sorted(set(ips))[:MAX_IOCS_PER_TASK]
    tasks = []
    if domains:
        det = {"sel_exact": {"QueryName": domains}, "sel_sub": {"QueryName|endswith": ["." + d for d in domains]},
               "condition": "sel_exact or sel_sub"}  # fmt: skip
        tasks.append(_task("ioc-dns-sighting", "DNS resolution of cluster domains (Sysmon 22).",
                           _rule("Cluster domain resolved", {"product": "windows", "category": "dns_query"}, det,
                                 ["attack.command-and-control"]), lookback, ["sysmon:22"]))  # fmt: skip
    if ips or domains:
        det = {}
        if ips:
            det["sel_ip"] = {"DestinationIp": ips}
        if domains:  # the host itself or a subdomain: a bare suffix would let "evil.com" match "notevil.com"
            det["sel_host"] = {"DestinationHostname": domains}
            det["sel_host_sub"] = {"DestinationHostname|endswith": ["." + d for d in domains]}
        det["condition"] = " or ".join(k for k in det)
        tasks.append(_task("ioc-net-sighting", "Network connections to cluster infrastructure (Sysmon 3).",
                           _rule("Connection to cluster infrastructure",
                                 {"product": "windows", "category": "network_connection"}, det,
                                 ["attack.command-and-control"]), lookback, ["sysmon:3"]))  # fmt: skip
    return tasks


_RUNMRU = {
    "sel_key": {"TargetObject|contains": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"},
    "sel_lolbin": {"Details|contains": ["mshta", "powershell", "pwsh", "cmd /c", "curl"]},
    "sel_payload": {"Details|contains": ["http", " -enc", " -e ", "iwr", "irm", "iex", "frombase64string"]},
    "condition": "sel_key and sel_lolbin and sel_payload",
}
_EXPLORER_SCRIPT_HOST = {
    "sel_parent": {"ParentImage|endswith": "\\explorer.exe"},
    "sel_child": {
        "Image|endswith": ["\\mshta.exe", "\\powershell.exe", "\\pwsh.exe", "\\cscript.exe", "\\wscript.exe"]
    },
    "sel_cli": {"CommandLine|contains": ["http", " -enc", "iwr", "irm", "iex", "frombase64string"]},
    "condition": "sel_parent and sel_child and sel_cli",
}


def clickfix_tasks(lookback: int) -> list[HuntingTask]:
    tags = ["attack.execution", "attack.t1204.004"]
    return [
        _task("v3-runmru-paste", "RunMRU value with a LOLBin plus a download/decode token (Sysmon 13).",
              _rule("ClickFix command pasted into Run dialog", {"product": "windows", "category": "registry_set"},
                    _RUNMRU, tags), lookback, ["sysmon:13"]),
        _task("v3-explorer-script-host", "explorer.exe spawning a script host with a download cradle (Sysmon 1).",
              _rule("Script host spawned by Explorer with cradle",
                    {"product": "windows", "category": "process_creation"}, _EXPLORER_SCRIPT_HOST, tags),
              lookback, ["sysmon:1"]),
    ]  # fmt: skip


def edge_lateral_movement_tasks(lookback: int) -> list[HuntingTask]:
    ph = "${HC_" + ScopePlaceholder.EDGE_DEVICE_INTERNAL_IPS.value + "}"
    logon = {"sel": {"EventID": 4624, "LogonType": 3, "IpAddress": ph}, "condition": "sel"}
    inbound = {"sel": {"SourceIp": ph, "DestinationPort": EDGE_PORTS, "Initiated": "false"}, "condition": "sel"}
    tags = ["attack.lateral-movement", "attack.t1021"]
    return [
        _task("v2-edge-network-logon", "Network logons (4624 type 3) originating from the edge appliance's inside IP.",
              _rule("Network logon from edge appliance", {"product": "windows", "service": "security"}, logon, tags),
              lookback, ["windows_security:4624"], TargetScope.EDGE_ADJACENT_SERVERS,
              kql=f'DeviceLogonEvents\n| where LogonType == "Network" and RemoteIP in ({ph})',
              placeholders=[ScopePlaceholder.EDGE_DEVICE_INTERNAL_IPS]),
        _task("v2-edge-inbound-admin-ports", "SMB/RDP/WinRM/LDAP connections accepted from the edge appliance.",
              _rule("Admin-port connection from edge appliance",
                    {"product": "windows", "category": "network_connection"}, inbound, tags),
              lookback, ["sysmon:3"], TargetScope.EDGE_ADJACENT_SERVERS,
              kql=("DeviceNetworkEvents\n| where ActionType == \"InboundConnectionAccepted\" and RemoteIP in "
                   f"({ph}) and LocalPort in ({', '.join(map(str, EDGE_PORTS))})"),
              placeholders=[ScopePlaceholder.EDGE_DEVICE_INTERNAL_IPS]),
    ]  # fmt: skip


def baseline_tasks(vector: AttackVector, observables: dict, lookback: int,
                   ref: dict[str, list[dict]] | None = None) -> list[HuntingTask]:  # fmt: skip
    """Tasks shared by every tenant receiving this cluster."""
    ref = ref or {}
    domains = observables.get("domains_block", []) + observables.get("domains_hunt", [])
    ips = observables.get("ips_block", []) + observables.get("ips_hunt", [])
    tasks = safe(ioc_sighting_tasks, domains, ips, lookback) + safe(
        hash_sighting_tasks, observables.get("hashes", []), lookback
    )
    if vector is AttackVector.CLICKFIX_FILELESS:
        tasks += safe(clickfix_tasks, lookback)
    elif vector is AttackVector.EDGE_DEVICE_EXPLOIT:
        tasks += safe(edge_lateral_movement_tasks, lookback)
    elif vector is AttackVector.LOTS_RMM_TUNNEL:
        tasks += safe(tunnel_and_bot_tasks, lookback)
    elif vector is AttackVector.BYOVD_DLL_SIDELOAD:
        tasks += safe(byovd_tasks, ref.get("loldrivers", []), lookback) + safe(
            sideload_tasks, ref.get("hijacklibs", []), lookback
        )
    elif vector is AttackVector.SUPPLY_CHAIN_SEO:
        tasks += safe(malicious_package_tasks, ref.get("osv_malicious", []), lookback)
    return tasks


def tenant_tasks(vector: AttackVector, observables: dict, approved_rmm: list[str], lookback: int,
                 ref: dict[str, list[dict]] | None = None) -> list[HuntingTask]:  # fmt: skip
    """Tasks that depend on one tenant's manifest (approved RMM) or its own exposure data."""
    ref = ref or {}
    if vector is AttackVector.LOTS_RMM_TUNNEL:
        return safe(rogue_rmm_tasks, ref.get("lolrmm", []), approved_rmm, lookback)
    if vector is AttackVector.IDENTITY_AITM_INFOSTEALER and observables.get("accounts"):
        return safe(credential_exposure_tasks, lookback)
    return []


# --- Phase 2b: dataset-driven and identity templates ---------------------------------------------
TUNNEL_DOMAINS = [
    "trycloudflare.com",
    "devtunnels.ms",
    "ngrok-free.app",
    "ngrok.io",
    "ngrok.app",
    "loca.lt",
    "serveo.net",
]
SCRIPT_HOSTS = ["\\powershell.exe", "\\pwsh.exe", "\\rundll32.exe", "\\python.exe", "\\pythonw.exe", "\\wscript.exe",
                "\\cscript.exe", "\\mshta.exe", "\\regsvr32.exe", "\\cmd.exe"]  # fmt: skip
USER_WRITABLE = ["\\Users\\", "\\ProgramData\\", "\\Windows\\Temp\\", "\\AppData\\"]
INSTALL_VERBS = ["pip install", "pip3 install", "npm install", "npm i ", "yarn add", "pnpm add"]
CAP_HASHES, CAP_NAMES = 150, 200


def _kql_list(values: list[str]) -> str:
    return ", ".join('"' + v.replace("\\", "\\\\").replace('"', "") + '"' for v in values)


def hash_sighting_tasks(hashes: list[str], lookback: int) -> list[HuntingTask]:
    hashes = sorted(set(hashes))[:CAP_HASHES]
    if not hashes:
        return []
    det = {"sel": {"Hashes|contains": [f"SHA256={h}" for h in hashes]}, "condition": "sel"}
    return [_task("ioc-hash-execution", "Execution of known-bad files by SHA256 (Sysmon 1 with SHA256 hashing).",
                  _rule("Known-bad file executed", {"product": "windows", "category": "process_creation"}, det,
                        ["attack.execution"]), lookback, ["sysmon:1"],
                  kql=f"DeviceProcessEvents\n| where SHA256 in~ ({_kql_list(hashes)})")]  # fmt: skip


def credential_exposure_tasks(lookback: int) -> list[HuntingTask]:
    upn = "${HC_" + ScopePlaceholder.AFFECTED_UPNS.value + "}"
    sam = "${HC_" + ScopePlaceholder.AFFECTED_SAM_ACCOUNTS.value + "}"
    det = {"sel": {"EventID": 4625, "TargetUserName": sam}, "condition": "sel"}
    kql = (
        "EntraIdSignInEvents\n| where AccountUpn in~ ("
        + upn
        + ") and ErrorCode in (50126, 50053, 50074, 50076, 500121)"
        "\n| summarize Attempts = count(), IPs = make_set(IPAddress, 20), Countries = make_set(Country, 10) by AccountUpn"
    )
    return [_task("v1-exposed-account-failed-logons",
                  "Failed logons for exposed accounts (4625 on-prem; Entra password/MFA failures) — signs the leaked "
                  "credential is being tried.",
                  _rule("Failed logon for exposed account", {"product": "windows", "service": "security"}, det,
                        ["attack.credential-access", "attack.t1078"]),
                  lookback, ["windows_security:4625", "entra_signin"], TargetScope.IDENTITY_PLANE, kql=kql,
                  placeholders=[ScopePlaceholder.AFFECTED_UPNS, ScopePlaceholder.AFFECTED_SAM_ACCOUNTS])]  # fmt: skip


def tunnel_and_bot_tasks(lookback: int) -> list[HuntingTask]:
    tunnels = {"sel": {"QueryName|endswith": TUNNEL_DOMAINS}, "condition": "sel"}
    bots = {
        "sel_img": {"Image|endswith": SCRIPT_HOSTS},
        "sel_dst": {"QueryName": ["api.telegram.org", "discord.com", "discordapp.com"]},
        "condition": "sel_img and sel_dst",
    }
    names = _kql_list([s.lstrip("\\") for s in SCRIPT_HOSTS])
    return [
        _task("v4-tunnel-dns", "DNS lookups of ad-hoc tunnel services (Cloudflare quick tunnels, Dev Tunnels, ngrok...).",
              _rule("Shadow tunnel service resolved", {"product": "windows", "category": "dns_query"}, tunnels,
                    ["attack.command-and-control", "attack.t1572"]), lookback, ["sysmon:22"],
              kql=f"DeviceNetworkEvents\n| where RemoteUrl has_any ({_kql_list(TUNNEL_DOMAINS)})"),
        _task("v4-script-host-bot-api", "Script hosts/LOLBins resolving Telegram or Discord APIs (exfiltration / C2).",
              _rule("Script host contacting bot API", {"product": "windows", "category": "dns_query"}, bots,
                    ["attack.exfiltration", "attack.t1567"]), lookback, ["sysmon:22"],
              kql=("DeviceNetworkEvents\n| where RemoteUrl has_any (\"api.telegram.org\", \"discord.com\") and "
                   f"InitiatingProcessFileName in~ ({names})")),
    ]  # fmt: skip


def rogue_rmm_tasks(lolrmm: list[dict], approved: list[str], lookback: int) -> list[HuntingTask]:
    approved_l = [a.lower() for a in approved]
    keep = [
        t for t in lolrmm if not any(a in t["name"].lower() or any(a in f for f in t["filenames"]) for a in approved_l)
    ]
    files = sorted({f for t in keep for f in t["filenames"]})[:250]
    domains = sorted({d for t in keep for d in t["domains"]})[:250]
    tasks = []
    if files:
        det = {"sel": {"Image|endswith": ["\\" + f for f in files]}, "condition": "sel"}
        tasks.append(_task("v4-unapproved-rmm-process", f"Execution of RMM tools not approved for this tenant ({len(files)} binaries).",
                           _rule("Unapproved RMM tool executed", {"product": "windows", "category": "process_creation"},
                                 det, ["attack.command-and-control", "attack.t1219"]), lookback, ["sysmon:1"],
                           kql=(f"DeviceProcessEvents\n| where FileName in~ ({_kql_list(files)}) or "
                                f"ProcessVersionInfoOriginalFileName in~ ({_kql_list(files)})")))  # fmt: skip
    if domains:
        det = {"sel": {"QueryName|endswith": domains}, "condition": "sel"}
        tasks.append(_task("v4-unapproved-rmm-dns", "DNS lookups of unapproved RMM infrastructure.",
                           _rule("Unapproved RMM domain resolved", {"product": "windows", "category": "dns_query"}, det,
                                 ["attack.command-and-control", "attack.t1219"]), lookback, ["sysmon:22"],
                           kql=f"DeviceNetworkEvents\n| where RemoteUrl has_any ({_kql_list(domains)})"))  # fmt: skip
    return tasks


def byovd_tasks(loldrivers: list[dict], lookback: int) -> list[HuntingTask]:
    hashes = [h for d in loldrivers for h in d["sha256"]][:CAP_HASHES]  # newest entries first
    known = {"sel": {"Hashes|contains": [f"SHA256={h}" for h in hashes]}, "condition": "sel"}
    odd = {
        "sel": {"Signed": "false"},
        "filter": {"ImageLoaded|startswith": "C:\\Windows\\System32\\drivers\\"},
        "condition": "sel and not filter",
    }
    svc = {
        "sel": {"EventID": 7045, "ImagePath|endswith": ".sys"},
        "filter": {"ImagePath|contains": "\\System32\\drivers\\"},
        "condition": "sel and not filter",
    }
    tags = ["attack.privilege-escalation", "attack.t1068"]
    return [
        _task("v5-loldrivers-hash-load", f"Load of a LOLDrivers vulnerable/malicious driver ({len(hashes)} newest hashes).",
              _rule("Known vulnerable driver loaded", {"product": "windows", "category": "driver_load"}, known, tags),
              lookback, ["sysmon:6"],
              kql=f"DeviceEvents\n| where ActionType == \"DriverLoad\" and SHA256 in~ ({_kql_list(hashes)})"),
        _task("v5-unsigned-driver-outside-drivers-dir", "Unsigned driver loaded from outside System32\\drivers.",
              _rule("Unsigned driver from unusual path", {"product": "windows", "category": "driver_load"}, odd, tags),
              lookback, ["sysmon:6"]),
        _task("v5-kernel-service-unusual-path", "Kernel driver service installed (7045) from outside System32\\drivers.",
              _rule("Driver service from unusual path", {"product": "windows", "service": "system"}, svc, tags),
              lookback, ["windows_system:7045"]),
    ]  # fmt: skip


def sideload_tasks(hijacklibs: list[dict], lookback: int) -> list[HuntingTask]:
    dlls = [r["dll"] for r in hijacklibs][:CAP_NAMES]
    if not dlls:
        return []
    det = {
        "sel_dll": {"ImageLoaded|endswith": ["\\" + d for d in dlls]},
        "sel_path": {"ImageLoaded|contains": USER_WRITABLE},
        "sel_unsigned": {"Signed": "false"},
        "condition": "sel_dll and sel_path and sel_unsigned",
    }
    return [_task("v5-hijacklibs-sideload", "Unsigned copy of a known side-loadable DLL (HijackLibs) loaded from a "
                  "user-writable folder. Same-folder-as-signed-EXE correlation is left to triage.",
                  _rule("DLL side-loading from user-writable path", {"product": "windows", "category": "image_load"}, det,
                        ["attack.defense-evasion", "attack.t1574.002"]), lookback, ["sysmon:7"],
                  kql=(f"DeviceImageLoadEvents\n| where FileName in~ ({_kql_list(dlls)}) and FolderPath has_any "
                       f"({_kql_list([p.strip(chr(92)) for p in USER_WRITABLE])})"))]  # fmt: skip


def malicious_package_tasks(osv: list[dict], lookback: int) -> list[HuntingTask]:
    names = sorted({r["package"] for r in osv if len(r["package"]) >= 5})[:CAP_NAMES]
    if not names:
        return []
    det = {
        "sel_verb": {"CommandLine|contains": INSTALL_VERBS},
        "sel_pkg": {"CommandLine|contains": [" " + n for n in names]},
        "condition": "sel_verb and sel_pkg",
    }
    return [_task("v6-malicious-package-install", f"Install of packages flagged malicious by OSV ({len(names)} recent).",
                  _rule("Known malicious package installed", {"product": "windows", "category": "process_creation"}, det,
                        ["attack.initial-access", "attack.t1195.002"]), lookback, ["sysmon:1"],
                  TargetScope.DEVELOPER_WORKSTATIONS,
                  kql=(f"DeviceProcessEvents\n| where ProcessCommandLine has_any ({_kql_list(INSTALL_VERBS)}) and "
                       f"ProcessCommandLine has_any ({_kql_list(names)})"))]  # fmt: skip


def safe(builder, *args) -> list[HuntingTask]:
    """A template that fails to compile or exceeds contract limits is skipped, never fatal."""
    import logging

    try:
        return builder(*args)
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).exception("template %s skipped", getattr(builder, "__name__", builder))
        return []
