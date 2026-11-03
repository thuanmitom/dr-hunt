"""Sigma taxonomy subset the compiler supports, and its Wazuh index mapping."""

from __future__ import annotations

# Sysmon-backed Sigma categories -> Sysmon EventID (also used by the harness to build sample docs).
SYSMON_CATEGORY_EVENT_ID: dict[str, int] = {
    "process_creation": 1,
    "network_connection": 3,
    "driver_load": 6,
    "image_load": 7,
    "file_event": 11,
    "registry_set": 13,
    "dns_query": 22,
}
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Fields an LLM draft may use, per category. Anything else is rejected before rendering.
ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "process_creation": frozenset(
        {"Image", "ParentImage", "CommandLine", "ParentCommandLine", "OriginalFileName", "IntegrityLevel", "User"}
    ),
    "network_connection": frozenset({"Image", "DestinationHostname", "DestinationIp", "DestinationPort", "Initiated"}),
    "driver_load": frozenset({"ImageLoaded", "Hashes", "Signed", "SignatureStatus"}),
    "image_load": frozenset({"Image", "ImageLoaded", "Signed", "SignatureStatus", "OriginalFileName"}),
    "file_event": frozenset({"Image", "TargetFilename"}),
    "registry_set": frozenset({"Image", "TargetObject", "Details"}),
    "dns_query": frozenset({"Image", "QueryName"}),
}


def wazuh_field(sigma_field: str) -> str:
    """Wazuh's eventchannel decoder: System.EventID -> data.win.system.eventID,
    EventData.CommandLine -> data.win.eventdata.commandLine (first letter lower-cased)."""
    if sigma_field == "EventID":
        return "data.win.system.eventID"
    if sigma_field == "Channel":
        return "data.win.system.channel"
    if sigma_field.startswith("data."):
        return sigma_field
    return "data.win.eventdata." + sigma_field[:1].lower() + sigma_field[1:]
