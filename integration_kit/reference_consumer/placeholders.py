"""Substitute ``${HC_<NAME>}`` placeholders with values that exist only inside your network (DECISIONS.md D-07).

* Wazuh DSL (from the pack): an array element equal to the placeholder is replaced by the list of values.
* Sigma (before converting it for Elastic or Splunk): a field value equal to the placeholder, alone or inside a list,
  is replaced by the list of values, so the backend emits its own ``IN (...)`` / OR.
A placeholder anywhere else is refused rather than guessed.
"""

from __future__ import annotations

import copy
import re
from typing import Any

import yaml

_WHOLE = re.compile(r"^\$\{HC_([A-Z0-9_]+)\}$")
_ANY = re.compile(r"\$\{HC_[A-Z0-9_]+\}")


class MissingValue(KeyError):
    """A placeholder has no configured value: the task cannot be evaluated."""


class UnsupportedPlaceholder(ValueError):
    """A placeholder in a position this consumer does not substitute."""


def _values(name: str, values: dict[str, list[str]]) -> list[str]:
    found = [str(v) for v in values.get(name) or [] if str(v)]
    if not found:
        raise MissingValue(name)
    return found


def _expand_list(items: list[Any], values: dict[str, list[str]]) -> list[Any]:
    out: list[Any] = []
    for item in items:
        m = _WHOLE.match(item) if isinstance(item, str) else None
        out.extend(_values(m.group(1), values) if m else [substitute_dsl(item, values)])
    return out


def substitute_dsl(node: Any, values: dict[str, list[str]]) -> Any:
    if isinstance(node, dict):
        return {k: substitute_dsl(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return _expand_list(node, values)
    if isinstance(node, str) and _ANY.search(node):
        raise UnsupportedPlaceholder(f"placeholder outside an array in DSL: {node[:80]!r}")
    return node


def _substitute_detection_value(value: Any, values: dict[str, list[str]]) -> Any:
    if isinstance(value, str):
        if m := _WHOLE.match(value):
            found = _values(m.group(1), values)
            return found if len(found) > 1 else found[0]
        if _ANY.search(value):
            raise UnsupportedPlaceholder(f"placeholder inside a longer Sigma value: {value[:80]!r}")
        return value
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            sub = _substitute_detection_value(item, values)
            out.extend(sub if isinstance(sub, list) else [sub])
        return out
    return value


def substitute_sigma(sigma_yaml: str, values: dict[str, list[str]]) -> str:
    doc = yaml.safe_load(sigma_yaml)
    detection = copy.deepcopy(doc.get("detection") or {})
    for name, selection in detection.items():
        if name == "condition":
            continue
        if isinstance(selection, dict):
            detection[name] = {f: _substitute_detection_value(v, values) for f, v in selection.items()}
        else:
            detection[name] = _substitute_detection_value(selection, values)
    doc["detection"] = detection
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    if _ANY.search(text):
        raise UnsupportedPlaceholder("placeholder left in the Sigma rule after substitution")
    return text
