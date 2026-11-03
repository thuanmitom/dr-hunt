"""Lookalike-domain matching for CertStream / URLScan (Vector 1).

Folds Unicode (IDN), Vietnamese diacritics and common homoglyphs/leet substitutions, then matches
brand keywords by substring or edit distance <= 1. The tenant's own domains never match.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

import idna

_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
        "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ʏ": "y", "ı": "i", "ł": "l", "đ": "d", "ð": "d",
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
    }
)  # fmt: skip


def fold(text: str) -> str:
    """'tên-côngty' / 'tenc0ngty' / 'xn--...' -> comparable ASCII skeleton."""
    t = text.lower()
    if "xn--" in t:
        try:
            t = idna.decode(t)
        except idna.IDNAError:
            pass
    t = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return t.translate(_CONFUSABLES)


def _within_one_edit(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) <= 1 or (
            len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
        )
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


@dataclass(frozen=True, slots=True)
class BrandMatch:
    domain: str
    keyword: str
    technique: str  # "substring" | "edit-distance"


class BrandMatcher:
    def __init__(self, keywords: list[str], own_domains: list[str]) -> None:
        self.keywords = sorted({fold(k) for k in keywords if len(k) >= 4})
        self.own = tuple(d.lower().rstrip(".") for d in own_domains)

    def is_own(self, domain: str) -> bool:
        return any(domain == d or domain.endswith("." + d) for d in self.own)

    def match(self, domain: str) -> BrandMatch | None:
        d = domain.lower().rstrip(".").removeprefix("*.")
        if not d or self.is_own(d):
            return None
        skeleton = fold(d)
        compact = skeleton.replace("-", "").replace(".", "")
        for kw in self.keywords:
            if kw in skeleton or kw in compact:
                return BrandMatch(d, kw, "substring")
        if any(len(kw) >= 6 for kw in self.keywords):
            tokens = {t for t in skeleton.replace("-", ".").split(".") if len(t) >= 5}
            for kw in self.keywords:
                if len(kw) >= 6 and any(_within_one_edit(kw, t) for t in tokens):
                    return BrandMatch(d, kw, "edit-distance")
        return None
