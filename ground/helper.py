from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Iterable, Set, Any
from collections import defaultdict, deque
import re

ISO_FMT = "%Y-%m-%d"


def parse_date(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    # Accept common variants (OSV uses RFC3339)
    candidates = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(s[:len(fmt)], fmt)
        except Exception:
            continue
    return None


def iso(d: Optional[datetime]) -> Optional[str]:
    return d.strftime(ISO_FMT) if d else None


def safe_min(dates: Iterable[Optional[datetime]]) -> Optional[datetime]:
    vals = [d for d in dates if d is not None]
    return min(vals) if vals else None

def infer_pkg_ver_from_release(release: str) -> Tuple[str, str]:
    if not release or not isinstance(release, str):
        return "", ""
    parts = release.split(":")
    if len(parts) >= 3:
        pkg = ":".join(parts[:2])
        ver = parts[-1]
        return pkg, ver
    if len(parts) == 2:
        return parts[0], parts[1]
    return release, ""

# -----------------------------
# SemVer Helpers
# -----------------------------

SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
# Extract the first x.y.z inside a string (e.g., 'v1.3.1-rc1' -> '1.3.1')
SEMVER_ANY_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")

@dataclass(order=True, frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int

    @staticmethod
    def parse(s: str):
        if not s:
            return None
        s = s.strip()
        # strip common 'v' prefix 
        if s.lower().startswith("v") and len(s) > 1:
            s = s[1:]
        m = SEMVER_RE.match(s)
        if not m:
            m2 = SEMVER_ANY_RE.search(s)
            if not m2:
                return None
            return SemVer(int(m2.group(1)), int(m2.group(2)), int(m2.group(3)))
        
        return SemVer(int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

@dataclass
class VersionRange:
    '''
    Supported expressions:
    - exact: "1.2.3"
    - comparators: ">=1.2.0", "<1.4.0", combined: ">=1.2.0,<1.4.0"
    
    '''
    lower: Optional[SemVer] = None
    lower_inclusive: bool = True
    upper: Optional[SemVer] = None
    upper_inclusive: bool = False
    exact: Optional[SemVer] = None

    @staticmethod
    def parse(expr: str) -> "VersionRange":
        expr = expr.strip()

        if SEMVER_RE.match(expr) or SEMVER_ANY_RE.search(expr):
            v = SemVer.parse(expr)
            return VersionRange(exact=v)
        
        parts = [p.strip() for p in expr.split(",") if p.strip()]
        rng = VersionRange()

        for p in parts:
            if p.startswith(">="):
                rng.lower = SemVer.parse(p[2:])
                rng.lower_inclusive = True
            elif p.startswith(">"):
                rng.lower = SemVer.parse(p[1:])
                rng.lower_inclusive = False
            elif p.startswith("<="):
                rng.upper = SemVer.parse(p[2:])
                rng.upper_inclusive = True
            elif p.startswith("<"):
                rng.upper = SemVer.parse(p[1:])
                rng.upper_inclusive = False
            elif p.startswith("=="):
                v = SemVer.parse(p[2:])
                rng.exact = v
            else:
                v = SemVer.parse(p)
                if v:
                    rng.exact = v
        return rng
    
    def contains(self, v: SemVer) -> bool:
        if self.exact is not None:
            return v == self.exact
        if self.lower is not None:
            if self.lower_inclusive and v < self.lower:
                return False
            if not self.lower_inclusive and v <= self.lower:
                return False
        if self.upper is not None:
            if self.upper_inclusive and v > self.upper:
                return False
            if not self.upper_inclusive and v >= self.upper:
                return False
        return True
