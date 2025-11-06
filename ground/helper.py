import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Iterable, Set, Any
from collections import defaultdict, deque
import re
from cve.cvescore import _nvd_infer_packages_from_cpe, _nvd_extract_references
import networkx as nx


ISO_FMT = "%Y-%m-%d"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# A robust parser for coordinates present in node name / attrs
_coord_re = re.compile(r'^(?P<g>[\w.\-]+):(?P<a>[\w.\-]+)(?:@(?P<v>.+))?$')


def _norm_pkg(s: str) -> str:
    s = (s or "").lower().strip()
    for suf in ("-core", "-parent", "-service", "-lib"):
        if s.endswith(suf):
            s = s[: -len(suf)]
    return s

def _build_pkg_index(G):
    full2ids, art2ids = {}, {}
    for nid, node in G.nodes.items():
        pkg_full = _norm_pkg(getattr(node, "package", "") or "")
        if not pkg_full:
            continue
        art = pkg_full.split(":")[-1]
        full2ids.setdefault(pkg_full, set()).add(nid)
        art2ids.setdefault(art, set()).add(nid)
    return full2ids, art2ids

def _resolve_root_ids(root_pkg: str, full2ids, art2ids):
    p = _norm_pkg(root_pkg)
    if p in full2ids:
        return list(full2ids[p])
    art = p.split(":")[-1]
    return list(art2ids.get(art, []))

def _norm(x: str) -> str:
    return (x or "").strip().lower()

def _extract_coords_from_node(nid, node_data) -> tuple[str, str]:
    # Try attrs first
    g = _norm(node_data.get("groupId")) if isinstance(node_data, dict) else ""
    a = _norm(node_data.get("artifactId")) if isinstance(node_data, dict) else ""
    if g and a:
        return g, a
    # Fallback to node string
    s = str(node_data.get("name") if isinstance(node_data, dict) and "name" in node_data else nid)
    m = _coord_re.match(s)
    if m:
        return _norm(m.group("g")), _norm(m.group("a"))
    # As a last resort, try to split dotted name
    if ":" in s:
        parts = s.split(":")
        if len(parts) >= 2:
            return _norm(parts[0]), _norm(parts[1].split("@")[0])
    return "", ""

def _pkg_key_from_artifact(a: str) -> str:
    # normalize a bit for pkg bucket
    a = _norm(a)
    # strip super-common suffixes
    a = re.sub(r'[-_.](core|impl|common|api|parent|lib|service)$', "", a)
    a = re.sub(r"[-_.]+", "-", a)
    return a.strip("-_.")

def _get_version(n):
    return (getattr(n, "version", None)
            or (n.get("version") if isinstance(n, dict) else None)
            or "")

def _get_release(n):
    # dict or object
    return (getattr(n, "release", None)
            or (n.get("release") if isinstance(n, dict) else None)
            or getattr(n, "name", None)
            or (n.get("name") if isinstance(n, dict) else None)
            or "")

def _coerce_time(t):
    if t is None:
        return None
    if isinstance(t, (int, float)):
        if t > 10_000_000_000:  # 13位→毫秒
            return datetime.fromtimestamp(t / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(t, tz=timezone.utc)
    if isinstance(t, str):
        try:
            return datetime.fromisoformat(t.replace("Z", "+00:00"))
        except Exception:
            return None
    return t if isinstance(t, datetime) else None

def _get_time(n):
    raw = (getattr(n, "time", None)
           or (n.get("time") if isinstance(n, dict) else None)
           or (n.get("timestamp") if isinstance(n, dict) else None))
    return _coerce_time(raw)

def _node_key(n):
    # remove repeatations：release|version|time
    tt = _get_time(n)
    return f"{_get_release(n)}|{_get_version(n)}|{tt.isoformat() if tt else ''}"

def _unwrap_record(r: Dict[str, Any]) -> Dict[str, Any]:
    if "data" in r and isinstance(r["data"], dict):
        return r["data"]
    if "builder_payload" in r and isinstance(r["builder_payload"], dict):
        return r["builder_payload"]
    return r

def _extract_cve_id(r: Dict[str, Any]) -> Optional[str]:
    # prioritize standard keys in data.aliases
    for k in ["cve_id", "cve", "id"]:
        v = r.get(k)
        if isinstance(v, str) and CVE_RE.match(v):
            return v
    for k in ("aliases",):
        vals = r.get(k) or []
        for v in vals:
            if isinstance(v, str) and CVE_RE.fullmatch(v):
                return v
    return None

def _extract_coordinates_from_osv_pkg(pkg_obj: Dict[str, Any]) -> Dict[str, Optional[str]]:
    ''' check ecosystem first and then filter with version and ranges
    
    '''
    name = (pkg_obj or {}).get("name") or ""
    eco = (pkg_obj or {}).get("ecosystem") or ""
    purl = (pkg_obj or {}).get("purl") or ""
    group = artifact = None

    if eco.lower() == "marven":
        if ":" in name:
            group, artifact = name.split(":", 1)
    if purl and "pkg:marven/" in purl:
        try:
            body = purl.split("pkg:marven/", 1)[1]
            gav = body.split("@",1)[0]
            parts = gav.split("/")
            if len(parts) >= 2:
                group, artifact = parts[0], parts[1]
        except Exception:
            pass
    if not artifact and name:
        artifact = name.split("/")[-1]
    return {"group": group, "artifact": artifact}


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
def smoke_dep_graph() -> Dict[str, Any]:
    return {
        "nodes": [
            {"id": "n1", "version": "1.0.0", "timestamp": 1609459200000, "release": "com.demo:core:1.0.0"},
            {"id": "n2", "version": "1.1.0", "timestamp": 1612137600000, "release": "com.demo:core:1.1.0"},
            {"id": "n3", "version": "0.1.0", "timestamp": 1612224000000, "release": "com.demo:app-service:0.1.0"},
        ],
        "edges": [
            {"src": "n1", "dst": "n2"},  # core:1.0.0 → core:1.1.0
            {"src": "n2", "dst": "n3"}   # core:1.1.0 → app-service:0.1.0
        ],
    }


def resolve_package_name(short_name: str, known_pkgs: Iterable[str]) -> str:
    """Try to find full package name (group:artifact) matching short_name."""
    short_name = short_name.lower()
    if ":" in short_name:
        return short_name
    matches = [k for k in known_pkgs
               if k.endswith(":" + short_name) or k.split(":")[-1] == short_name]
    if not matches:
        return short_name
    if len(matches) == 1:
        return matches[0]
    # deterministic resolution: pick lexicographically smallest
    return sorted(matches)[0]


def smoke_osv_jsonl() -> List[Dict[str, Any]]:
    """
    OSV-style record that triggers both _package() and _extract_coordinates_from_osv_pkg.
    """
    return [
            {
                "id": "CVE-TEST-0001",
                "package": "com.demo:core",
                "details": "Test vulnerability in com.demo:core < 1.1.0",
                "affected": [
                    {
                        "package": {"ecosystem": "Maven", "name": "com.demo:core"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "1.1.0"},
                                ],
                            }
                        ],
                        "versions": ["1.0.0"],
                    }
                ],
                "fix_commits": [],
            }
        ]

def smoke_nvd_jsonl() -> List[Dict[str, Any]]:
    """
    Minimal NVD-like record (optional, for completeness)
    """
    return [
        {
            "source": "nvd",
            "data": {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-TEST-0001",
                            "descriptions": [
                                {"lang": "en", "value": "Test NVD entry for core 1.0.0 vulnerability."}
                            ],
                        }
                    }
                ]
            },
        }
    ]

def _split_release(release: str):
    # "group:artifact:version" -> (group, artifact, version)
    if not release:
        return None, None, None
    parts = str(release).split(":")
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return None, parts[0], parts[1]
    return None, None, parts[0] if parts else (None, None, None)


def split_cve_meta_to_builder_inputs(cve_meta: Dict[Any, List[Dict[str, Any]]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Accepts pre-cached items like:
      {'source':'nvd','data':{...NVD v2 container...}}
      {'source':'osv','data':{...OSV single record...}}

    Returns:
      (osv_records, nvd_records)  # each a list of dicts consumable by GTBuilder
    """
    osv_records: List[Dict[str, Any]] = []
    nvd_records: List[Dict[str, Any]] = []

    for metas in cve_meta.values():
        if not isinstance(metas, list):
            continue
        for item in metas:
            if not isinstance(item, dict):
                continue

        src = (item.get("source") or "").lower()

        payload = item.get("builder_payload")
        if payload is None:
            payload = item.get("data")
        if not isinstance(payload, dict):
            payload = {}

        if src == "osv":
            # data is an OSV record; keep as-is so builder can read affected[].versions/ranges.events
            osv_records.append(payload)

        elif src == "nvd":
            # NVD v2 container → expand to individual CVEs as lightweight dicts
            container = payload if payload.get("vulnerabilities") else {}
            if container:
                for it in (container.get("vulnerabilities") or []):
                    cve = (it.get("cve") or {})
                    nvd_records.append({
                        "cve_id": cve.get("id"),
                        "published": cve.get("published"),
                        "lastModified": cve.get("lastModified"),
                        "packages": _nvd_infer_packages_from_cpe(cve),
                        "references": _nvd_extract_references(cve),
                        "metrics": cve.get("metrics"),
                        "source": "NVD",
                    })
        else:
            # Fallback detection if 'source' is missing but structure is recognizable
            data = payload
            if isinstance(data, dict) and data.get("vulnerabilities"):  # NVD v2 container
                for it in (data.get("vulnerabilities") or []):
                    cve = (it.get("cve") or {})
                    nvd_records.append({
                        "cve_id": cve.get("id"),
                        "published": cve.get("published"),
                        "lastModified": cve.get("lastModified"),
                        "packages": _nvd_infer_packages_from_cpe(cve),
                        "references": _nvd_extract_references(cve),
                        "metrics": cve.get("metrics"),
                        "source": "NVD",
                    })
            elif isinstance(data, dict) and (data.get("id") or data.get("affected") or data.get("references")):  # OSV-like
                osv_records.append(data)

    return osv_records, nvd_records

def build_release_index_from_depgraph(G):
    """
    Build a mapping from artifact name (e.g., 'tomcat') to a list of
    (node_id, release, timestamp), sorted by timestamp.
    """
    idx = {}

    for nid, node in G.nodes.items():
        # handle both dict-like and object-like nodes
        attrs = getattr(node, "__dict__", node) if not isinstance(node, dict) else node

        # try to extract release string
        release = attrs.get("release")
        if not release:
            pkg = attrs.get("package") or attrs.get("group")
            ver = attrs.get("version")
            if pkg and ver:
                release = f"{pkg}:{ver}"
            else:
                continue
        
        # standardize
        release = str(release).strip()
        if release.count(":") < 2:
            continue
        
        parts = release.split(":")
        group = parts[0].lower()
        artifact = parts[1].lower()
        key = f"{group}:{artifact}"  # use full identity for uniqueness

        ts = node.time.timestamp() if node.time else 0

        idx.setdefault(key, []).append((nid, release, ts))

    # sort each artifact list by timestamp ascending
    for k in idx:
        idx[k].sort(key=lambda x: x[2] or 0)

    return idx


def resolve_root_to_node(root_id: str, release_index: dict, G=None):
    """
    Given a root_id (like 'tomcat'), find the earliest version node.
    """
    pkg = root_id.strip("@").lower()
    cands = release_index.get(pkg)
    if not cands:
        # try fuzzy match (substring or partial)
        for k in release_index:
            if k.endswith(f":{pkg}") or pkg in k:
                cands = release_index[k]
                break

    if not cands:
        return None, f"pkg_not_found_in_graph: {pkg}"

    # filter out individual nodes
    if G is not None:
        cands = [(nid, rel, ts) for nid, rel, ts in cands if nid in G and (G.out_degree(nid) > 0 or G.in_degree(nid) > 0)]
    
    if not cands:
        return None, f"no_connected_node_found_for:{pkg}"

    # pick earliest timestamp
    cands.sort(key=lambda x: x[2] or 0)
    nid, rel, ts = cands[0]

    return nid, f"matched_by_artifact: {pkg}"

