import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Iterable, Set, Any
from collections import defaultdict, deque
import re
from cve.cvescore import _nvd_infer_packages_from_cpe, _nvd_extract_references

ISO_FMT = "%Y-%m-%d"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

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

def _coerce_time(self, t):
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

def _get_time(self, n):
    raw = (getattr(n, "time", None)
           or (n.get("time") if isinstance(n, dict) else None)
           or (n.get("timestamp") if isinstance(n, dict) else None))
    return _coerce_time(raw)

def _node_key(self, n):
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
    # Two versions of the same package + one downstream that depends on the later one
    return {
        "nodes": [
            {"id": "n1", "version": "1.0.0", "timestamp": 1609459200000, "release": "com.demo:core:1.0.0"},
            {"id": "n2", "version": "1.1.0", "timestamp": 1612137600000, "release": "com.demo:core:1.1.0"},
            {"id": "n3", "version": "0.1.0", "timestamp": 1612224000000, "release": "com.app:service:0.1.0"},
        ],
        "edges": [
            {"src": "n2", "dst": "n3"}  # service depends on core:1.1.0
        ]
    }


def smoke_osv_jsonl() -> List[Dict[str, Any]]:
    # OSV-style record referencing versions and a fix commit
    return [{'source': 'osv', 'data': 
             {'id': 'CVE-2023-4874', 
            'details': 'Null pointer dereference when viewing a specially crafted email in Mutt >1.5.2 <2.2.12', 'modified': '2025-09-24T12:15:18.877423Z', 'published': '2023-09-09T15:15:34Z', 'related': ['ALSA-2024:2290', 'ALSA-2024:3058', 'MGASA-2024-0175', 'RLSA-2024:3058', 'SUSE-SU-2023:3702-1', 'SUSE-SU-2023:3826-1', 'USN-6374-2', 'openSUSE-SU-2024:13222-1'], 
            'references': [{'type': 'ADVISORY', 'url': 'https://gitlab.com/muttmua/mutt/-/commit/452ee330e094bfc7c9a68555e5152b1826534555.patch'}, 
                            {'type': 'ADVISORY', 'url': 'https://gitlab.com/muttmua/mutt/-/commit/a4752eb0ae0a521eec02e59e51ae5daedf74fda0.patch'}, 
                            {'type': 'ADVISORY', 'url': 'https://www.debian.org/security/2023/dsa-5494'}, {'type': 'WEB', 'url': 'http://www.openwall.com/lists/oss-security/2023/09/26/6'}, {'type': 'WEB', 'url': 'https://lists.debian.org/debian-lts-announce/2023/09/msg00021.html'}], 
                            'affected': [{'ranges': [{'type': 'GIT', 'repo': 'https://github.com/muttmua/mutt', 'events': [{'introduced': '0'}, {'fixed': '0a81a2a7ca2b4f33ae686bdedecbbdfd54cd1aff'}]}, {'type': 'GIT', 'repo': 'https://gitlab.com/muttmua/mutt', 
                                                                                                                                                                                                        'events': [{'introduced': '0'}, {'fixed': '452ee330e094bfc7c9a68555e5152b1826534555'}, 
                                                                                                                {'fixed': 'a4752eb0ae0a521eec02e59e51ae5daedf74fda0'}]}], 
                                                                                                                                                            'versions': ['mutt-0-92-10i', 'mutt-0-92-11i', 'mutt-0-92-9i', 'mutt-0-93-unstable', 'mutt-0-94-10i-rel', 'mutt-0-94-13-rel', 'mutt-0-94-14-rel', 'mutt-0-94-15-rel', 'mutt-0-94-16i-rel', 'mutt-0-94-17i-rel', 'mutt-0-94-18-rel', 'mutt-0-94-5i-rel', 'mutt-0-94-6i-rel', 'mutt-0-94-7i-rel', 'mutt-0-94-8i-rel', 'mutt-0-94-9i-p1', 'mutt-0-94-9i-rel', 'mutt-0-95-rel', 'mutt-0-96-1-rel', 'mutt-0-96-2-slightly-post-release', 'mutt-0-96-3-rel', 'mutt-0-96-4-rel', 'mutt-0-96-5-rel', 'mutt-0-96-6-rel', 'mutt-0-96-7-rel', 'mutt-0-96-8-rel', 'mutt-0-96-rel', 'mutt-1-1-1-1-rel', 'mutt-1-1-1-2-rel', 'mutt-1-1-1-rel', 'mutt-1-1-10-rel', 'mutt-1-1-11-rel', 'mutt-1-1-12-rel', 'mutt-1-1-13-rel', 'mutt-1-1-14-rel', 'mutt-1-1-2-rel', 'mutt-1-1-3-rel', 'mutt-1-1-4-rel', 'mutt-1-1-5-rel', 'mutt-1-1-6-rel', 'mutt-1-1-7-rel', 'mutt-1-1-8-rel', 'mutt-1-1-9-rel', 'mutt-1-1-rel', 'mutt-1-10-1-rel', 'mutt-1-10-rel', 'mutt-1-11-1-rel', 'mutt-1-11-2-rel', 'mutt-1-11-3-rel', 'mutt-1-11-4-rel', 'mutt-1-11-rel', 'mutt-1-12-1-rel', 'mutt-1-12-2-rel', 'mutt-1-12-rel', 'mutt-1-13-1-rel', 'mutt-1-13-2-rel', 'mutt-1-13-3-rel', 'mutt-1-13-4-rel', 'mutt-1-13-5-rel', 'mutt-1-13-rel', 'mutt-1-14-1-rel', 'mutt-1-14-2-rel', 'mutt-1-14-3-rel', 'mutt-1-14-4-rel', 'mutt-1-14-5-rel', 'mutt-1-14-6-rel', 'mutt-1-14-7-rel', 'mutt-1-14-rel', 'mutt-1-3-1-rel', 'mutt-1-3-10-rel', 'mutt-1-3-11-rel', 'mutt-1-3-12-rel', 'mutt-1-3-13-rel', 'mutt-1-3-14-rel', 'mutt-1-3-15-rel', 'mutt-1-3-16-rel', 'mutt-1-3-17-rel', 'mutt-1-3-18-rel', 'mutt-1-3-19-rel', 'mutt-1-3-2-rel', 'mutt-1-3-20-rel', 'mutt-1-3-21-rel', 'mutt-1-3-22-1-rel', 'mutt-1-3-22-rel', 'mutt-1-3-23-1-rel', 'mutt-1-3-23-2-rel', 'mutt-1-3-23-rel', 'mutt-1-3-24-rel', 'mutt-1-3-25-rel', 'mutt-1-3-26-rel', 'mutt-1-3-27-rel', 'mutt-1-3-3-rel', 'mutt-1-3-4-rel', 'mutt-1-3-5-rel', 'mutt-1-3-6-rel', 'mutt-1-3-7-rel', 'mutt-1-3-8-rel', 'mutt-1-3-9-rel', 'mutt-1-3-rel', 'mutt-1-5-1-rel', 'mutt-1-5-10-rel', 'mutt-1-5-11-rel', 'mutt-1-5-12-rel', 'mutt-1-5-13-rel', 'mutt-1-5-14-rel', 'mutt-1-5-15-rel', 'mutt-1-5-16-rel', 'mutt-1-5-17-rel', 'mutt-1-5-18-rel', 'mutt-1-5-19-rel', 'mutt-1-5-2-rel', 'mutt-1-5-20-rel', 'mutt-1-5-21-rel', 'mutt-1-5-22-rel', 'mutt-1-5-23-rel', 'mutt-1-5-24-rel', 'mutt-1-5-3-rel', 'mutt-1-5-4-rel', 'mutt-1-5-5-1-rel', 'mutt-1-5-5-rel', 'mutt-1-5-6-rel', 'mutt-1-5-7-rel', 'mutt-1-5-8-rel', 'mutt-1-5-9-rel', 'mutt-1-6-1-rel', 'mutt-1-6-2-rel', 'mutt-1-6-rel', 'mutt-1-7-1-rel', 'mutt-1-7-2-rel', 'mutt-1-7-rel', 'mutt-1-8-1-rel', 'mutt-1-8-2-rel', 'mutt-1-8-3-rel', 'mutt-1-8-rel', 'mutt-1-9-1-rel', 'mutt-1-9-2-rel', 'mutt-1-9-3-rel', 'mutt-1-9-4-rel', 'mutt-1-9-5-rel', 'mutt-1-9-rel', 'mutt-2-0-1-rel', 'mutt-2-0-2-rel', 'mutt-2-0-3-rel', 'mutt-2-0-4-rel', 'mutt-2-0-5-rel', 'mutt-2-0-6-rel', 'mutt-2-0-7-rel', 'mutt-2-0-rel', 'mutt-2-1-1-rel', 'mutt-2-1-2-rel', 'mutt-2-1-3-rel', 'mutt-2-1-4-rel', 'mutt-2-1-5-rel', 'mutt-2-1-rel', 'mutt-2-2-1-rel', 'mutt-2-2-10-rel', 'mutt-2-2-11-rel', 'mutt-2-2-2-rel', 'mutt-2-2-3-rel', 'mutt-2-2-4-rel', 'mutt-2-2-5-rel', 'mutt-2-2-6-rel', 'mutt-2-2-7-rel', 'mutt-2-2-8-rel', 'mutt-2-2-9-rel', 'mutt-2-2-rel', 'post-type-punning-patch', 'pre-type-punning-patch'], 'database_specific': {'source': 'https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2023-4874.json'}}], 'schema_version': '1.7.3', 'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H'}]}}]

def smoke_nvd_jsonl() -> List[Dict[str, Any]]:
    # Minimal NVD complement
    return [{'source': 'nvd', 'data': 
             {'resultsPerPage': 1, 'startIndex': 0, 'totalResults': 1, 'format': 'NVD_CVE', 'version': '2.0', 'timestamp': '2025-10-09T08:56:40.940', 'vulnerabilities': 
              [{'cve': {'id': 'CVE-2023-4873', 'sourceIdentifier': 'cna@vuldb.com', 'published': '2023-09-10T03:15:18.080', 'lastModified': '2024-11-21T08:36:09.820', 'vulnStatus': 'Modified', 'cveTags': [], 'descriptions': 
        [{'lang': 'en', 'value': 'A vulnerability, which was classified as critical, was found in Byzoro Smart S45F Multi-Service Secure Gateway Intelligent Management Platform up to 20230906. Affected is an unknown function of the file /importexport.php. The manipulation of the argument sql leads to os command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-239358 is the identifier assigned to this vulnerability.'}, 
            {'lang': 'es', 'value': 'Una vulnerabilidad, que se clasificó como crítica, se encontró en Beijing Baichuo Smart S45F Multi-Service Secure Gateway Intelligent Management Platform hasta la versión 20230906. Una función desconocida del archivo /importexport.php está afectada. La manipulación del argumento sql conduce a la inyección de comandos de Sistema Operativo. Es posible lanzar el ataque de forma remota. El exploit ha sido divulgado al público y puede ser utilizado. VDB-239358 es el identificador asignado a esta vulnerabilidad.'}], 
            'metrics': {'cvssMetricV31': [{'source': 'cna@vuldb.com', 'type': 'Secondary', 'cvssData': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L', 'baseScore': 6.3, 'baseSeverity': 'MEDIUM', 'attackVector': 'NETWORK', 'attackComplexity': 'LOW', 'privilegesRequired': 'LOW', 'userInteraction': 'NONE', 'scope': 'UNCHANGED', 'confidentialityImpact': 'LOW', 'integrityImpact': 'LOW', 'availabilityImpact': 'LOW'}, 'exploitabilityScore': 2.8, 'impactScore': 3.4}, 
                                        {'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'baseScore': 9.8, 'baseSeverity': 'CRITICAL', 'attackVector': 'NETWORK', 'attackComplexity': 'LOW', 'privilegesRequired': 'NONE', 'userInteraction': 'NONE', 'scope': 'UNCHANGED', 'confidentialityImpact': 'HIGH', 'integrityImpact': 'HIGH', 'availabilityImpact': 'HIGH'}, 'exploitabilityScore': 3.9, 'impactScore': 5.9}], 'cvssMetricV2': 
                                        [{'source': 'cna@vuldb.com', 'type': 'Secondary', 'cvssData': {'version': '2.0', 'vectorString': 'AV:N/AC:L/Au:S/C:P/I:P/A:P', 'baseScore': 6.5, 'accessVector': 'NETWORK', 'accessComplexity': 'LOW', 'authentication': 'SINGLE', 'confidentialityImpact': 'PARTIAL', 'integrityImpact': 'PARTIAL', 'availabilityImpact': 'PARTIAL'}, 'baseSeverity': 'MEDIUM', 'exploitabilityScore': 8.0, 'impactScore': 6.4, 'acInsufInfo': False, 'obtainAllPrivilege': False, 'obtainUserPrivilege': False, 'obtainOtherPrivilege': False, 'userInteractionRequired': False}]}, 
                                        'weaknesses': [{'source': 'cna@vuldb.com', 'type': 'Primary', 'description': [{'lang': 'en', 'value': 'CWE-78'}]}], 'configurations': [{'operator': 'AND', 'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:o:byzoro:smart_s45f_firmware:*:*:*:*:*:*:*:*', 'versionEndIncluding': '20230906', 'matchCriteriaId': '2B7BCA64-40FB-44E9-8F26-4BB243B68F15'}]}, {'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': False, 'criteria': 'cpe:2.3:h:byzoro:smart_s45f:-:*:*:*:*:*:*:*', 'matchCriteriaId': '0BDA1A96-1CB9-48C6-805E-514CE4FEC9E3'}]}]}], 
                                        'references': [{'url': 'https://github.com/cugerQDHJ/cve/blob/main/rce.md', 'source': 'cna@vuldb.com', 'tags': ['Exploit', 'Third Party Advisory']}, 
                                                                    {'url': 'https://vuldb.com/?ctiid.239358', 'source': 'cna@vuldb.com', 'tags': 
                                                                                                                                                                                                                                                                    ['Permissions Required', 'Third Party Advisory']}, {'url': 'https://vuldb.com/?id.239358', 'source': 'cna@vuldb.com', 'tags': ['Permissions Required', 'Third Party Advisory']}, {'url': 'https://vuldb.com/?submit.204279', 'source': 'cna@vuldb.com'}, {'url': 'https://github.com/cugerQDHJ/cve/blob/main/rce.md', 'source': 'af854a3a-2127-422b-91ae-364da2661108', 'tags': ['Exploit', 'Third Party Advisory']}, {'url': 'https://vuldb.com/?ctiid.239358', 'source': 'af854a3a-2127-422b-91ae-364da2661108', 'tags': ['Permissions Required', 'Third Party Advisory']}, {'url': 'https://vuldb.com/?id.239358', 'source': 'af854a3a-2127-422b-91ae-364da2661108', 'tags': ['Permissions Required', 'Third Party Advisory']}, 
                                                                                                                                                                                                                                                                    {'url': 'https://vuldb.com/?submit.204279', 'source': 'af854a3a-2127-422b-91ae-364da2661108'}]}}]}}]
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


def _family_key(group: str, artifact: str) -> str:
    """
    Normalize and merge related artifacts under one family name.
    Example:
        org.apache.tomcat.embed:tomcat-embed-core -> tomcat
        org.springframework.boot:spring-boot-starter-web -> spring
        org.apache.hadoop:hadoop-common -> hadoop
    """
    # prioritize artifact name
    base = artifact.lower()
    



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

