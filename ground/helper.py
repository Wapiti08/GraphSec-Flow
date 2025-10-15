import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Iterable, Set, Any
from collections import defaultdict, deque
import re
from cve.cvescore import _nvd_infer_packages_from_cpe, _nvd_extract_references

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


