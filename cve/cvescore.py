'''
 # @ Create Time: 2025-09-23 16:36:12
 # @ Modified time: 2025-09-23 16:36:37
 # @ Description: module to convert severity or vector-like CVE scores to numerical scores
 '''

import math
import re
import json
from pathlib import Path
from typing import Dict, Any, Iterable

def map_severity_to_score(sev: str) -> float:
    ''' it aligns with cvss31_base_score() below
    
    '''
    if not sev:
        return 0.0
    
    sev = sev.strip().upper()
    # Tune these thresholds to your liking
    mapping = {
        "NONE": 0.0,
        "LOW": 2.0,
        "MEDIUM": 5.5,
        "MODERATE": 5.5,  # alias
        "HIGH": 8.0,
        "CRITICAL": 9.5,
        "UNKNOWN": 0.0,
    }
    return mapping.get(sev, 0.0)

def cvss31_base_score(vector: str) -> float:
    """
    Compute CVSS v3.1 base score from vector string like:
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
    Implements the official base metrics formula.
    """
    if not vector or not vector.startswith("CVSS:3.1/"):
        return ValueError("Not a CVSS3.1 vector")
    
    # Parse metrics
    parts = dict(m.split(":") for m in vector.split("/")[1:])  # drop "CVSS:3.1"
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
    AC = {"L": 0.77, "H": 0.44}[parts["AC"]]
    S  = parts["S"]  # "U" or "C"
    UI = {"N": 0.85, "R": 0.62}[parts["UI"]]

    # PR depends on Scope
    if S == "U":
        PR = {"N": 0.85, "L": 0.62, "H": 0.27}[parts["PR"]]
    else:  # S == "C"
        PR = {"N": 0.85, "L": 0.68, "H": 0.5}[parts["PR"]]

    # Confidentiality/Integrity/Availability
    CIA_map = {"N": 0.0, "L": 0.22, "H": 0.56}
    C = CIA_map[parts["C"]]
    I = CIA_map[parts["I"]]
    A = CIA_map[parts["A"]]

    # Impact subscore
    ISS = 1 - (1 - C) * (1 - I) * (1 - A)
    if S == "U":
        Impact = 6.42 * ISS
    else:
        Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15

    # Exploitability subscore
    Exploitability = 8.22 * AV * AC * PR * UI

    if Impact <= 0:
        base = 0.0
    else:
        if S == "U":
            base = min(Impact + Exploitability, 10)
        else:
            base = min(1.08 * (Impact + Exploitability), 10)

    # CVSS "round up" to one decimal: ceil(x*10)/10
    return math.ceil(base * 10.0) / 10.0


def load_cve_seve_json(path: Path) -> Dict[str, str]:
    '''
    Accepts either:
      - a list of objects with {"name": "CVE-YYYY-NNNN", "severity": "..."}
      - or a dict whose values are lists of such objects (e.g., keyed by coordinates)
    Returns: { "CVE-2015-8031": "CRITICAL", ... }

    '''
    data = json.loads(path.read_text(encoding='utf-8'))

    def extract_from_iter(items: Iterable[Dict[str, Any]], out: Dict[str, str]):
        for it in items:
            name = it.get("name")
            sev = it.get("severity")
            if name and sev:
                out[name] = sev
    
    out: Dict[str, str] = {}

    if isinstance(data, list):
        extract_from_iter(data, out)
    elif isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                extract_from_iter(v, out)
    
    else:
        raise ValueError(f"Unexpected JSON structure in {path}")

    return out


def cve_score_lookup(
    cve_dict: str | None = None,
    sev_str: dict | None = None,
    ) -> float:
    '''
    Args:
        cve_dict: the cve information dict from OSV or NVD
        sev_str: optional severity string like "CRITICAL" or "HIGH"
    
    Priority:
        1) map severity_str to numeric
        2) numeric score in osv_dict
        3) cvss31 vector in osv_dict -> compute base score
        4) fallback 0.0
    Expected osv_dict shape examples:
        {"severity": [{"score": 8.8, "type": "CVSS_V3"}], ...}
        {"severity": [{"type":"CVSS_V3","score":null,"score_vector":"CVSS:3.1/..."}], ...}
    '''
    if sev_str:
        return map_severity_to_score(sev_str)

    if cve_dict:
        sev_list = cve_dict.get("severity") or []
        for entry in sev_list:
            sc = entry.get("score")
            if sc is not None:
                try:
                    return float(sc)
                except Exception:
                    pass
        
        for entry in sev_list:
            vec = entry.get("score_vector") or entry.get("vectorString")
            if not vec:
                cvss = cve_dict.get("cvssV3") or {}
                vec = cvss.get("vectorString")
            if vec and isinstance(vec, str) and vec.startswith("CVSS:3.1/"):
                try:
                    return cvss31_base_score(vec)
                except Exception:
                    pass

    return 0.0