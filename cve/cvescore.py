'''
 # @ Create Time: 2025-09-23 16:36:12
 # @ Modified time: 2025-09-23 16:36:37
 # @ Description: module to convert severity or vector-like CVE scores to numerical scores
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import math
import re
import json
from pathlib import Path
from typing import Dict, Any, Iterable, Optional, Tuple
from cve.cveinfo import osv_cve_api


def _normalize_cve_id(item: Any) -> Optional[str]:
    """Turn a cve_list entry into a lookup string for OSV."""
    if isinstance(item, str) and item.strip():
        return item.strip()
    if isinstance(item, dict):
        for key in ("id", "name", "cve_id", "cveId"):
            val = item.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None

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
        return 0.0
    
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

def iter_cve_entries(cve_list):
    '''
    convert node.cve_list to tuples of (cve_id, severity_str, vector_str)
    '''
    if not cve_list:
        return
    for it in cve_list:
        if not isinstance(it, dict):
            continue
        cid = _normalize_cve_id(it) 
        if not cid:
            continue
        yield cid, it.get("severity")

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


def cve_score_dict_gen(unique_cve_ids, cve_agg_data_dict):
    ''' 
    args:
        unique_cve_ids: an iterable of unique cve ids
        cve_agg_data_dict: the dict with cve_id -> severity_str mapping

    return:
    {
        "CVE-2015-8031": 9.8,
        "CVE-2016-9910": 7.5,
        ...
    }
    '''
    cve_score_dict = {}
    # check whether the severity string is present
    for cve_id in unique_cve_ids:
        cve_str = cve_agg_data_dict.get(cve_id)
        if cve_str:
            score = map_severity_to_score(cve_str)
            cve_score_dict[cve_id] = score
            continue
        else:
            # try to fetch from osv api
            osv_dict = osv_cve_api(cve_id)
            try:
                score = cvss31_base_score(osv_dict.get("score", ""))
            except Exception:
                pass
            cve_score_dict[cve_id] = score
    return cve_score_dict

def node_cve_score_agg(depgraph, node_id, per_cve_scores, 
                        t_s=None, t_e=None, 
                        agg="sum",
                        prefer_per_cve: bool = True,
                        ):
    '''
    Aggregate the CVE scores for a given node n in depgraph.
    If t_s and t_e are given, only consider CVEs whose timestamps fall within [t_s, t_e].
    
    args:
        node_id: node id
        depgraph: the dependency graph (networkx graph)
        per_cve_scores: dict of cve_id -> score
        t_s: start timestamp (inclusive)
        t_e: end timestamp (inclusive)
        agg: aggregation method, either "sum" or "max" or "mean"
    
    return:
        aggregated score (float)
    '''
    items = depgraph.nodes[node_id].get("cve_list")
    vals = []
    if not items:
        return 0.0

    vals = []
    for cid, sev in iter_cve_entries(items):
        s = None
        rec = per_cve_scores.get(cid)
        if prefer_per_cve and rec is not None:
            # float or {"score": float}
            if isinstance(rec, dict):
                s = rec.get("score")
            elif isinstance(rec, (int, float)):
                s = float(rec)
        if s is None:
            s = map_severity_to_score(sev)

        if s is not None:
            vals.append(float(s))

    if not vals:
        return 0.0

    if agg == "sum":
        return sum(vals)
    elif agg == "max":
        return max(vals)
    elif agg == "mean":
        return sum(vals) / len(vals)
    elif agg == "decay_mean":
        return sum(vals) / len(vals)
    else:
        return sum(vals)
            
