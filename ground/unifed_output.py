# Convert the uploaded JSONL ground-truth files into a unified GT JSON file
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

rc_path = Path("/mnt/data/root_causes.jsonl")
rp_path = Path("/mnt/data/ref_paths.jsonl")
out_path = Path("/mnt/data/gt_unified.json")

out_path = Path.cwd().parent.joinpath("data", "gt_unified.json")
rp_path = Path.cwd().parent.joinpath("data", "ref_paths.jsonl")
rc_path = Path.cwd().parent.joinpath("data","root_causes.jsonl")

def _normalize_node_id(package: Optional[str], version: Optional[str], node_id: Optional[str]) -> Optional[str]:
    if node_id:
        nid = str(node_id).strip()
        if nid.endswith("@"):
            nid = nid[:-1]
        return nid or None
    if package and version:
        p = str(package).strip()
        v = str(version).strip()
        if p and v:
            return f"{p}@{v}"
        if p:
            return p
    if package:
        p = str(package).strip()
        return p or None
    return None

def _to_ms(ts):
    if ts is None or ts == "":
        return None
    try:
        v = float(ts)
        return v * 1000.0 if v < 1e10 else v
    except Exception:
        return None

def _safe_parse_path(path_field: Any) -> List[str]:
    """
    Try to coerce the path field into a list of node_ids (strings).
    Accepts list, dict with 'nodes', or JSON-encoded string of the above.
    """
    if path_field is None:
        return []
    v = path_field
    # If it's a JSON-encoded string, try to parse
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("{") or s.startswith("["):
            try:
                v = json.loads(s)
            except Exception:
                # maybe comma-separated
                parts = [x.strip() for x in s.split(",") if x.strip()]
                return parts
        else:
            # plain comma-separated or single node
            parts = [x.strip() for x in s.split(",") if x.strip()]
            return parts
    # Dict with nodes
    if isinstance(v, dict) and "nodes" in v:
        arr = v.get("nodes") or []
        return [str(x).strip() for x in arr if str(x).strip()]
    # List already
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    # Fallback to string repr
    return [str(v).strip()] if str(v).strip() else []

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception as e:
                rows.append({"__parse_error__": str(e), "__raw__": line})
    return rows

root_causes = read_jsonl(rc_path)
ref_paths = read_jsonl(rp_path)

# Build root map
root_map: Dict[str, Dict[str, Any]] = {}
for item in root_causes:
    if "__parse_error__" in item: 
        continue
    cve = item.get("cve_id")
    pkg = item.get("package") or ""
    ver = item.get("version") or ""
    nid = _normalize_node_id(pkg, ver, None)
    tms = _to_ms(item.get("time_introduced"))
    conf = float(item.get("confidence", 0.0) or 0.0)
    if not cve:
        continue
    root_map[cve] = {
        "pkg": pkg or None,
        "version": ver or None,
        "node_id": nid,
        "t": tms,
        "confidence": conf,
        "evidence": item.get("evidence"),
        "fix_commits": item.get("fix_commits"),
    }

# Aggregate records by cve_id
gt_records: Dict[str, Dict[str, Any]] = {}
for cve, root in root_map.items():
    gt_records[cve] = {"cve_id": cve, "root": root, "paths": [], "confidence": root.get("confidence", 0.0)}

for item in ref_paths:
    if "__parse_error__" in item: 
        continue
    cve = item.get("cve_id")
    if not cve:
        continue
    rec = gt_records.setdefault(cve, {"cve_id": cve, "root": None, "paths": [], "confidence": float(item.get("confidence", 0.0) or 0.0)})
    # consider root_id if root missing
    rid = item.get("root_id")
    if rec["root"] is None and rid is not None:
        nid = _normalize_node_id(None, None, rid)
        rec["root"] = {"pkg": None, "version": None, "node_id": nid, "t": None, "confidence": float(item.get("confidence", 0.0) or 0.0)}
    # parse path
    nodes = _safe_parse_path(item.get("path"))
    # clean trailing @
    nodes = [n[:-1] if n.endswith("@") else n for n in nodes]
    if nodes:
        rec["paths"].append({"nodes": nodes, "t_arrive": None, "source": item.get("source"), "reason": item.get("reason")})
    # take max confidence
    try:
        rec["confidence"] = max(float(rec.get("confidence", 0.0)), float(item.get("confidence", 0.0) or 0.0))
    except Exception:
        pass

gt_list = list(gt_records.values())
out_path.write_text(json.dumps(gt_list, ensure_ascii=False, indent=2), encoding="utf-8")

print(f"Wrote unified GT: {out_path} (records={len(gt_list)})")
