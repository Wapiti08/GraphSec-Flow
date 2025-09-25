'''
 # @ Create Time: 2025-08-26 10:24:43
 # @ Modified time: 2025-08-26 10:24:45
 # @ Description: 

    Build a CVE-enriched dependency dataset from three inputs:
      1) dep_graph.pkl               — dependency graph (e.g., a NetworkX Graph/DiGraph or a node/edge dict)
      2) aggregated_data.json        — CVE info keyed by 'group:artifact:version' -> list of CVE dicts
      3) graph_nodes_edges.pkl       — original graph nodes/edges or a node catalog that includes nodeId -> 'id' (release name)

    Output:
      - A tabular CSV and/or JSONL with node-level CVE annotations
      - (optional) an augmented graph pickle with CVE attributes attached to nodes

  
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import argparse
import json
import pickle
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union
from pathlib import Path
import pandas as pd
from utils.util import _safe_load_json, _safe_load_pickle, _safe_save_pickle
from utils.util import _as_node_catalog, _detect_graph_nodes_and_edges


# ----------- Data Class ------------
@dataclass
class CVERecord:
    node_id: str
    release: Optional[str]
    has_cve: bool
    cve_count: int
    cve_names: List[str]
    severities: List[str]
    timestamp: Optional[int] = None
    indegree: Optional[int] = None
    outdegree: Optional[int] = None



# ----------- Core Logic ----------------
def build_nodeid_to_release(nodes_edges_obj: Any) -> Dict[str, Optional[str]]:
    nodes = _as_node_catalog(nodes_edges_obj)
    out: Dict[str, Optional[str]] = {}
    for nid, attrs in nodes.items():
        release = None
        if isinstance(attrs, Mapping):
            release = attrs.get('id')
            if release is not None:
                release = str(release)
        out[str(nid)] = release
    return out

def merge_graph_with_cves(
    dep_graph_obj: Any,
    nodeid_to_release: Mapping[str, Optional[str]],
    cve_index: Mapping[str, List[Mapping[str, Any]]], 
    explode: bool = False,
    compute_degrees: bool = True,
    ) -> List[CVERecord]:

    nodes, edges = _detect_graph_nodes_and_edges(dep_graph_obj)

    indeg = {}
    outdeg = {}

    if compute_degrees and edges:
        for u, v in edges:
            outdeg[u] = outdeg.get(u, 0) + 1
            indeg[v] = indeg.get(v, 0) + 1
    
    records: List[CVERecord] = []
    for nid, nattrs in nodes.items():
        release = nodeid_to_release.get(nid)
        ts = None
        if isinstance(nattrs, Mapping):
            ts = nattrs.get('timestamp')
        
        cves = cve_index.get(release, []) if release else []
        cve_names = [str(c.get('name')) for c in cves if isinstance(c, Mapping) and c.get('name') is not None]
        severities = [str(c.get('severity')) for c in cves if isinstance(c, Mapping) and c.get('severity') is not None]

        if explode and cves:
            for c in cves:
                if not isinstance(c, Mapping):
                    continue
                rec = CVERecord(
                    node_id=str(nid),
                    release=release,
                    has_cve=True,
                    cve_count=1,
                    cve_names=[str(c.get('name'))] if c.get('name') is not None else [],
                    severities=[str(c.get('severity'))] if c.get('severity') is not None else [],
                    timestamp=ts,
                    indegree=indeg.get(nid),
                    outdegree=outdeg.get(nid),
                )
                records.append(rec)
        
        else:
            rec = CVERecord(
                node_id=str(nid),
                release=release,
                has_cve=bool(cves),
                cve_count=len(cves),
                cve_names=cve_names,
                severities=severities,
                timestamp=ts,
                indegree=indeg.get(nid),
                outdegree=outdeg.get(nid),
            )
            records.append(rec)

        return records

def records_to_df(records: List[CVERecord]):
    rows = []
    for r in records:
        row = asdict(r)
        # serialize lists for CSV friendliness
        row["cve_names"] = json.dumps(r.cve_names, ensure_ascii=False)
        row['severities'] = json.dumps(r.severities, ensure_ascii=False)
        rows.append(row)
    return pd.DataFrame(rows)


def write_jsonl(records: List[CVERecord], path: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        for r in records:
            f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")


def augment_graph_with_cves(dep_graph_obj: Any, nodeid_to_release: Mapping[str, Optional[str]], cve_index: Mapping[str, List[Mapping[str, Any]]]) -> Any:
    
    nodes, edges = _detect_graph_nodes_and_edges(dep_graph_obj)
    
    try:
        import copy
        graph_copy = copy.deepcopy(dep_graph_obj)
    except Exception:
        graph_copy = dep_graph_obj

    try:
        import networkx as nx  # type: ignore
        if isinstance(graph_copy, nx.Graph) or isinstance(graph_copy, nx.DiGraph):
            for nid in list(graph_copy.nodes):
                release = nodeid_to_release.get(nid)
                cves = cve_index.get(release, []) if release else []
                graph_copy.nodes[nid]['cve_count'] = len(cves)
                graph_copy.nodes[nid]['has_cve'] = bool(cves)
                graph_copy.nodes[nid]['cve_list'] = cves  # passthrough
                graph_copy.nodes[nid]['release'] = release
            return graph_copy
    except Exception:
        pass

    if isinstance(graph_copy, dict) and 'nodes' in graph_copy and isinstance(graph_copy['nodes'], dict):
        for nid, attrs in graph_copy['nodes'].items():
            release = nodeid_to_release.get(nid)
            cves = cve_index.get(release, []) if release else []
            if isinstance(attrs, MutableMapping):
                attrs['cve_count'] = len(cves)
                attrs['has_cve'] = bool(cves)
                attrs['cve_list'] = cves
                attrs['release'] = release
        return graph_copy

    if isinstance(graph_copy, dict):
        for nid, attrs in graph_copy.items():
            if isinstance(attrs, MutableMapping):
                release = nodeid_to_release.get(nid)
                cves = cve_index.get(release, []) if release else []
                attrs['cve_count'] = len(cves)
                attrs['has_cve'] = bool(cves)
                attrs['cve_list'] = cves
                attrs['release'] = release
        return graph_copy

    raise ValueError('Unsupported graph structure for augmentation.')

# ---------------- CLI -----------------

def main():
    p = argparse.ArgumentParser(description='Generate CVE-enriched dependency dataset (full id match, no CWE).')
    p.add_argument('--dep_graph', required=True, help="Path to dep_graph.pkl")
    p.add_argument('--cve_json', required=True, help='Path to aggregated_data.json')
    p.add_argument('--nodes_pkl', required=True, help='Path to graph_nodes_edges.pkl')
    p.add_argument('--out_csv', help='Path to write CSV (optional)')
    p.add_argument('--out_jsonl', help='Path to write JSONL (optional)')
    p.add_argument('--augment_graph', help='Path to write augmented graph pickle (optional)')
    p.add_argument('--explode', action='store_true', help='Explode to one row per CVE')
    args = p.parse_args()

    dep_graph = _safe_load_pickle(Path(args.dep_graph))
    nodes_obj = _safe_load_pickle(Path(args.nodes_pkl))
    cve_index = _safe_load_json(Path(args.cve_json))

    nodeid_to_release = build_nodeid_to_release(nodes_obj)
    records = merge_graph_with_cves(dep_graph, nodeid_to_release, cve_index, explode=args.explode)

    if args.out_csv:
        if pd is None:
            raise RuntimeError('pandas is not installed; cannot write CSV. Install pandas or skip --out-csv.')
        df = records_to_df(records)
        df.to_csv(args.out_csv, index=False)

        if args.out_jsonl:
            write_jsonl(records, args.out_jsonl)

        if args.augment_graph:
            augmented = augment_graph_with_cves(dep_graph, nodeid_to_release, cve_index)
            _safe_save_pickle(augmented, Path(args.augment_graph))

        if not any([args.out_csv, args.out_jsonl, args.augment_graph]):
            for rec in records[:10]:
                print(asdict(rec))

if __name__ == '__main__':
    main()