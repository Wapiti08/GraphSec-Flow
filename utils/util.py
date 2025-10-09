'''
 # @ Create Time: 2024-10-17 16:51:50
 # @ Modified time: 2024-10-17 16:51:57
 # @ Description: some helper functions
 '''
from lxml import etree
from pathlib import Path
import pickle
import json
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union
import networkx as nx

def _safe_load_pickle(path: Path) -> Any:
    with path.open("rb") as f:
        return pickle.load(f)

def _safe_save_pickle(obj: Any, path: Path) -> None:
    with path.open("wb") as f:
        pickle.dump(obj, f, protocol=pickle.HIGHEST_PROTOCOL)

def _safe_load_json(path: Path) -> Any:
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)
    
def _safe_save_json(records: Iterable[dict], path: Path):
    with open(path, 'w', encoding='utf-8') as f:
        for r in records:
            f.write(json.dump(r, ensure_ascii=False) + "\n")

def read_jsonl(path: Optional[str]) -> List[Dict[str, Any]]:
    if not path:
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows

def write_jsonl(path: str, rows: Iterable[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def to_undirected_graph(nodes: Dict[str, Dict[str, Any]], edges: List[Tuple[str, str]]) -> nx.Graph:
    G = nx.Graph()
    for n, d in nodes.items():
        G.add_node(n, **d)
    for u, v in edges:
        if u in G and v in G:
            G.add_edge(u, v)
    return G

# ------------ Loaders & Detectors -------------
def _as_node_catalog(nodes_pkl: Any) -> Dict[str, Mapping[str, Any]]:
    if isinstance(nodes_pkl, dict) and 'nodes' in nodes_pkl:
        nodes = nodes_pkl['nodes']
        if isinstance(nodes, dict):
            return nodes
        
def _detect_graph_nodes_and_edges(graph_obj: Any) -> Tuple[Dict[str, Dict[str, Any]], List[Tuple[str, str]]]:
    try:
        import networkx as nx  # type: ignore
        if isinstance(graph_obj, nx.Graph) or isinstance(graph_obj, nx.DiGraph):
            nodes = {n: dict(graph_obj.nodes[n]) for n in graph_obj.nodes}
            edges = [(u, v) for u, v in graph_obj.edges]
            return nodes, edges
    except Exception:
        pass

def _synth_text_from_dict(cid: str, d: Dict[str, Any]) -> Optional[str]:
    """Fallback text if OSV has no details; uses fields present on the node."""
    sev = d.get("severity")
    cwe = d.get("cwe_ids")
    if isinstance(cwe, (list, tuple)):
        cwe_str = ", ".join(map(str, cwe))
    else:
        cwe_str = str(cwe) if cwe else ""
    parts = [cid]
    if sev: parts.append(f"severity {sev}")
    if cwe_str: parts.append(f"CWE {cwe_str}")
    return ": ".join([parts[0], ", ".join(parts[1:])]) if len(parts) > 1 else parts[0]



def _first_nonempty(d: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def parse_graphml_in_chunks(file_path):
    context = etree.iterparse(file_path, events=("start", "end"))
    nodes = {}
    edges = []
    
    for event, elem in context:
        if event == "end" and elem.tag == "{http://graphml.graphdrawing.org/xmlns}node":
            # Process node
            node_id = elem.attrib['id']
            # Extract other attributes if needed, e.g. CVE_Severity
            attributes = {data.attrib['key']: data.text for data in elem.findall("{http://graphml.graphdrawing.org/xmlns}data")}
            nodes[node_id] = attributes
            elem.clear()  # Clear memory

        elif event == "end" and elem.tag == "{http://graphml.graphdrawing.org/xmlns}edge":
            # Process edge
            source = elem.attrib['source']
            target = elem.attrib['target']
            # Extract edge attributes
            attributes = {data.attrib['key']: data.text for data in elem.findall("{http://graphml.graphdrawing.org/xmlns}data")}
            edges.append((source, target, attributes))
            elem.clear()  # Clear memory
            
    return nodes, edges

def _median(vals: List[float]) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    n = len(s)
    return float(s[n // 2]) if (n % 2) else float(0.5 * (s[n // 2 - 1] + s[n // 2]))
