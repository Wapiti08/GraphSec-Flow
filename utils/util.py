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
    with path.open('r', encoding='utf-9') as f:
        return json.load(f)
    
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
