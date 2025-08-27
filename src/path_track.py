'''
 # @ Create Time: 2024-09-19 15:12:43
 # @ Modified time: 2024-09-19 15:43:34
 # @ Description: modules to identity vulnerablity propagation paths

 
    Read an already ENRICHED dependency graph (augmented pickle) that contains
      node attrs: release, has_cve, cve_count, cve_list, timestamp (and any others)

    Then:
      - Build a temporal DiGraph using node 'timestamp'
      - Attach edge weights using time lag + optional centrality + optional node scores
      - Find up to K shortest temporal paths from a source to targets
      - Output results and optional GEXF subgraphs

    Inputs:
      --aug-graph  dep_graph_with_cves.pkl   (networkx or dict-like with 'nodes'/'edges')
      --source     node_id
      [--targets   node_id ...]              (optional; default: leaf nodes of temporal graph)
      [--similarity-json sim.json]           (optional; node_id -> similarity score, e.g. from Vamana)
      [--paths-jsonl paths.jsonl]            (optional; write path summaries JSONL)
      [--subgraph-gexf subgraph.gexf]        (optional; union-of-paths subgraph)
      [--tree-gexf tree.gexf]                (optional; arborescence rooted at source)

    We assume nodes ALREADY have:
      - release (str or None), has_cve (bool), cve_count (int), cve_list (list of dicts), timestamp (number)

    Weight model:
      weight(u->v) = alpha * time_lag(u,v) + beta * 1/(centrality[v]+eps) + gamma * 1/(score[v]+eps)
    Where score[v] comes from either:
      - provided similarity-json (node_id -> similarity), optionally blended with severity score
      - OR severity-derived score from node's cve_list/cve_count
      
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import argparse
import json
import pickle
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import networkx as nx
from utils.util import _safe_load_json, _safe_load_pickle, _safe_save_pickle
from utils.util import _detect_graph_nodes_and_edges, to_undirected_graph


# --------- build temporal graph ----------
def build_temporal_digraph(
      G_undirected: nx.Graph,
      strict_increase: bool=False,
      t_start: Optional[float] = None,
      t_end: Optional[float] = None
    ) -> nx.DiGraph:
    ''' build a temporal directed graph (DAG) from an undirected dependency graph
    
    Each node must carry a numeric 'timestamp' attribute. For any undirected
      edge {u, v}, we add directed edges according to timestamps:
    '''
    if t_start is None: t_start = float('-inf')
    if t_end is None: t_end = float('inf')

    # filter nodes by timestamp presence + range
    allowed = []
    for n, d in G_undirected.nodes(data=True):
        if 'timestamp' in d:
            ts = d['timestamp']
            if t_start <= ts <= t_end:
                allowed.append(n)

    D = nx.DiGraph()
    for n in allowed:
        D.add_node(n, **G_undirected.nodes[n])
      
    for u, v in G_undirected.subgraph(allowed).edges():
        tsu = G_undirected.nodes[u].get("timestamp")
        tsv = G_undirected.nodes[v].get('timestamp')

        if tsu is None or tsv is None:
            continue
        if strict_increase:
            if tsu < tsv: D.add_edge(u, v, time_lag = tsv - tsu)
            if tsv < tsu: D.add_edge(v, u, time_lag = tsu - tsv)
        else:
            if tsu <= tsv: D.add_edge(u, v, time_lag = tsv - tsu)
            if tsv <= tsu: D.add_edge(v ,u, time_lag = tsu - tsv)
    
    return D

# ----------------- Scoring -----------------
SEV_WEIGHT = {'CRITICAL':5, 'HIGH':3, 'MODERATE':2, 'MEDIUM':2, 'LOW':1}

def node_severity_score(attrs: Mapping[str, Any]) -> float:
    '''
      Compute a severity-based score for a node from its CVE attributes.

        The score sums weights for each CVE on the node using SEV_WEIGHT,
        then adds a small bonus proportional to the total CVE count.
    '''
    cves = attrs.get('cve_list', [])
    if not cves:
        return 0.0
    score = 0.0
    for c in cves:
        sev = str(c.get('severity', '')).upper()
        score += SEV_WEIGHT.get(sev, 0)
    if score == 0.0:
        score = float(attrs.get('cve_count', 0))
        score += 0.2 * float(attrs.get('cve_count', 0))
    
    return score

def build_node_scores(D: nx.DiGraph,
                      similarity_scores: Optional[Mapping[str, float]] = None,
                      blend_lambda: float = 0.7
                      ) -> Dict[str, float]:
    '''
    calculate the node score combining cve score and similarity score 

    '''
    scores = {}
    for n in D.nodes:
        sev = node_severity_score(D.nodes[n])
        if similarity_scores is not None and n in similarity_scores:
            sim = float(similarity_scores[n])
            scores[n] = blend_lambda * sim + (1-blend_lambda) * sev
        else:
            scores[n] = sev
    return scores

def attach_edge_weights(
        D: nx.DiGraph,
        alpha: float,
        beta: float,
        gamma: float,
        centrality: Optional[Mapping[str, float]] = None,
        node_scores: Optional[Mapping[str, float]] = None,
        eps: float = 1e-6
      ) -> None:
    ''' Compute and attach 'weight' on each edge using the model:
    w(u->v) = alpha * time_lag(u,v) + beta * 1/(centrality[v]+eps) + gamma * 1/(node_scores[v]+eps)

    args:
      D: temporal graph with edge attribute 'time_lag' (float)
      alpha: weight for time lag (larger alpha penalizes long lags more)
      beta: weight for inverse centrality of the target node v
      gamma: weight for inverse node score of v (set 0 to disable). A larger node
        score reduces the penalty, making v more attractive on a path
      centrality: Node centrality scores (e.g., degree_centrality). Required if beta != 0.
      node_scores: node-level scores from severity/similarity, required if gamma !=0
      eps: small constant to avoid division by zero

    '''
    for u, v, d in D.edges(data=True):
        w = alpha * float(d.get('time_lag', 0.0))
        if beta and centrality is not None:
            w += beta * (1.0 / (float(centrality.get(v, 0.0)) + eps))
        if gamma and node_scores is not None:
            w += gamma * (1.0 / (float(node_scores.get(v, 0.0)) + eps))
        d['weight'] = w


# ------------- Paths & summaries ------------

def k_shortest_paths(D: nx.DiGraph, source: str, 
                     targets: Iterable[str], k: int = 3) -> Dict[str, List[List[str]]]:
    '''
    compute up to K shortest simple paths (by 'weight') from source to each target
    
    args:
      D: temporal graph whose edges carry a 'weight' attribute
      source: starting node id
      targets: target node ids to search paths to
      k: number of shortest paths per target to return

    '''
    out: Dict[str, List[List[str]]] = {}
    for t in targets:
        if t == source or t not in D or source not in D:
            continue
        try:
            gen = nx.shortest_simple_paths(D, source, t, weight='weight')
            paths = []
            for i, p in enumerate(gen):
                if i > k: break
                paths.append(p)
            if paths:
                out[t] = paths
        except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass
        return out

def severity_rank(sev: Optional[str]) -> int:
    ''' convert severity string to an integer rank for comparisons
    
    '''
    if not sev: return 0
    return {'LOW':1,'MODERATE':2,'MEDIUM':2,'HIGH':3,'CRITICAL':4}.get(str(sev).upper(), 0)

def summarize_path(D: nx.DiGraph, path: List[str]) -> dict:
    ''' Summarize a path by length, total CVE count on nodes, and maximum severity on nodes.
    
    '''
    total_cves = 0
    max_sev_rank = 0
    for n in path:
        attrs = D.nodes[n]
        total_cves += int(attrs.get('cve_count', 0))
        for c in attrs.get('cve_list', []):
            max_sev_rank = max(max_sev_rank, severity_rank(c.get('severity')))
    max_sev = None
    if max_sev_rank > 0:
        rev = {1:'LOW', 2:'MODERATE', 3:'HIGH', 4:'CRITICAL'}
        max_sev = rev[max_sev_rank]
    return {
        'length': len(path),
        'total_cves': total_cves,
        'max_severity': max_sev
        }

def main():
    
