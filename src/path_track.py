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

def select_auto_source(
    D: nx.DiGraph,
    strategy: str = 'earliest_cve',
    similarity_scores: Optional[Mapping[str, float]] = None
  ) -> Optional[str]:
    ''' pick a source (root cause) automatically according to a strategy
    
    args:
      D: temporal graph with node 'timestamp' and CVE attributes
      strategy: {'earliest','indegree0','earliest_cve','top_sim'}
        - 'earliest': pick node with minimal teimstamp
        - 'indegree0': pick any node with in_degree = 0
        - 'earliest_cve': among nodes with has_cve==True, pick minimal timestamp (default)
        - 'top_sim': pick node with maximum similarity score (requires similarity_scores)
      similarity_score: node similarity scores used when strategy == 'top_sim'
    '''
    # Helper: get timestamp
    def ts(n): return D.nodes[n].get('timestamp')

    candidates = list(D.nodes)

    if not candidates:
        return None
    
    if strategy == "earliest":
        candidates = [n for n in candidates if ts(n) is not None]
        return min(candidates, key= lambda n: ts(n), default=None) if candidates else None
    
    if strategy == "indegree0":
        inds = [n for n in candidates if D.in_degree(n) == 0 and ts(n) is not None]
        if inds:
            return min(inds, key=lambda n: ts(n))
        # fallback to earliest
        return min([n for n in candidates if ts(n) is not None], key=lambda n: ts(n), default=None)

    if strategy == "earliest_cve":
        cve_nodes = [n for n in candidates if D.nodes[n].get('has_cve') and ts(n) is not None]
        if cve_nodes:
            return min(cve_nodes, key=lambda n: ts(n))
        # fallback to earliest
        return min([n for n in candidates if ts(n) is not None], key=lambda n: ts(n), default=None)

    if strategy == "top_sim":
        if not similarity_scores:
            return None
        
        sims = [(n, similarity_scores.get(n, None)) for n in candidates]
        sims = [(n,s) for n, s in sims if s is not None]

        if sims:
            sims.sort(key=lambda x: x[1], reverse=True)
            return sims[0][0]
        return None
  
    return min([n for n in candidates if ts(n) is not None], key=lambda n: ts(n), default=None)


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
    ''' compute propagation paths from an enriched graph

    '''
    ap = argparse.ArgumentParser(description='Propagation paths from an already-enriched dependency graph.')
    ap.add_argument('--aug-graph', required=True, help='Augmented graph pickle with CVE attributes')
    ap.add_argument('--source', help='Root/source node_id (optional if --auto-source is provided)')
    ap.add_argument("--auto-source", choices=['earliest', 'indegree0', 'earliest_cve','top_sim'],
                   default='earliest_cve',
                    help='Auto-select source strategy when --source is not provided (default: earliest_cve)')

    ap.add_argument('--targets', nargs='*', help='Optional explicit target node_ids')
    ap.add_argument('--k', type='int', default=3, help ='Top-k paths per target')
    ap.add_argument('--alpha', type=float, default=1.0, help='Weight for time lag')
    ap.add_argument('--beta', type=float, default=0.0, help='Weight for centrality inverse')
    ap.add_argument('--gamma', type=float, default=1.0, help='Weight for node score inverse')
    ap.add_argument('--blend-lambda', type=float, default=0.7, help='Blend sim vs severity (if similarity-json provided)')
    ap.add_argument('--similarity-json', help='Optional node_id -> similarity score JSON')
    ap.add_argument('--t-start', type=float, help='Timestamp lower bound (inclusive)')
    ap.add_argument('--t-end', type=float, help="Timestamp upper bound (inclusive)")
    ap.add_argument("--strict-increase", action='store_true', help='Require strictly increasing timestamps')
    ap.add_argument("--paths_jsonl", help="Write path summaries to JSONL")
    ap.add_argument('--subgraph-gexf', help='Write union-of-paths subgraph (GEXF)')
    ap.add_argument('--tree-gexf', help='Write arborescence (GEXF)')
    args = ap.parse_args()

    # load graph
    graph_obj = _safe_load_pickle(args.aug_graph)
    nodes, edges = _detect_graph_nodes_and_edges(graph_obj)

    # build undirected then temporal
    G_und = to_undirected_graph(nodes, edges)
    D = build_temporal_digraph(G_und,
                               strict_increase=args.strict_increase,
                               t_start = args.t_start,
                               t_end = args.t_end)
    
    # auto-select source if needed
    sim_scores = _safe_load_json(args.similarity_json) if args.similarity_json else None
    source = args.source
    if not source:
        source = select_auto_source(D, strategy=args.auto_source, similarity_scores=sim_scores)
        if not source:
            raise SystemExit('Failed to auto-select a source node. Please provide --source explicitly.')
        print(f"[auto-source] strategy={args.auto_source} -> source={source}")
    
    if source not in D:
        raise SystemExit(f"Source {source} not in temporal graph (possibly filtered by time range).")

    # target default: leaf nodes
    if args.targets:
        targets = [t for t in args.targets if t in D and t != source]
    else:
        targets = [n for n in D.nodes if D.out_degree(n) == 0 and n != source]

    # optional centrality
    centrality = nx.degree_centrality(D) if args.beta != 0.0 else None

    # Node scores from similarity or severity
    node_scores = build_node_scores(D, similarity_scores=sim_scores, blend_lambda=args.blend_lambda)

    # Attach weights & compute paths
    attach_edge_weights(D, alpha=args.alpha, beta=args.beta, gamma=args.gamma,
                    centrality=centrality, node_scores=node_scores)
    
    paths_by_t = k_shortest_paths(D, source, targets, k=args.k)

    # summaries
    records = []
    for t, paths in paths_by_t.items():
        for i, p in enumerate(paths, 1):
            s = summarize_path(D, p)
            total_w = 0.0
            for u, v in zip(p[:-1], p[1:]):
                total_w += float(D[u][v].get('weight', 0.0))
            rec = {
                'target': t,
                'rank': i,
                'score': total_w,
                'path': p,
                "length": s['length'],
                'total_cves': s['total_cves'],
                'max_severity': s['max_severity']
            }
            records.append(rec)
    
    # Console preview
    if not records:
        print('No paths found within constraints.')
    else:
        records.sort(key=lambda r: (r['target'], r['score']))
        for r in records[:min(len(records), 50)]:
            print(f"target={r['target']} rank={r['rank']} score={r['score']:.3f} length={r['length']} total_cves={r['total_cves']} max_severity={r['max_severity']}\\n  path={' -> '.join(r['path'])}")
    
    # Files
    if args.paths_jsonl:
        _safe_save_json(records, args.paths_jsonl)
      
    if args.subgraph_gexf:
        # Build union-of-paths subgraph
        H = nx.DiGraph()
        for r in records:
            p = r['path']
            for n in p:
                if n not in H:
                    H.add_node(n, **D.nodes[n])
            for u, v in zip(p[:-1], p[1:]):
                if not H.has_edge(u, v):
                    H.add_edge(u, v, **D[u][v])
        nx.write_gexf(H, args.subgraph_gexf)
        
    if args.tree_gexf:
        # compress to a branching (optional)
        H = nx.DiGraph()
        for r in records:
            p = r['path']
            for n in p:
                if n not in H:
                    H.add_node(n, **D.nodes[n])
            for u, v in zip(p[:-1], p[1:]):
                if not H.has_edge(u, v):
                    H.add_edge(u, v, **D[u][v])
        W = nx.DiGraph()
        for n, d in H.nodes(data=True):
            W.add_node(n, **d)
        for u, v, d in H.edges(data=True):
            w = float(d.get('weight', 0.0))
            W.add_edge(u, v, weight=-w)
        try:
            B = nx.maximum_branching(W, preserve_attrs=True)
            reachable = nx.descendants(B, source) | {source}
            T = B.subgraph(reachable).copy()
            nx.write_gexf(T, args.tree_gexf)
        except Exception:
            nx.write_gexf(H, args.tree_gexf)

    if __name__ == '__main__':
        main()


