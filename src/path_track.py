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
from dataclasses import dataclass
import pickle
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import networkx as nx
from utils.util import _safe_load_json, _safe_load_pickle, _safe_save_json
from utils.util import _detect_graph_nodes_and_edges, to_undirected_graph
from src.root_ana import RootCauseAnalyzer, Scope
from cent.temp_cent import TempCentricity
from cve.cvescore import load_cve_seve_json, cve_score_dict_gen, _normalize_cve_id
from utils.util import _first_nonempty, _synth_text_from_dict, _median
from search.vamana import VamanaOnCVE, VamanaSearch
from cve.cvevector import CVEVector
from cve.cveinfo import osv_cve_api 
from wins.timeline_links import build_interwins_links
from cve.cvescore import load_cve_seve_json, node_cve_score_agg, cve_score_dict_gen, _normalize_cve_id

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
        - 'earliest': pick node with minimal timestamp
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


@dataclass
class PathConfig:
    # temporal & weighting
    t_start: Optional[float] = None
    t_end: Optional[float] = None
    strict_increase: bool = False
    alpha: float = 1.0
    beta: float = 0.0
    gamma: float = 0.0
    blend_lambda: float = 0.7
    k_paths: int = 3
    targets: Optional[List[str]] = None
    similarity_scores: Optional[Mapping[str, float]] = None


class RootCausePathAnalyzer(RootCauseAnalyzer):
    '''
    succeed RootCauseAnalyzer to compute propagation paths:
        1) Root cause identificatoin
        2) Use root cause as source to compute shorted paths to targets
        3) optionally write paths and subgraphs to files
    '''
    def __init__(self,         
                 depgraph: Any,
                vamana: VamanaOnCVE,
                node_cve_scores: Dict[int, float],
                timestamps: Dict[int, float],
                centrality: TempCentricity,
                search_scope: Scope = "auto",):
        
        self.depgraph = depgraph
        # # Explicitly pass in the parent class's required parameters by keyword
        # (do not pass depgraph to super)
        super().__init__(
                    vamana=vamana,
                    node_cve_scores=node_cve_scores,
                    timestamps=timestamps,
                    centrality=centrality,
                    search_scope=search_scope,
                )
        
        self._last_root_node: Optional[str] = None
        self._last_paths: Optional[Dict[str, List[List[str]]]] = None
        self._last_D: Optional[nx.DiGraph] = None

    # --------- build temporal graph ----------
    def build_temporal_digraph(
        self,
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

    # ---------- compute paths based on root cause -----------
    def _compute_paths_from_source(
            self,
            source: str,
            cfg: PathConfig    
        ) -> Tuple[nx.DiGraph, Dict[str, List[List[str]]]]:

        dep = self.depgraph
        # 1) get undirected graph
        if isinstance(dep, nx.Graph):
            G_und = dep if not isinstance(dep, nx.DiGraph) else dep.to_undirected()
        elif isinstance(dep, dict) and "nodes" in dep and "edges" in dep:
            G_und = to_undirected_graph(dep['nodes'], dep['edges'])
        else:
            raise ValueError("Unsupported depgraph format")
    
        # 2) build temporal graph
        D = self.build_temporal_digraph(
                G_und,
                strict_increase=cfg.strict_increase,
                t_start=cfg.t_start,
                t_end=cfg.t_end
            )

        # =========== for debug ===========
        src_in_dep = source in self.depgraph
        src_in_D = source in D
        src_ts = None
        try:
            src_ts = self.depgraph.nodes[source].get("timestamp")
        except Exception:
            pass
        print(f"[debug] source in depgraph? {src_in_dep}, in D? {src_in_D}, timestamp={src_ts}")

        if source not in D:
            # Diagnose
            dep = self.depgraph
            reason = []

            if source not in dep:
                # Try a simple normalization: strip leading 'n' if present and retry
                alt = source[1:] if isinstance(source, str) and source.startswith('n') else None
                if alt is not None and alt in dep:
                    source = alt  # adopt normalized ID
                else:
                    reason.append("source ID not in depgraph")
            if source in dep and source not in D:
                ts = dep.nodes[source].get("timestamp")
                if ts is None:
                    reason.append("source node missing 'timestamp'")
                else:
                    reason.append(f"source timestamp {ts} outside window [{cfg.t_start}, {cfg.t_end}]")

            msg = "; ".join(reason) or "unknown reason"
            print(f"[warn] Skipping root {source}: not present in current temporal window ({msg})")
            # Gracefully skip this source by returning an empty result
            return nx.DiGraph(), {}

        # 3) get target set
        if cfg.targets and len(cfg.targets) > 0:
            targets = [t for t in cfg.targets if t in D and t != source]
        else:
            # choose nodes without outgoing edges (leaf nodes)
            targets = [n for n in D.nodes if D.out_degree(n) == 0 and n != source]
        
        # 4) compute weights
        centrality = nx.degree_centrality(D) if cfg.beta != 0.0 else None
        node_scores = build_node_scores(D, similarity_scores=cfg.similarity_scores, 
                                        blend_lambda=cfg.blend_lambda) if cfg.gamma != 0.0 else None
        attach_edge_weights(D, alpha=cfg.alpha, beta=cfg.beta, gamma=cfg.gamma,
                            centrality=centrality, node_scores=node_scores)
        
        # 5) K shortest paths
        paths_by_t = k_shortest_paths(D, source, targets, k=cfg.k_paths)
        return D, paths_by_t

    # ------- entry point: root cause + path --------
    def analyze_with_paths(
            self,
            k_neighbors: int = 15,
            t_start: Optional[float] = None,
            t_end: Optional[float] = None,
            path_cfg: Optional[PathConfig] = None,
            explain: bool = False,
            source = None,
            ):
        ''' 
        dentify root cause (unless 'source' is provided), then compute propagation paths from it.

        return: (root_comm, root_node, D, paths_by_target, records)
        records: list of path summaries
        '''
        # 1) ------ root cause choice ------------
        if source is not None:
            root_comm = None
            root_node = source
        else:
            root_comm, root_node, _ = self.analyze(
                            query_vector=getattr(self, "query_vector", None),
                            k=int(k_neighbors), 
                            t_start=t_start, t_end=t_end, 
                            explain=explain)
            
        if not root_node:
            return None, None, None, {}, []
        
        # 2) paths
        cfg = path_cfg if path_cfg else PathConfig()
        # align with overall t_start/t_end
        if cfg.t_start is None:
            cfg.t_start = t_start
        if cfg.t_end is None:
            cfg.t_end = t_end

        # --------- if root cause is not in window, return none ----------
        src_ts = None
        try:
            src_ts = self.depgraph.nodes[root_node].get("timestamp")
        except Exception:
            pass

        if src_ts is not None:
            outside_left  = (cfg.t_start is not None and src_ts < cfg.t_start)
            outside_right = (cfg.t_end   is not None and src_ts >= cfg.t_end)
            if outside_left or outside_right:
                # cache blank result, keep interface steady
                self._last_root_node = root_node
                self._last_paths = {}
                self._last_D = None
                return root_comm, root_node, None, {}, []

        # ------- compute path ----------
        try:
            D, paths_by_t = self._compute_paths_from_source(root_node, cfg)
        except ValueError as e:
            print(f"[warn] Skipping root {root_node} due to error: {e}")
            return None, {}

        # 3) generate summaries
        records: List[Dict[str, Any]] = []
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

        # cache latest results for retrieval
        self._last_root_node = root_node
        self._last_paths = paths_by_t
        self._last_D = D

        return root_comm, root_node, D, paths_by_t, records

    def export_jsonl(self, records: List[Dict[str, Any]], filepath: str) -> None:
        ''' write path summaries to JSONL file '''
        import json
        with open(filepath, 'w', encoding="utf-8") as f:
            for r in sorted(records, key=lambda r: (r['target'], r['score'])):
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        
    def export_subgraph_gexf(self, out_path: str):
        if self._last_D is None or self._last_paths is None:
            raise RuntimeError("No computed paths available to export.")
    
        H = nx.DiGraph()
        # union-of-paths
        for paths in self._last_paths.values():
            for p in paths:
                for n in p:
                    if n not in H:
                        H.add_node(n, **self._last_D.nodes[n])
                for u, v in zip(p[:-1], p[1:]):
                    if not H.has_edge(u, v):
                        H.add_edge(u, v, **self._last_D[u][v])
        nx.write_gexf(H, out_path)

    def interwindow_links(self, windows, window_results):
        return build_interwins_links(self.depgraph, self.timestamps, windows, window_results)

def main():
    ''' 
    Unified entry:
      - If --source is provided: compute paths from explicit source.
      - Else: run RootCause analysis first, then compute propagation paths from the root.
    '''
    ap = argparse.ArgumentParser(description='Propagation paths from an already-enriched dependency graph.')
    # ---- I/O ----
    ap.add_argument('--aug_graph', required=True, help='Augmented graph pickle with CVE attributes')
    ap.add_argument('--similarity_json', default=None, help='Optional node_id -> similarity score JSON')
    ap.add_argument("--paths_jsonl", help="Write path summaries to JSONL")
    ap.add_argument('--subgraph_gexf', help='Write union-of-paths subgraph (GEXF)')

    # ----- Time Window (shared) ------
    ap.add_argument('--t_start', type=float, help='Timestamp lower bound (inclusive)')
    ap.add_argument('--t_end', type=float, help="Timestamp upper bound (inclusive)")
    ap.add_argument("--strict_increase", action='store_true', help='Require strictly increasing timestamps')

    # ----- Path Weighting -----
    ap.add_argument('--k_paths', type=int, default=3, help ='Top-k paths per target')
    ap.add_argument('--alpha', type=float, default=5.0, help='Weight for time lag')
    ap.add_argument('--beta', type=float, default=0.0, help='Weight for centrality inverse')
    ap.add_argument('--gamma', type=float, default=0.0, help='Weight for node score inverse')
    ap.add_argument('--blend_lambda', type=float, default=0.7, help='Blend sim vs severity (if similarity-json provided)')

    # ----- Source & Targets -----
    ap.add_argument("--auto_source", choices=['earliest', 'indegree0', 'earliest_cve','top_sim'],
                   default='earliest_cve',
                    help='Auto-select source strategy when --source is not provided (default: earliest_cve)')
    ap.add_argument('--targets', nargs='*', help='Optional explicit target node_ids')

    # ---- Root-cause options ----
    ap.add_argument('--source', help='Root/source node_id (optional if --auto-source is provided)')
    ap.add_argument('--rca_k', type=int, default=15, help='Top-K neighborhood for root cause analysis')
    ap.add_argument('--rca_explain', action='store_true', help='Verbose explain for root cause step')

    args = ap.parse_args()

    # load graph
    graph_obj = _safe_load_pickle(Path(args.aug_graph))
    sim_scores = _safe_load_json(args.similarity_json) if args.similarity_json else None

    # ---- Instantiate analyzer ----
    # load initial parameters

    nodes = list(graph_obj.nodes)

    depgraph = graph_obj if isinstance(graph_obj, nx.Graph) else None

    # ---------- for quick test ------------
    import random

    seeds = []
    max_nodes = 1000
    random.seed(0)

    # 仅考虑带 timestamp 的节点，避免后面再额外删一遍
    candidates = [n for n, a in depgraph.nodes(data=True) if "timestamp" in a]

    # 从参数里收集种子
    if getattr(args, "source", None) and args.source in depgraph and "timestamp" in depgraph.nodes[args.source]:
        seeds.append(args.source)

    if getattr(args, "targets", None):
        seeds.extend([t for t in args.targets if t in depgraph and "timestamp" in depgraph.nodes[t]])

    keep = set(seeds)

    # 如果没给 source/targets，则回退到合理的默认集合
    if not keep:
        if len(candidates) == 0:
            raise ValueError("Graph has no nodes with 'timestamp'; nothing to keep.")
        if depgraph.number_of_nodes() > max_nodes:
            keep.update(random.sample(candidates, min(max_nodes, len(candidates))))
        else:
            keep.update(candidates)

    # 如果给了 seeds，但图很大，也可以在 seeds 的基础上补一些节点（可选）
    elif depgraph.number_of_nodes() > max_nodes and len(keep) < max_nodes:
        pool = [n for n in candidates if n not in keep]
        need = max_nodes - len(keep)
        if pool:
            keep.update(random.sample(pool, min(len(pool), need)))

    # 用 keep 来收缩图（不要再用 seeds）
    depgraph = depgraph.subgraph(keep).copy()

    # 刷新 nodes
    nodes = list(depgraph.nodes())

    # 保险：再清掉任何意外缺少 timestamp 的节点
    missing_ts = [n for n, a in depgraph.nodes(data=True) if "timestamp" not in a]
    if missing_ts:
        depgraph.remove_nodes_from(missing_ts)
        nodes = [n for n in nodes if n not in missing_ts]

    # ---------------------------------------------------------

    unique_cve_ids = {
        cid for _, attrs in depgraph.nodes(data=True) 
        for cid in ([_normalize_cve_id(x) for x in (attrs.get("cve_list") or [])])
        if cid
    }

    # ------------ define data path -----------------
    data_dir = Path.cwd().parent.joinpath("data")

    cve_agg_data_dict_path = Path.cwd().parent.joinpath("data", "aggregated_data.json")
    cve_agg_data_dict = load_cve_seve_json(cve_agg_data_dict_path)

    node_cve_scores_path   = data_dir.joinpath("node_cve_scores.pkl")
    per_cve_scores_path    = data_dir.joinpath("per_cve_scores.pkl")
    node_texts_path        = data_dir.joinpath("nodeid_to_texts.pkl")

    # ---------- prepare CVE scores -------------
    if per_cve_scores_path.exists():
        per_cve_scores = pickle.loads(per_cve_scores_path.read_bytes())
        print(f"[cache] Loaded per_cve_scores from {per_cve_scores_path}")
    else:
        unique_cve_ids = {
            cid for _, attrs in depgraph.nodes(data=True) 
            for cid in ([_normalize_cve_id(x) for x in (attrs.get("cve_list") or [])])
            if cid
        }

        cve_agg_data_dict = load_cve_seve_json(cve_agg_data_dict_path)
        # generate mapping from cve_id -> score
        per_cve_scores = cve_score_dict_gen(unique_cve_ids, cve_agg_data_dict)
        per_cve_scores_path.write_bytes(pickle.dumps(per_cve_scores))
        print(f"[build] Saved per_cve_scores -> {per_cve_scores_path}")

    # ---------- prepare node CVE scores -------------
    if node_cve_scores_path.exists():
        node_cve_scores = pickle.loads(node_cve_scores_path.read_bytes())
        print(f"[cache] Loaded node_cve_scores from {node_cve_scores_path}")
    else:
        node_cve_scores = {
            n: node_cve_score_agg(depgraph, n, per_cve_scores, agg="sum")
            for n in depgraph.nodes()
        }
        node_cve_scores_path.write_bytes(pickle.dumps(node_cve_scores))
        print(f"[build] Saved node_cve_scores -> {node_cve_scores_path}")
    
    try:
        timestamps = {n: float(depgraph.nodes[n]["timestamp"]) for n in nodes}
    except KeyError:
        raise KeyError("depgraph nodes missing 'timestamp' attribute")
    
    centrality = TempCentricity(depgraph, "auto")
    embedder = CVEVector()

    # ---------- prepare node texts -------------
    if node_texts_path.exists():
        nodeid_to_texts = pickle.loads(node_texts_path.read_bytes())
        print(f"[cache] Loaded nodeid_to_texts from {node_texts_path}")
    else:
        nodeid_to_texts: Dict[Any, List[str]] = {}
        TEXT_KEYS = ["details", "summary", "description"]

        for nid, attrs in depgraph.nodes(data=True):
            raw_list = attrs.get("cve_list", []) or []
            texts = []
            for raw in raw_list:
                cid = _normalize_cve_id(raw)
                try:
                    rec = osv_cve_api(cid) or {}
                except Exception as e:
                    rec = {"_error": str(e)}
                
                if "source" in rec:
                    rec = rec["data"]

                text = _first_nonempty(rec, TEXT_KEYS)
                if not text and isinstance(raw, dict):
                    text = _synth_text_from_dict(cid, raw)
                texts.append(text)
            if texts:
                nodeid_to_texts[nid] = texts

        if not nodeid_to_texts:
            raise RuntimeError("No CVE texts found.")
    
    # ---------- downstream ----------

    ann = VamanaSearch()
    vamana = VamanaOnCVE(depgraph, nodeid_to_texts, embedder, ann)
    rcp = RootCausePathAnalyzer(
                            depgraph=graph_obj, 
                            vamana = vamana,
                            node_cve_scores=node_cve_scores,
                            timestamps=timestamps,
                            centrality=centrality,
                            search_scope="auto")

    # ----- Build Path Config -----
    path_cfg = PathConfig(
        t_start=args.t_start,
        t_end=args.t_end,
        strict_increase=bool(args.strict_increase),
        alpha=float(args.alpha),
        beta=float(args.beta),
        gamma=float(args.gamma),
        blend_lambda=float(args.blend_lambda),
        k_paths=int(args.k_paths),
        targets=args.targets if args.targets else None,
        similarity_scores=sim_scores
    )

    # auto-select source if needed

    root_comm, root_node, D, paths_by_t, records = None, None, None, {}, []
    
    source = args.source
    if source:
        # explicit source mode
        result = rcp.analyze_with_paths(
            k_neighbors=int(args.rca_k),
            t_start=args.t_start,
            t_end=args.t_end,
            path_cfg=path_cfg,
            explain=bool(args.rca_explain),
            source = source
        )

        if not result:
            print(f"[warn] No paths found (explicit source={source}).")
            root_comm, root_node, D, paths_by_t, records = None, source, None, {}, []
        else:
            root_comm, root_node, D, paths_by_t, records = result

    # ---------- Console Preview -----------
    if not records:
        print('No paths found within constraints.')
    else:
        records.sort(key=lambda r: (r['target'], r['score']))
        limit = min(len(records), 50)
        print(f"[root] source={root_node} (community={root_comm})" if root_node else "[root] source=<explicit>")
        for r in records[:limit]:
            print(
                f"target={r['target']} rank={r['rank']} score={r['score']:.3f} "
                f"length={r['length']} total_cves={r['total_cves']} max_severity={r['max_severity']}\n"
                f"  path={' -> '.join(r['path'])}"
            )

    # ------- Export ------------
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
        

if __name__ == '__main__':
    main()


