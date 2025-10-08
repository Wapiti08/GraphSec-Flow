'''
 # @ Create Time: 2024-09-19 15:12:57
 # @ Modified time: 2024-09-19 15:43:24
 # @ Description: module to locate root cause software for vulnerablity
 '''
import sys 
from pathlib import Path 
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from typing import Dict, Iterable, Optional, Tuple,Callable, AnyStr, List, Any, Literal
from search.vamana import VamanaOnCVE, VamanaSearch
from cve.cvevector import CVEVector
from cent.temp_cent import TempCentricity
from com.commdet import TemporalCommDetector
import random
from cve.cveinfo import osv_cve_api 
from cve.cvescore import load_cve_seve_json, node_cve_score_agg, cve_score_dict_gen, _normalize_cve_id
import pickle
from utils.util import _first_nonempty, _synth_text_from_dict, _median
import argparse
import time
from search.sideeval import _hop_distance, _sim_from_dist

Scope = Literal["window", "global", "auto"]

class RootCauseAnalyzer:
    '''
    orchestrates root-cause detection:
    1) Use Vamana to get nearest neighbors to a query vector
    2) Build a temporal subgraph over those candidates
    3) Detect a communities and score them temporally
    4) Choose a representative root node from the top community
    
    The root node is selected by a tie-breaker prioritizing:
      - higher CVE score
      - earlier timestamp
      - higher eigenvector centrality
    '''

    def __init__(
        self,
        vamana: VamanaOnCVE,
        node_cve_scores: Dict[int, float],
        timestamps: Dict[int, float],
        centrality: TempCentricity,
        search_scope: Scope = "auto",
        ) -> None:
        '''
        args:
            timestamps: global mapping of node_id -> timestamp (float)

        '''

        self.vamana = vamana
        self.node_cve_scores = node_cve_scores
        self.timestamps = timestamps
        self.centrality = centrality   
        self.search_scope = search_scope

        self._detector = TemporalCommDetector(
            dep_graph=vamana.dep_graph,
            timestamps=timestamps,
            cve_scores=node_cve_scores,
            centrality_provider=centrality,
        )

    
    def _select_root_node(self, 
                       candidates: List[str],
                       cent_scores: Dict[int, float],
                       scope: str = "auto", # "window", "global", "auto"
                       ):
        '''
        pick a single root node from candidates using _node_rank_key

        args:
            candidates: list/iterable of node ids to consider
            cent_scores: dict of node_id -> centrality score
        '''
        cent_scores = cent_scores or {}
        candidates = list(candidates) if candidates is not None else []

        if not candidates:
            return None

        # optional override scores (adjust 'cve_score' part of the key)
        node_score_override = {}

        if scope == "global" and hasattr(self, "timestamps") and self.timestamps:
            ts_vals = [self.timestamps.get(n) for n in candidates if n in self.timestamps]
            ts_vals = [t for t in ts_vals if t is not None]
            if ts_vals:
                tmin, tmax = min(ts_vals), max(ts_vals)
                span = max(1, tmax - tmin)
                for n in candidates:
                    ts = self.timestamps.get(n)
                    base = self.cve_scores.get(n, 0.0)
                    if ts is not None:
                        early_bonus = 0.1 * (1.0 - (ts - tmin) / span)
                        node_score_override[n] = base + early_bonus
                    else:
                        node_score_override[n] = base

        key_fn = self._node_rank_key(cent_scores, node_score_override or None)

        return max(candidates, key=key_fn)
    
    def compute_comm_scores_and_reps(
        self,
        comm_to_nodes: Dict[int, List[int]],
        cent_scores: Dict[int, float],
        w_cve: float = 1.0,
        w_cent: float = 1.0,
        w_early: float = 0.5,
        ) -> Tuple[Dict[int, float], Dict[int, int]]:
        '''
        compute the community scores and pick up representative nodes
        evidence: community score = sum(CVE) + sum(centrality) - min(timestamp)
        representative node: w_cve*CVE + w_cent*cent + w_early*(-timestamp)

        args:
            comm_to_nodes: mapping of community_id -> list of node_ids
            cent_scores: mapping of node_id -> centrality score
            w_cve, w_cent, w_early: weights for scoring

        '''
        def _comm_score(nodes: Iterable[int]) -> float:
            cve_sum = sum(self.cve_scores.get(n, 0.0) for n in nodes)
            cent_sum = sum(cent_scores.get(n, 0.0) for n in nodes)
            min_ts = min(self.timestamps.get(n, float("inf")) for n in nodes)
            return w_cve * cve_sum + w_cent * cent_sum - w_early * min_ts
    
        def _pick_rep(nodes: Iterable[int]) -> int:
            best, best_s = None, float("-inf")
            for n in nodes:
                ts = self.timestamps.get(n, float("inf"))
                early = -float(ts) if (ts is not None) else 0.0
                s = ( w_cve * self.cve_scores.get(n, 0.0)
                     + w_cent * cent_scores.get(n, 0.0)
                     + w_early * early)
                if s > best_s:
                    best, best_s = n, s
            return best

        comm_scores = {c: _comm_score(nodes) for c, nodes in comm_to_nodes.items()}
        representatives = {c: _pick_rep(nodes) for c, nodes in comm_to_nodes.items()}
        return comm_scores, representatives

    def _node_rank_key(self, 
                       cent_scores: Dict[int, float],
                       node_score_override: Optional[Dict[int, float]] = None):
        node_score_override = node_score_override or {}

        def _key(n: int):
            # priopritize by CVE score, then timestamp, then centrality
            cve_score = node_score_override.get(n, self.cve_scores.get(n, 0.0))
            ts_key = -self.timestamps.get(n, float('inf'))  # earlier is better
            cent = cent_scores.get(n, 0.0)
            return (cve_score, ts_key, cent)

        return _key
    
    def analyze_window(
            self,
            t_s: Optional[float],
            t_e: Optional[float],
            node_whitelist: Optional[Iterable[int]] = None,
            w_cve: float = 1.0,
            w_cent: float = 1.0,
            w_early: float = 0.5,
            return_subgraph: bool = False,
        ) -> Dict[str, object]:
        '''
        simple interface to analyze a fixed time window
        extract temporal subgraph -> compute centrailty -> community detection -> 
                    score communities -> pick root node
        return: {partition, comm_to_nodes, comm_scores, representatives, cent_scores, [subgraph]}
        '''
        if node_whitelist is None:
            node_whitelist = self._detector.dep_graph.nodes()
        
        sub = self._detector.extract_temporal_subgraph(t_s, t_e, node_whitelist)
        if sub.number_of_nodes() == 0:
            out = dict(partition={}, comm_to_nodes={}, comm_scores={}, representatives={}, cent_scores={})
            if return_subgraph: out["subgraph"] = sub
            return out
        
        # compute centrality
        cent_all = self.centrality.eigenvector_centrality(t_s, t_e) or {}
        cent_scores = {n: cent_all.get(n, 0.0) for n in sub.nodes()}

        # louvain
        cres = self._detector.detect_communities(sub)

        # score + representative nodes
        comm_scores, reps = self.compute_comm_scores_and_reps(
            cres.comm_to_nodes, cent_scores, w_cve, w_cent, w_early
            )
        
        out = dict(
            partition=cres.partition,
            comm_to_nodes=cres.comm_to_nodes,
            comm_scores=comm_scores,
            representatives=reps,
            cent_scores=cent_scores,
        )

        if return_subgraph: out["subgraph"] = sub
        return out

    def analyze(
            self,
            query_vector,
            k: int = 10,
            t_s: Optional[float] = None,
            t_e: Optional[float] = None,
            explain: bool=True,
            cve_score_lookup: Optional[Callable[[str],float]] = None, # cve_id -> score
            return_diagnostics: bool=False,
            hop_mode: str="either",
            search_scope: Scope = "auto",
            **kwargs
        ) -> Tuple[Optional[int], Optional[int]]:
        """
        args:
            query_vector: np.ndarray of shape (dim,) or (1, dim)
            k: number of nearest neighbors to retrieve
            t_s, t_e: time window for temporal subgraph (inclusive)
            explain: if True, get per-node CVE explanation from Vamana
            cve_score_lookup: function mapping cve_id -> score
            return_diagnostics: if True, return detailed diagnostics dict
            hop_mode: "either", "forward", "reverse", "undirected" - how to compute hop distance

        Returns:
            (root_comm, root_node) by default.
            If return_diagnostics is True:
                (root_comm, root_node, diagnostics_dict)        
        """
        if "return_disgnostics" in kwargs:  # backward compat
            return_diagnostics = kwargs.pop("return_disgnostics") or return_diagnostics

        # 1) search (with explain)
        t0 = time.perf_counter()
        res = self.vamana.search(query_vector, k=k, return_explanations=explain)
        t1 = time.perf_counter()
        search_time_ms = (int((t1 - t0) * 1000))

        if explain and isinstance(res, tuple):
            neighbors, explanations = res
        else:
            neighbors, explanations = res, None

        # 2) build temporal override scores
        node_score_override: Dict[int, float] = {}
        if explanations and cve_score_lookup:
            for node_id, info in explanations.items():
                cve_id = info.get("best_cve_id")
                if cve_id:
                    try:
                        node_score_override[node_id] = cve_score_lookup(cve_id)
                    except Exception as e:
                        pass

        # 3) scope-aware temporal subgraph
        def _extract_by_scope(scope: Scope):
            if scope == "global":
                return self._detector.extract_temporal_subgraph(None, None, neighbors)
            return self._detector.extract_temporal_subgraph(t_s, t_e, neighbors)
        
        scopes_to_try = ["window"] if search_scope=="window" else \
            ["global"] if search_scope=="global" else \
            ["window", "global"]

        temp_subgraph = None
        used_scope: Scope = "window"
        for sc in scopes_to_try:
            used_scope = sc  # type: ignore
            temp_subgraph = _extract_by_scope(sc)  # type: ignore
            if temp_subgraph is not None and temp_subgraph.number_of_nodes() > 0:
                break
        
        if temp_subgraph is None or temp_subgraph.number_of_nodes() == 0:
            if return_diagnostics:
                return None, None, {
                    "search_time_ms": search_time_ms,
                    "reason": "empty_temporal_subgraph",
                    "scope_tried": scopes_to_try,
                    "window": {"t_s": t_s, "t_e": t_e},
                }
            return None, None
        
        # 4) communities
        comm_res = self._detector.detect_communities(temp_subgraph)
        if not comm_res.comm_to_nodes:
            if return_diagnostics:
                return None, None, {
                    "search_time_ms": search_time_ms,
                    "reason": "no_communities",
                    "used_scope": used_scope,
                }
            
            return None, None

        # 5) score communities
        root_comm, cent_scores = self._detector.choose_root_community(
            comm_to_nodes=comm_res.comm_to_nodes,
            t_s=t_s if used_scope=="window" else None,
            t_e=t_e if used_scope=="window" else None,
        )

        if root_comm is None:
                if return_diagnostics:
                    return None, None, {
                        "search_time_ms": search_time_ms,
                        "reason": "no_root_comm",
                        "used_scope": used_scope,
                    }
                return None, None

        # 6) pick root node (global-aware tie-break optional)
        rank_key = self._node_rank_key(cent_scores)

        def global_aware_key(nid: int):
            base = rank_key(nid)
            if used_scope == "global":
                ts = getattr(self._detector, "timestamp_of", lambda _ : None)(nid)
                if ts is not None:
                    return (base, -float(ts))
            return (base, 0.0)


        cand_nodes = [n for n, c in comm_res.partition.items() if c == root_comm]
        root_node = max(cand_nodes, key=global_aware_key)

        if not return_diagnostics:
            return root_comm, root_node

        # ---- build reliable diagnostics ----
        
        # a) hop distance from each neighbor to the chosen root
        G = getattr(self.vamana, "dep_graph", None)
        graph_hop_to_root = {}
        for nid in neighbors:
            graph_hop_to_root[nid] = _hop_distance(G, nid, root_node, mode=hop_mode)

        diagnostics = {
            "search_time_ms": search_time_ms,
            "graph_hop_to_root": graph_hop_to_root,
            "graph_hop_mode": hop_mode,
            "chosen_root_node": root_node,
            "chosen_root_comm": root_comm,
        }

        if explanations:
            sims: List[float] = []
            ngb_sims: List[Dict[str, Any]] = []
            for nid in neighbors:
                info = explanations.get(nid)
                if not info:
                    continue
                try:
                    best_sim_negdist = float(info.get("best_similarity"))
                except (TypeError, ValueError):
                    continue
                d = -best_sim_negdist
                sim_mapped = 1.0 / (1.0 + d)
                sims.append(sim_mapped)
                ngb_sims.append({
                    "node_id": nid,
                    "similarity": sim_mapped,
                    "best_point_id": info.get("best_point_id"),
                    "best_cve_id": info.get("best_cve_id"),
                    "best_timestamp_ms": info.get("best_timestamp_ms"),
                })

            if sims:
                diagnostics["neighbor_similarities"] = ngb_sims
                diagnostics["similarity_summary"] = {
                    "count": len(sims),
                    "mean": float(sum(sims) / len(sims)),
                    "median": _median(sims),
                    "min": float(min(sims)),
                    "max": float(max(sims)),
                }

        return root_comm, root_node, diagnostics


def main(query_vec = None, search_scope='auto', explain=True, k=15, diag=True, force_rebuild=False):
    # -------------- data path ---------------
    data_dir = Path.cwd().parent.joinpath("data")

    cve_depdata_path       = data_dir.joinpath("dep_graph_cve.pkl")
    cve_agg_data_dict_path = data_dir.joinpath("aggregated_data.json")
    per_cve_scores_path    = data_dir.joinpath("per_cve_scores.pkl")
    node_cve_scores_path   = data_dir.joinpath("node_cve_scores.pkl")
    node_texts_path        = data_dir.joinpath("nodeid_to_texts.pkl")

    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)

    nodes = list(depgraph.nodes)

    # ---------- prepare CVE scores -------------
    if per_cve_scores_path.exists() and not force_rebuild:
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
    if node_cve_scores_path.exists() and not force_rebuild:
        node_cve_scores = pickle.loads(node_cve_scores_path.read_bytes())
        print(f"[cache] Loaded node_cve_scores from {node_cve_scores_path}")
    else:
        node_cve_scores = {
            n: node_cve_score_agg(depgraph, n, per_cve_scores, agg="sum")
            for n in depgraph.nodes()
        }
        node_cve_scores_path.write_bytes(pickle.dumps(node_cve_scores))
        print(f"[build] Saved node_cve_scores -> {node_cve_scores_path}")
    
    # ---------- Timestamps / Models -------------
    try:
        timestamps = {n: float(depgraph.nodes[n]["timestamp"]) for n in nodes}
    except KeyError:
        raise KeyError("depgraph nodes missing 'timestamp' attribute")
    
    centrality = TempCentricity(depgraph, search_scope)
    embedder = CVEVector()

    # ---------- prepare node texts -------------
    if node_texts_path.exists() and not force_rebuild:
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
                text = _first_nonempty(rec, TEXT_KEYS)
                if not text and isinstance(raw, dict):
                    text = _synth_text_from_dict(cid, raw)
                texts.append(text)
            if texts:
                nodeid_to_texts[nid] = texts

        if not nodeid_to_texts:
            raise RuntimeError("No CVE texts found.")
        
        # save to file
        node_texts_path.write_bytes(pickle.dumps(nodeid_to_texts))
        print(f"[build] Saved nodeid_to_texts -> {node_texts_path}")

    # ---------- downstream ----------
    ann = VamanaSearch()
    vamana = VamanaOnCVE(depgraph, nodeid_to_texts, embedder, ann)

    analyzer = RootCauseAnalyzer(
        vamana=vamana,
        cve_scores=node_cve_scores,
        timestamps=timestamps,
        centrality=centrality,
    )
    
    all_ts = sorted(timestamps.values())
    t_s = all_ts[len(all_ts) // 4]
    t_e = all_ts[3 * len(all_ts) // 4]

    def _cve_score_lookup(cve_id: str) -> float:
        return per_cve_scores.get(cve_id, 0.0)

    print("Running RootCauseAnalyzer...")

    root_comm, root_node = analyzer.analyze(
        query_vector=query_vec,
        k=k,
        t_s=t_s,
        t_e=t_e,
        explain=explain,
        cve_score_lookup=_cve_score_lookup,
    )

    if root_comm is None or root_node is None:
        print("No root cause detected in the given window.")
    else:
        nd = depgraph.nodes[root_node]
        print(f"Root community: {root_comm}")
        print(f"Root node: {root_node}")
        print({
            "cve_id": nd.get("cve_id"),
            "cve_score": node_cve_scores[root_node],
            "timestamp": timestamps[root_node],
        })

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run RootCauseAnalyzer on a query vector")
    parser.add_argument("--cve_id", type=str, required=True, help="cve_id to form query vector")
    parser.add_argument("--k", type=int, default=15, help="Number of nearest neighbors")
    parser.add_argument("--scope", choices=["window", "global", "auto"], default="auto", help="Search only in window, globally, or auto")
    parser.add_argument("--diag", type=bool, default=True, help="Whether to return diagnostics")
    parser.add_argument("--explain", type=bool, default=True, help="Whether to explain search results")

    args = parser.parse_args()

    cve_data = osv_cve_api(args.cve_id)
    cvevector = CVEVector()
    emb = cvevector.encode(cve_data["details"]) 

    main(query_vec=emb, k=args.k, search_scope=args.scope, explain = args.explain, diag=args.diag)