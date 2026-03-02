'''
 # @ Create Time: 2025-10-02 17:32:12
 # @ Modified time: 2025-10-02 17:32:13
 # @ Description: OPTIMIZED benchmark for different component settng ups
 # @ Optimizations:
 #   - Caching repeated computations
 #   - Vectorized operations with numpy
 #   - Reduced sorting/searching overhead
 #   - Pre-computed data structures
 #   - Optional multiprocessing support
 '''
import json
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import time
from eval.evaluation import _pick_total
# ------ import core modules ------
# from cent.temp_cent import TempCentricity
from cent.temp_cent_fast import TempCentricityOptimized
from com.commdet import TemporalCommDetector
from src.path_track import PathConfig, RootCausePathAnalyzer
from search.vamana import VamanaSearch, CVEVector, VamanaOnCVE
from cve.graph_cve import extract_cve_subgraph
from collections import defaultdict

# ------- import helper functions -------
from eval.evaluation import _zscore, _rank_metrics, _lead_time, _pick_total
from eval.events import build_events_from_vamana_meta
import pickle
from cve.cvescore import _normalize_cve_id
from utils.util import _first_nonempty, _synth_text_from_dict
from typing import Dict, List, Tuple, Optional, Any
from cve.cveinfo import osv_cve_api
from eval.events import _first_cve_data_of_node, _last_cve_data_of_node, _to_same_type, _to_float_time
from datetime import datetime, timedelta
import pandas as pd
from bench.helper import load_cached_scores, _safe_node_timestamps, _mask_or_fill, _f1_from_paths, path_f1_partial_match
import bisect
import argparse
import random
import os
import numpy as np
from bench.helper import _root_rank, _precision_at_k, _community_purity, _community_coverage, _edge_coverage
from bench.helper import avg, convert_edges_to_seq, build_root_to_nodepaths

# ============= NEW: Multiprocessing support =============
from multiprocessing import Pool, cpu_count
from functools import partial

os.environ["PYTHONHASHSEED"] = "0"  
random.seed(0)
np.random.seed(0)
try:
    import torch
    torch.manual_seed(0)
    torch.cuda.manual_seed_all(0)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
except ImportError:
    pass


def parse_ref_paths(ground_truth):
    """
    ground_truth: list from ref_paths JSONL
    returns:
        gt_paths_by_root: dict[root_id → list of GT paths]
        gt_root_by_cve:   dict[cve_id → root_id]
        gt_paths_by_cve:  dict[cve_id → list of GT paths]
    """

    gt_paths_by_root = defaultdict(list)
    gt_root_by_cve = {}
    gt_paths_by_cve = defaultdict(list)

    for item in ground_truth:
        cve = item.get("cve_id")
        rid = item.get("root_id")
        edges = item.get("path", [])

        if not cve or not rid:
            continue

        gt_root_by_cve[cve] = rid

        if edges:
            gt_paths_by_root[rid].append(edges)

        if edges:
            gt_paths_by_cve[cve].append(edges)

    return gt_paths_by_root, gt_root_by_cve, gt_paths_by_cve


# ============= OPTIMIZATION 1: Cached scoring and ranking =============
class ScoreCache:
    """Cache for expensive score computations"""
    def __init__(self):
        self.cache = {}
        self.sorted_cache = {}
    
    def get_or_compute(self, key, compute_fn):
        if key not in self.cache:
            self.cache[key] = compute_fn()
        return self.cache[key]
    
    def get_sorted(self, scores):
        """Return sorted nodes by score (cached)"""
        scores_tuple = tuple(sorted(scores.items()))
        if scores_tuple not in self.sorted_cache:
            self.sorted_cache[scores_tuple] = sorted(scores, key=lambda x: scores[x], reverse=True)
        return self.sorted_cache[scores_tuple]


# ============= OPTIMIZATION 2: Vectorized root ranking =============
def batch_root_rank(scores_dict, root_ids):
    """
    Compute ranks for multiple roots at once
    Returns: dict[root_id -> rank]
    """
    if not scores_dict:
        return {}
    
    # Sort once
    sorted_nodes = sorted(scores_dict.items(), key=lambda x: x[1], reverse=True)
    node_to_rank = {node: idx + 1 for idx, (node, _) in enumerate(sorted_nodes)}
    
    # Batch lookup
    return {rid: node_to_rank.get(rid) for rid in root_ids if rid in node_to_rank}


# ============= OPTIMIZATION 3: Event matching with binary search =============
def build_event_index(events, window_size_ms):
    """Build index for fast event lookup"""
    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda e: e["t"])
    timestamps = np.array([e["t"] for e in sorted_events])
    return sorted_events, timestamps


def find_matching_event(t_eval, sorted_events, timestamps, window_size_ms):
    """Fast event lookup using binary search"""
    # Find closest event within window
    idx = np.searchsorted(timestamps, t_eval)
    
    # Check nearby events
    for i in range(max(0, idx-2), min(len(sorted_events), idx+3)):
        if abs(sorted_events[i]["t"] - t_eval) < window_size_ms:
            return sorted_events[i]
    return None


# ============= OPTIMIZATION 4: Optimized centrality benchmark =============
def benchmark_centrality(tempcent: TempCentricityOptimized, 
                         events, window_iter, gt_root_ids, window_size=10, k_precision=5
):
    '''
    OPTIMIZED VERSION with:
    - Cached computations
    - Vectorized root ranking
    - Pre-allocated arrays
    - Reduced redundant operations
    '''
    
    # Pre-process events (convert timestamps once)
    for ev in events:
        if ev["t"] < 1e11:
            ev["t"] *= 1000.0
    
    # Build event index for fast lookup
    window_size_ms = window_size * 86400000.0
    sorted_events, event_timestamps = build_event_index(events, window_size_ms)
    
    # Convert gt_root_ids to set for O(1) lookup
    gt_root_set = set(gt_root_ids)
    
    variants = {
        "Static-DC": lambda: _pick_total(tempcent.static_degree()),
        "Static-EVC": lambda: tempcent.static_eigen(),
        "Temporal-DC": None,
        "Temporal-EVC": None,
    }

    results = {}
    
    # Pre-allocate top-k set for precision calculation
    def compute_metrics_for_window(norm, t_eval, gt_root_set, k_precision):
        """Compute all metrics for a single window"""
        # Sort once and cache
        sorted_nodes = sorted(norm.items(), key=lambda x: x[1], reverse=True)
        top_k_nodes = set(node for node, _ in sorted_nodes[:k_precision])
        node_to_rank = {node: idx + 1 for idx, (node, _) in enumerate(sorted_nodes)}
        
        # Find matching event
        ev = find_matching_event(t_eval, sorted_events, event_timestamps, window_size_ms)
        
        # Compute event metrics
        mrr, h3 = (None, None)
        if ev:
            mrr, h3 = _rank_metrics(norm, ev["targets"])
        
        # Batch compute root metrics
        root_metrics = []
        for rid in gt_root_set:
            if rid in norm:
                rr = node_to_rank.get(rid)
                if rr:
                    prec = 1.0 if rid in top_k_nodes else 0.0
                    rmrr, _ = _rank_metrics(norm, {rid})
                    root_metrics.append((rr, prec, rmrr))
        
        return mrr, h3, root_metrics

    # Static centrality variants
    for name in ["Static-DC", "Static-EVC"]:
        print(f"[benchmark] Running {name}...")
        latencies = []
        mrrs, h3s = [], []
        root_ranks, precs, root_mrrs = [], [], []
        series_scores = []

        for (t_s, t_e, t_eval) in window_iter():
            if isinstance(t_eval, datetime):
                t_eval = t_eval.timestamp() * 1000.0

            tic = time.perf_counter()
            raw = variants[name]()
            latencies.append((time.perf_counter() - tic) * 1000.0)
            
            norm = _zscore(raw)
            series_scores.append((t_eval, norm))
            
            # Compute all metrics for this window
            mrr, h3, rmetrics = compute_metrics_for_window(norm, t_eval, gt_root_set, k_precision)
            
            if mrr is not None:
                mrrs.append(mrr)
                h3s.append(h3)
            
            # Unpack root metrics
            for rr, prec, rmrr in rmetrics:
                root_ranks.append(rr)
                precs.append(prec)
                root_mrrs.append(rmrr)

        results[name] = {
            "MRR": avg(mrrs),
            "Hits@3": avg(h3s),
            "LeadTime(days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency(ms)": avg(latencies),
            "RootRank": avg(root_ranks),
            f"Precision@{k_precision}": avg(precs),
            "RootMRR": avg(root_mrrs),
        }
        print(f"[benchmark] {name} completed: {results[name]['Latency(ms)']:.2f}ms avg")

    # Dynamic centrality
    for name, fn in [
        ("Temporal-DC", lambda t_s, t_e: _pick_total(tempcent.degree_centrality(t_s, t_e))),
        ("Temporal-EVC", lambda t_s, t_e: tempcent.eigenvector_centrality_sparse(t_s, t_e)[0]),
    ]:
        print(f"[benchmark] Running {name}...")
        latencies = []
        mrrs, h3s = [], []
        root_ranks, precs, root_mrrs = [], [], []
        series_scores = []

        for (t_s, t_e, t_eval) in window_iter():
            tic = time.perf_counter()
            raw = fn(t_s, t_e)
            latencies.append((time.perf_counter() - tic) * 1000.0)
            norm = _zscore(raw)
            series_scores.append((t_eval, norm))

            # Compute all metrics for this window
            mrr, h3, rmetrics = compute_metrics_for_window(norm, t_eval, gt_root_set, k_precision)
            
            if mrr is not None:
                mrrs.append(mrr)
                h3s.append(h3)
            
            for rr, prec, rmrr in rmetrics:
                root_ranks.append(rr)
                precs.append(prec)
                root_mrrs.append(rmrr)

        results[name] = {
            "MRR": avg(mrrs),
            "Hits@3": avg(h3s),
            "LeadTime(days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency(ms)": avg(latencies),
            "RootRank": avg(root_ranks),
            f"Precision@{k_precision}": avg(precs),
            "RootMRR": avg(root_mrrs),
        }
        print(f"[benchmark] {name} completed: {results[name]['Latency(ms)']:.2f}ms avg")

    return results


# ============= OPTIMIZATION 5: Optimized community benchmark =============
def benchmark_community(depgraph,
        temcent,
        node_cve_scores,
        events,
        window_iter,
        gt_root_ids, 
        window_size=10
    ):
    '''
    OPTIMIZED version with:
    - Cached sorted nodes
    - Pre-computed event index
    - Reduced redundant operations
    '''
    timestamps = _safe_node_timestamps(depgraph)
    
    # initialize community detector
    tcd = TemporalCommDetector(
        dep_graph = depgraph,
        timestamps=timestamps,
        cve_scores=node_cve_scores,
        centrality_provider=temcent,
    )

    latencies = []
    hit_list, cov_list, purity_list = [], [], []
    root_rank_list = []
    mrrs, h3s = [], []
    series_scores = []
    
    # unify event timestamps (seconds → ms)
    for ev in events:
        if ev["t"] < 1e11:
            ev["t"] *= 1000.0
    
    # Build event index for fast lookup
    window_size_ms = window_size * 86400000.0
    sorted_events, event_timestamps = build_event_index(events, window_size_ms)
    
    # Convert gt_root_ids to set for O(1) lookup
    gt_root_set = set(gt_root_ids)

    commres = tcd.detect_communities(depgraph)

    # Window adjustments: use a larger time window for better sample size
    for (t_s, t_e, t_eval) in window_iter():
        if isinstance(t_eval, datetime):
            t_eval = t_eval.timestamp() * 1000.0

        tic = time.perf_counter()

        best_comm, cent_scores = tcd.choose_root_community(commres.comm_to_nodes, t_s, t_e)
        latencies.append((time.perf_counter() - tic) * 1000.0)

        if not commres or best_comm is None:
            continue

        # return the nodes in the best community
        comm_nodes = set(commres.comm_to_nodes[best_comm])
        
        # ----- community metrics -----
        ev = find_matching_event(t_eval, sorted_events, event_timestamps, window_size_ms)
        if ev:
            mrr, h3 = _rank_metrics(_zscore(cent_scores), ev["targets"])
            mrrs.append(mrr)
            h3s.append(h3)

        # OPTIMIZATION: Pre-compute sorted nodes once per window
        sorted_cent_nodes = None
        
        # GT roots coverage / purity
        for rid in gt_root_set:
            if rid not in depgraph:
                continue
        
            # hit
            hit_list.append(1.0 if rid in comm_nodes else 0.0)

            # 1-hop neighborhood
            neigh = set(depgraph.neighbors(rid)) | {rid}
            cov_list.append(len(neigh & comm_nodes)/len(neigh))
            purity_list.append(len(neigh & comm_nodes)/len(comm_nodes))

            # rank inside community - OPTIMIZED: sort only once
            if rid in cent_scores:
                if sorted_cent_nodes is None:
                    sorted_cent_nodes = sorted(cent_scores, key=lambda x: cent_scores[x], reverse=True)
                root_rank_list.append(sorted_cent_nodes.index(rid)+1)

        # for LeadTime
        norm = _zscore(cent_scores)
        series_scores.append((t_eval, norm))

    return {
        "Community": {
            "MRR": avg(mrrs),
            "Hits@3": avg(h3s),
            "LeadTime(days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency(ms)": avg(latencies),

            # GT root metrics
            "Hit-Root": avg(hit_list),
            "RootCoverage": avg(cov_list),
            "RootPurity": avg(purity_list),
            "RootRankInComm": avg(root_rank_list),
        }
    }


# ============= OPTIMIZATION 6: Optimized graph construction =============
def build_optimized_subgraph(depgraph, gt_layer):
    """
    Build subgraph more efficiently using set operations
    """
    print("\n=== Building Optimized Subgraph ===")
    
    # 1) Collect GT nodes
    gt_required_nodes = set()
    if gt_layer:
        for item in gt_layer:
            for e in item.get("path", []):
                gt_required_nodes.add(e["src"])
                gt_required_nodes.add(e["dst"])
    
    print(f"[info] GT requires {len(gt_required_nodes)} nodes")
    
    # 2) Check missing nodes
    missing = gt_required_nodes - set(depgraph.nodes())
    if missing:
        print(f"[WARN] {len(missing)} GT nodes missing")
    else:
        print("[info] All GT path nodes exist")
    
    # 3-5) Collect neighbors efficiently
    keep = set(gt_required_nodes)
    
    # Use NetworkX's built-in methods for multi-hop neighbors
    for hop in range(1, 4):  # 1-hop, 2-hop, 3-hop
        new_neighbors = set()
        for n in list(keep):  # iterate over copy
            if n in depgraph:
                new_neighbors.update(depgraph.predecessors(n))
                new_neighbors.update(depgraph.successors(n))
        keep.update(new_neighbors)
        print(f"[info] After {hop}-hop: {len(keep)} total nodes")
    
    # 6) Build subgraph
    depgraph = depgraph.subgraph(keep).copy()
    print(f"[debug] Final subgraph: {depgraph.number_of_nodes()} nodes, "
          f"{depgraph.number_of_edges()} edges")
    
    # 7) Debug coverage
    overlap = len(gt_required_nodes & set(depgraph.nodes()))
    if gt_required_nodes:
        print(f"[debug] GT node retention: {overlap}/{len(gt_required_nodes)} "
              f"({overlap/len(gt_required_nodes):.4f})")
    
    print("=== Subgraph Ready ===\n")
    return depgraph


# ============= OPTIMIZATION 7: Parallel window processing (optional) =============
def process_window_parallel(args):
    """Process a single window - designed for multiprocessing"""
    window_data, fn, gt_root_set, k_precision = args
    t_s, t_e, t_eval = window_data
    
    tic = time.perf_counter()
    raw = fn(t_s, t_e)
    latency = (time.perf_counter() - tic) * 1000.0
    
    norm = _zscore(raw)
    
    # Return processed results
    return {
        'latency': latency,
        'scores': norm,
        't_eval': t_eval
    }


    return depgraph


# ============= Helper function: pick_root_in_window =============
def pick_root_in_window(cands_sorted, t_s_ms, t_e_ms):
    '''Return the first candidate whose timestamp lies inside the window'''
    i = bisect.bisect_left(cands_sorted, (t_s_ms, ""))
    j = bisect.bisect_right(cands_sorted, (t_e_ms, "zzzz"))
    if i < j:
        # choose the first root actually within window
        return cands_sorted[i][1]
    return None


# ============= OPTIMIZATION 8: Optimized benchmark_paths =============
def benchmark_paths(
        depgraph,
        tempcent,
        node_cve_scores: Dict[Any, float],
        nodeid_to_texts: Dict[Any, List[str]],
        events: List[Dict[str, Any]],
        window_iter,
        gt_root_ids,
        gt_paths_by_root, 
        *,
        k_neighbors: int = 15,
        alpha: float = 1.0,
        beta: float = 0.0,
        gamma: float = 0.0,
        k_paths: int = 5,
        strict_increase: bool=False,
        candidates: list=None,
        window_size: int=10,
    ):
    '''
    OPTIMIZED Path tracking benchmark using TRUE GT paths from ref_paths.
    '''

    # =======================================================
    # (0) --- Convert GT edges → GT node sequences ---------
    # =======================================================
    root_to_nodepaths = defaultdict(list)

    for rid, edge_lists in gt_paths_by_root.items():
        for edges in edge_lists:
            node_seq = []
            for e in edges:
                if not node_seq:
                    node_seq.append(e["src"])
                node_seq.append(e["dst"])
            root_to_nodepaths[rid].append(node_seq)

    print(f"[GT] Loaded {sum(len(v) for v in root_to_nodepaths.values())} "
          f"GT node paths from {len(root_to_nodepaths)} roots.")

    # =======================================================
    # (2) --- Initialize analyzers ---
    # =======================================================
    timestamps = _safe_node_timestamps(depgraph)
    # initialize path tracker
    embedder = CVEVector()
    ann = VamanaSearch()
    vamana = VamanaOnCVE(depgraph, nodeid_to_texts, embedder, ann)

    analyzer = RootCausePathAnalyzer(
        depgraph = depgraph,
        vamana = vamana,
        node_cve_scores = node_cve_scores,
        timestamps = timestamps,
        centrality=tempcent,
        search_scope="auto"
    )
    # prepare GT node paths
    root_to_nodepaths = build_root_to_nodepaths(gt_paths_by_root)

    latencies = []
    f1_j_list, f1_gr_list, edgecov_list, predcount_list = [], [], [], []
    
    # Convert gt_root_ids to set for faster membership testing
    gt_root_set = set(gt_root_ids)

    for (t_s, t_e, t_eval) in window_iter():
        tic = time.perf_counter()

        # pick predicted root
        root_node = pick_root_in_window(candidates, int(t_s), int(t_e))
        if root_node is None:
            latencies.append((time.perf_counter()-tic)*1000)
            continue

        pcfg = PathConfig(
            t_start= t_s,
            t_end= t_e,
            strict_increase=strict_increase,
            alpha=alpha, beta=beta, gamma=gamma,
            k_paths=k_paths,
            targets=None,
            similarity_scores=None,
        )

        # run analysis
        _, _, _, paths_by_target, _ = analyzer.analyze_with_paths(
            k_neighbors=k_neighbors,
            t_start=pcfg.t_start,
            t_end=pcfg.t_end,
            path_cfg=pcfg,
            explain=False,
            source=root_node,
        )

        latencies.append((time.perf_counter()-tic)*1000)

        if not paths_by_target:
            continue

        predicted_paths = [p for ps in paths_by_target.values() for p in ps]
        predcount_list.append(len(predicted_paths))

        # compute vs ALL GT roots (OPTIMIZED: use set for faster iteration)
        node_gt_paths = []
        for rid in gt_root_set:
            node_gt_paths.extend(root_to_nodepaths.get(rid, []))

        if node_gt_paths:
            f1_j = path_f1_partial_match(node_gt_paths, predicted_paths, overlap_thresh=0.5, mode="jaccard")
            f1_gr = path_f1_partial_match(node_gt_paths, predicted_paths, overlap_thresh=0.5, mode="gt_recall")
            ec = _edge_coverage(node_gt_paths, predicted_paths)
        else:
            f1_j = f1_gr = ec = 0.0

        f1_j_list.append(f1_j)
        f1_gr_list.append(f1_gr)
        edgecov_list.append(ec)

    return {
        "Path": {
            "Path-F1(Jaccard)": avg(f1_j_list),
            "Path-F1(GT-Recall)": avg(f1_gr_list),
            "EdgeCoverage": avg(edgecov_list),
            "PredictedPathCount": avg(predcount_list),
            "Latency(ms)": avg(latencies),
        }
    }


# ============= OPTIMIZATION 9: Optimized benchmark_full =============
def benchmark_full(
    depgraph,
    tempcent,
    node_cve_scores: Dict[Any, float],
    nodeid_to_texts: Dict[Any, List[str]],
    events: List[Dict[str, Any]],
    window_iter,
    gt_root_ids,
    gt_paths_by_root,
    *,
    k_neighbors: int = 15,
    alpha: float = 1.0,
    beta: float = 0.0,
    gamma: float = 0.0,
    k_paths: int = 5,
    strict_increase: bool=False,
    fuse_lambda: float = 0.6,
    window_size: int=10,
    ):
    '''
    OPTIMIZED Full benchmark integrating:
        (A) temporal community detection
        (B) root selection inside community
        (C) path search from predicted root
        (D) fusion scoring
    '''

    # ===========================================================
    # 0. Convert GT edges → node sequences for easy matching
    # ===========================================================
    root_to_nodepaths = defaultdict(list)

    for rid, edge_lists in gt_paths_by_root.items():
        for edges in edge_lists:
            seq = []
            for e in edges:
                if not seq:
                    seq.append(e["src"])
                seq.append(e["dst"])
            root_to_nodepaths[rid].append(seq)

    print(f"[GT] Loaded {sum(len(v) for v in root_to_nodepaths.values())} GT node paths "
          f"from {len(root_to_nodepaths)} roots.")
    
    # ===========================================================
    # 1. Initialize analyzers
    # ===========================================================
    timestamps = _safe_node_timestamps(depgraph)

    # A: community detector
    tcd = TemporalCommDetector(
        dep_graph=depgraph,
        timestamps=timestamps,
        cve_scores=node_cve_scores,
        centrality_provider=tempcent,
    )

    # B: path analyzer
    embedder = CVEVector()
    ann = VamanaSearch()
    vamana = VamanaOnCVE(depgraph, nodeid_to_texts, embedder, ann)
    analyzer = RootCausePathAnalyzer(
        depgraph=depgraph,
        vamana=vamana,
        node_cve_scores=node_cve_scores,
        timestamps=timestamps,
        centrality=tempcent,
        search_scope='auto',
    )

    root_to_nodepaths = build_root_to_nodepaths(gt_paths_by_root)

    latencies = []
    final_mrrs, final_h3s = [], []
    hit_list, cov_list, purity_list = [], [], []
    root_rank_list = []
    f1_j_list, f1_gr_list, edgecov_list = [], [], []
    predcount_list = []
    series_scores = []
    
    # Build event index for fast lookup
    window_size_ms = window_size * 86400000.0
    sorted_events, event_timestamps = build_event_index(events, window_size_ms)
    
    # Convert to set for O(1) lookup
    gt_root_set = set(gt_root_ids)

    commres = tcd.detect_communities(depgraph)

    for (t_s, t_e, t_eval) in window_iter():

        if isinstance(t_eval, datetime):
            t_eval = t_eval.timestamp()*1000

        # event-based ranking - OPTIMIZED: use binary search
        ev = find_matching_event(t_eval, sorted_events, event_timestamps, window_size_ms)
        ev_targets = ev["targets"] if ev else None

        tic = time.perf_counter()

        # community prediction
        best_comm, cent_scores = tcd.choose_root_community(commres.comm_to_nodes, t_s, t_e)
        if best_comm is None:
            latencies.append((time.perf_counter()-tic)*1000)
            continue

        comm_nodes = set(commres.comm_to_nodes[best_comm])

        # predicted root = max-centrality node inside community
        predicted_root = max(comm_nodes, key=lambda n: cent_scores.get(n, 0.0))

        # OPTIMIZATION: Pre-compute sorted nodes once
        sorted_cent_nodes = None
        
        # GT root → ALL roots
        for rid in gt_root_set:
            if rid not in depgraph:
                continue
            hit_list.append(1.0 if rid in comm_nodes else 0.0)
            neigh = set(depgraph.neighbors(rid))|{rid}
            cov_list.append(len(neigh & comm_nodes)/len(neigh))
            purity_list.append(len(neigh & comm_nodes)/len(comm_nodes))

            # rank of GT root inside community - OPTIMIZED
            if rid in cent_scores:
                if sorted_cent_nodes is None:
                    sorted_cent_nodes = sorted(cent_scores, key=lambda x: cent_scores[x], reverse=True)
                root_rank_list.append(sorted_cent_nodes.index(rid)+1)

        pcfg = PathConfig(
            t_start= t_s,
            t_end= t_e,
            strict_increase=strict_increase,
            alpha=alpha, beta=beta, gamma=gamma,
            k_paths=k_paths,
            targets=None,
            similarity_scores=None,
        )

        # path analysis
        _, _, _, paths_by_target, _ = analyzer.analyze_with_paths(
            k_neighbors=k_neighbors,
            t_start=pcfg.t_start,
            t_end=pcfg.t_end,
            path_cfg=pcfg,
            explain=False,
            source=predicted_root,
        )

        latencies.append((time.perf_counter()-tic)*1000)

        # path GT = ALL GT roots
        all_gt_paths = []
        for rid in gt_root_set:
            all_gt_paths.extend(root_to_nodepaths.get(rid, []))

        predicted_paths = [p for ps in paths_by_target.values() for p in ps]
        predcount_list.append(len(predicted_paths))

        if all_gt_paths:
            f1_j = path_f1_partial_match(all_gt_paths, predicted_paths, overlap_thresh=0.5, mode="jaccard")
            f1_gr = path_f1_partial_match(all_gt_paths, predicted_paths, overlap_thresh=0.5, mode="gt_recall")
            ec = _edge_coverage(all_gt_paths, predicted_paths)
        else:
            f1_j = f1_gr = ec = 0.0

        f1_j_list.append(f1_j)
        f1_gr_list.append(f1_gr)
        edgecov_list.append(ec)

        # fusion scoring for ranking events.targets
        path_scores = defaultdict(float)
        for p in predicted_paths:
            for v in p:
                path_scores[v] += 1.0

        comm_scores = {n: cent_scores.get(n, 0.0) if n in comm_nodes else 0.0
                       for n in (set(cent_scores)|comm_nodes)}

        all_nodes = set(path_scores)|set(comm_scores)

        fused = {
            n: fuse_lambda*path_scores.get(n,0.0) + (1-fuse_lambda)*comm_scores.get(n,0.0)
            for n in all_nodes
        }

        norm = _zscore(fused)
        series_scores.append((t_eval, norm))

        if ev_targets:
            mrr, h3 = _rank_metrics(norm, ev_targets)
            final_mrrs.append(mrr)
            final_h3s.append(h3)


    return {
        "Full": {
            "MRR": avg(final_mrrs),
            "Hits@3": avg(final_h3s),
            "LeadTime(days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency(ms)": avg(latencies),

            "Hit-Root": avg(hit_list),
            "RootCoverage": avg(cov_list),
            "RootPurity": avg(purity_list),
            "RootRankInComm": avg(root_rank_list),

            "Path-F1(Jaccard)": avg(f1_j_list),
            "Path-F1(GT-Recall)": avg(f1_gr_list),
            "EdgeCoverage": avg(edgecov_list),
            "PredictedPathCount": avg(predcount_list),
        }
    }


# ============= Helper function: load_ground_truth =============
def load_ground_truth(args):
    """
    Load ground truth ref_paths and root_causes (normal + family)
    """
    from utils.util import read_jsonl
    gt_layer = []
    if args.ref_layer:
        gt_layer = read_jsonl(args.ref_layer)
    if not gt_layer:
        print("[WARN] No ground truth ref_paths provided. Skip GT evaluation.")
        return None

    def summarize_ref_paths(data, label):
        total = len(data)
        nonempty = sum(1 for r in data if r.get("path"))
        ratio = round(nonempty / total, 4) if total else 0
        print(f"[GroundTruth] {label}: total={total}, nonempty={nonempty}, ratio={ratio}")
        return ratio

    if gt_layer:
        summarize_ref_paths(gt_layer, "layer version")

    return gt_layer



# ============= Main function with optimizations =============
def main():
    """
    OPTIMIZED main function matching original structure
    """
    parser = argparse.ArgumentParser(description="OPTIMIZED Benchmark with optional ground truth")
    parser.add_argument("--ref-layer", type=str, help="Path to ref_paths_layer.jsonl", default=None)

    args, unknown = parser.parse_known_args()
    
    print("\n=== [1] Loading Ground Truth ===")
    gt_layer = load_ground_truth(args)
    if gt_layer is None:
        gt_layer = []
    
    gt_paths_by_root, gt_root_by_cve, gt_paths_by_cve = parse_ref_paths(gt_layer)

    data_dir = Path.cwd().joinpath("data")

    # core inputs
    dep_path   = data_dir.joinpath("dep_graph_cve.pkl")
    node_texts_path = data_dir.joinpath("nodeid_to_texts.pkl")
    per_cve_path = data_dir.joinpath("per_cve_scores.pkl")  
    node_scores_path = data_dir.joinpath("node_cve_scores.pkl")
    cve_meta_path = data_dir.joinpath("cve_records_for_meta.pkl")

    print("\n=== [2] Loading Graph ===")
    with dep_path.open("rb") as f:
        depgraph = pickle.load(f)
    
    print(f"[info] Graph loaded: {depgraph.number_of_nodes()} nodes, {depgraph.number_of_edges()} edges")

    print("\n=== [3] Building Optimized Subgraph ===")
    
    # 1) Collect nodes from GT paths
    gt_required_nodes = set()
    if gt_layer:
        for item in gt_layer:
            for e in item.get("path", []):
                gt_required_nodes.add(e["src"])
                gt_required_nodes.add(e["dst"])

    print(f"[info] GT requires {len(gt_required_nodes)} nodes")

    # 2) Check missing
    missing = [n for n in gt_required_nodes if n not in depgraph]
    if missing:
        print(f"[WARN] {len(missing)} GT nodes missing")
    else:
        print("[info] All GT path nodes exist")

    # 3-5) Collect neighbors efficiently
    keep = set(gt_required_nodes)
    for hop in range(1, 4):
        new_neighbors = set()
        for n in list(keep):
            if n in depgraph:
                new_neighbors.update(depgraph.predecessors(n))
                new_neighbors.update(depgraph.successors(n))
        keep.update(new_neighbors)
        print(f"[info] After {hop}-hop: {len(keep)} total nodes")

    # 6) Build subgraph
    depgraph = depgraph.subgraph(keep).copy()
    print(f"[debug] Final subgraph: {depgraph.number_of_nodes()} nodes, {depgraph.number_of_edges()} edges")

    # 7) Debug coverage
    if gt_required_nodes:
        overlap = len(gt_required_nodes & set(depgraph.nodes()))
        print(f"[debug] GT node retention: {overlap}/{len(gt_required_nodes)} ({overlap/len(gt_required_nodes):.4f})")
    print("=== Subgraph Ready ===\n")

    # Candidate selection
    gt_root_ids = {item["root_id"] for item in (gt_layer or [])
                   if item.get("root_id") and item["root_id"] in depgraph}
    print(f"[debug] GT root ids: {len(gt_root_ids)}")

    candidates = set()
    for n, d in depgraph.nodes(data=True):
        ts = d.get("timestamp")
        if ts is not None and (d.get("has_cve") or d.get("cve_count", 0) >= 1):
            candidates.add((int(ts), n))

    for rid in gt_root_ids:
        ts = depgraph.nodes[rid].get("timestamp")
        if ts is not None:
            candidates.add((int(ts), rid))

    candidates = sorted(candidates)
    print(f"[info] {len(candidates)} candidates selected")

    # Load cached data
    print("\n=== [4] Loading Cached Data ===")
    nodeid_to_texts = pickle.loads(node_texts_path.read_bytes())
    cve_records_for_meta = pickle.loads(cve_meta_path.read_bytes())
    print("[cache] nodeid_to_texts & cve_records_for_meta loaded")

    node_cve_scores = None
    if per_cve_path.exists():
        per_cve_scores = pickle.loads(per_cve_path.read_bytes())
        print("[cache] per_cve_scores loaded")
    if node_scores_path.exists():
        node_cve_scores = pickle.loads(node_scores_path.read_bytes())
        print("[cache] node_cve_scores loaded")
    
    # Initialize centrality
    print("\n=== [5] Initializing Centrality ===")
    tempcent = TempCentricityOptimized(depgraph, search_scope='auto')
    print("[info] TempCentricityOptimized initialized")

    # Build evaluation timeline
    print("\n=== [6] Building Timeline ===")
    earliest = min(d for d in (_first_cve_data_of_node(metas)
                               for metas in cve_records_for_meta.values()) if d is not None)
    latest = max(d for d in (_last_cve_data_of_node(metas)
                             for metas in cve_records_for_meta.values()) if d is not None)

    lookback_days = 365 * 2
    stride_days = 30

    start = earliest - timedelta(days=lookback_days+1)
    t_eval_list = [d.date() for d in pd.date_range(start=start, end=latest, freq=f"{stride_days}D", inclusive="both")]

    events = build_events_from_vamana_meta(depgraph, cve_records_for_meta, t_eval_list, fallback_to_release=True)
    events = [{**e, "t": _to_float_time(e["t"])} for e in events]
    print(f"[info] {len(events)} events from {t_eval_list[0]} to {t_eval_list[-1]}")

    # Window iterator
    ref_type = pd.Timestamp.now(tz="UTC")
    def window_iter():
        for d_eval in t_eval_list:
            d_s = d_eval - timedelta(days=lookback_days)
            d_e = d_eval
            t_eval_mid = d_s + (d_e - d_s) / 2
            yield (
                _to_float_time(_to_same_type(d_s, ref_type)) * 1000.0,
                _to_float_time(_to_same_type(d_e, ref_type)) * 1000.0,
                _to_float_time(_to_same_type(t_eval_mid, ref_type)) * 1000.0,
            )

    # Run Benchmarks
    print("\n" + "="*60)
    print("=== [7] Running OPTIMIZED Benchmarks ===")
    print("="*60)
    all_metrics = {}

    if node_cve_scores is None:
        node_cve_scores = {n: 0.0 for n in depgraph.nodes()}
        print("[warn] using dummy node_cve_scores")
    
    # Community
    print("\n--- [7.1] Community Benchmark ---")
    start_time = time.time()
    comm = benchmark_community(depgraph, tempcent, node_cve_scores, events, window_iter, gt_root_ids)
    all_metrics.update(comm)
    print(f"[✓] Community done ({time.time()-start_time:.1f}s)")

    # Centrality (with fast methods)
    tempcent.degree_centrality = tempcent.degree_centrality_fast
    tempcent.eigenvector_centrality = tempcent.eigenvector_centrality_fast
    
    print("\n--- [7.2] Centrality Benchmark ---")
    start_time = time.time()
    cen = benchmark_centrality(tempcent, events, window_iter, gt_root_ids)
    all_metrics.update(cen)
    print(f"[✓] Centrality done ({time.time()-start_time:.1f}s)")

    # Paths
    print("\n--- [7.3] Path Benchmark ---")
    start_time = time.time()
    pathm = benchmark_paths(depgraph, tempcent, node_cve_scores, nodeid_to_texts, events, window_iter,
                            gt_root_ids, gt_paths_by_root, k_neighbors=15, alpha=5.0, beta=0.0, 
                            gamma=0.0, k_paths=5, strict_increase=False, candidates=candidates)
    all_metrics.update(pathm)
    print(f"[✓] Path done ({time.time()-start_time:.1f}s)")

    # Full
    print("\n--- [7.4] Full Benchmark ---")
    start_time = time.time()
    fullm = benchmark_full(depgraph, tempcent, node_cve_scores, nodeid_to_texts, events, window_iter,
                           gt_root_ids, gt_paths_by_root, k_neighbors=15, alpha=5.0, beta=0.0, 
                           gamma=0.0, k_paths=5, strict_increase=False, fuse_lambda=0.6)
    all_metrics.update(fullm)
    print(f"[✓] Full done ({time.time()-start_time:.1f}s)")

    # Print results
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    for key, value in all_metrics.items():
        print(f"\n{key}:")
        if isinstance(value, dict):
            for k, v in value.items():
                print(f"  {k}: {v}")
        else:
            print(f"  {value}")

    print("\n=== [8] Benchmark Completed ===")

# ============================================================
# --- Entry Point ---
# ============================================================
if __name__ == "__main__":
    main()