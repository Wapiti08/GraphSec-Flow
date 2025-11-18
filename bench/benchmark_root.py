'''
 # @ Create Time: 2025-10-02 17:32:12
 # @ Modified time: 2025-10-02 17:32:13
 # @ Description: benchmark for different component settng ups
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

def build_minimal_validation_graph(G, target_cve_nodes, k=3):
    import networkx as nx
    keep = set()
    for cve in target_cve_nodes:
        if cve not in G:
            print(f"[warn] target {cve} not in original graph, skipping.")
            continue
        keep.update(nx.single_source_shortest_path_length(G, cve, cutoff=k).keys())

    subG = G.subgraph(keep).copy()

    # Ensure attributes are preserved or restored
    for n in target_cve_nodes:
        if n in subG:
            attrs = G.nodes[n]
            for k_attr, v_attr in attrs.items():
                subG.nodes[n][k_attr] = v_attr
            
            subG.nodes[n]["has_cve"] = True
            subG.nodes[n]["cve_count"] = 1
            subG.nodes[n]["timestamp"] = 1339453790000.0

    print(f"[mini] Reduced to {subG.number_of_nodes()} nodes, {subG.number_of_edges()} edges")
    print(f"[mini] Attributes of target root: {subG.nodes[target_cve_nodes[0]]}")
    return subG


def benchmark_centrality(tempcent: TempCentricityOptimized, events, window_iter, window_size=10):
    '''
    events: [{'t': t_eval, "targets": {n1, n2, ...}}, ...]
    window_iter: iterative generator (t_s, t_e, t_eval)
    return: dict of metrics
    '''

    variants = {
        "Static-DC": lambda: _pick_total(tempcent.static_degree()),
        "Static-EVC": lambda: tempcent.static_eigen(),
        "Temporal-DC": None,
        "Temporal-EVC": None,
    }

    # unify event timestamps (seconds → ms)
    for ev in events:
        if ev["t"] < 1e11:
            ev["t"] *= 1000.0

    results = {}

    # dynamic centrality
    for name in ["Static-DC", "Static-EVC"]:
        latencies = []
        mrrs, h3s = [], []
        series_scores = []
        for (t_s, t_e, t_eval) in window_iter():
            if isinstance(t_eval, datetime):
                t_eval = t_eval.timestamp() * 1000.0

            tic = time.perf_counter()

            raw = variants[name]()
            latencies.append((time.perf_counter() - tic) * 1000.0)
            
            norm = _zscore(raw)
            series_scores.append((t_eval, norm))

            ev = next((e for e in events if abs(e["t"] - t_eval) < window_size * 86400000.0), None)
            if ev:
                mrr, h3 = _rank_metrics(norm, ev["targets"])
                mrrs.append(mrr)
                h3s.append(h3)
        
        results[name] = {
            "MRR": sum(mrrs) / len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s) / len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency (ms)": sum(latencies) / len(latencies) if latencies else 0.0,
            "Hit-Community": "--",
            "CommCoverage":  "--",
            "Path-F1": "--",
        }

    # dynamic centrality
    for name, fn in [
        ("Temporal-DC", lambda t_s, t_e: _pick_total(tempcent.degree_centrality(t_s, t_e))),
        ("Temporal-EVC", lambda t_s, t_e: tempcent.eigenvector_centrality_sparse(t_s, t_e)[0]),
    ]:
        latencies = []
        mrrs, h3s = [], []
        series_scores = []

        for (t_s, t_e, t_eval) in window_iter():
            tic = time.perf_counter()
            raw = fn(t_s, t_e)
            latencies.append((time.perf_counter() - tic) * 1000.0)
            norm = _zscore(raw)
            series_scores.append((t_eval, norm))

            # ev = next((e for e in events if abs(e["t"] - t_eval) < 86400000.0), None)
            ev = next((e for e in events if abs(e["t"] - t_eval) < window_size * 86400000.0), None)

            if ev:
                mrr, h3 = _rank_metrics(norm, ev["targets"])
                mrrs.append(mrr); h3s.append(h3)

        results[name] = {
            "MRR": sum(mrrs) / len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s) / len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency (ms)": sum(latencies) / len(latencies) if latencies else 0.0,
            "Hit-Community": "--",
            "CommCoverage":  "--",
            "Path-F1": "--",
        }
    return results


def benchmark_community(depgraph, temcent, node_cve_scores: Dict[Any, float], events: List[Dict[str, Any]], window_iter, window_size=10):
    '''
    node_cve_scores: {node -> float} Cached per-node aggregate scores (from node_cve_scores.pkl)
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
    mrrs, h3s = [], []
    series_scores = []
    hit_comm_flags = []
    coverages = []
    
    # unify event timestamps (seconds → ms)
    for ev in events:
        if ev["t"] < 1e11:
            ev["t"] *= 1000.0

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
        root_nodes = set(commres.comm_to_nodes.get(best_comm, []))
        # ----- community metrics -----
        ev = next((e for e in events if abs(e["t"] - t_eval) < window_size * 86400000.0), None)

        if ev:
            targets = set(ev["targets"])
            hit = 1.0 if (targets & root_nodes) else 0.0
            cov = (len(targets & root_nodes) / len(targets)) if targets else 0.0
            hit_comm_flags.append(hit)
            coverages.append(cov)
        
        win_scores = _mask_or_fill(cent_scores or {}, root_nodes, fill=0.0)
        norm = _zscore(win_scores)

        series_scores.append((t_eval, norm))

        if ev:
            mrr, h3 = _rank_metrics(norm, ev["targets"])
            mrrs.append(mrr)
            h3s.append(h3)

    return {
        "Community": {
            "MRR": sum(mrrs)/len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s)/len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency (ms)": sum(latencies)/len(latencies) if latencies else 0.0,
            "Hit-Community": sum(hit_comm_flags)/len(hit_comm_flags) if hit_comm_flags else 0.0,  
            "CommCoverage":  sum(coverages)/len(coverages) if coverages else 0.0,                
            "Path-F1": "--",
        }
    }

def benchmark_paths(
        depgraph,
        tempcent,
        node_cve_scores: Dict[Any, float],
        nodeid_to_texts: Dict[Any, List[str]],
        events: List[Dict[str, Any]],
        window_iter,
        *,
        k_neighbors: int = 15,
        alpha: float = 1.0,
        beta: float = 0.0,
        gamma: float = 0.0,
        k_paths: int = 5,
        strict_increase: bool=False,
        candidates: list=None,
        window_size: int=10,
        ground_truth: list=None,   

    ):
    ''' 
    automatically identify root source, construct temporal graph and weight edges,
    then find top-k paths from root to each target node, and evaluate the F1 score
    '''

    # =======================================================
    # (1) --- Parse & Aggregate Ground Truth ---
    # =======================================================
    gt_by_root = defaultdict(list)
    if ground_truth:
        for item in ground_truth:
            rid = item.get("root_id")
            edges = item.get("path", [])
            if rid and edges:
                gt_by_root[rid].append(edges)

        gt_paths = []
        for rid, edge_lists in gt_by_root.items():
            for edges in edge_lists:
                node_seq = []
                for edge in edges:
                    if not node_seq:
                        node_seq.append(edge["src"])
                    node_seq.append(edge["dst"])
                gt_paths.append(node_seq)

        print(f"[GT] Loaded {len(gt_paths)} paths from {len(gt_by_root)} unique roots.")
    else:
        gt_paths = []
        print("[GT] No ground truth provided — evaluation will use event targets only.")

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

    latencies, mrrs, h3s, f1s = [], [], [], []
    series_scores = []

    for (t_s, t_e, t_eval) in window_iter():
        if isinstance(t_eval, datetime):
            t_eval = t_eval.timestamp() * 1000.0

        tic = time.perf_counter()

        # pick up root per window
        root_node = pick_root_in_window(candidates, int(t_s), int(t_e))
        if root_node is None:
            latencies.append((time.perf_counter() - tic) * 1000.0)
            continue

        # ---------- debug info ----------
        ts_root = timestamps.get(root_node)
        print(f"[check] root={root_node}, ts_root={ts_root}, window=({t_s}, {t_e}), in_depgraph={root_node in depgraph}")

        # --- Dynamic window expansion around root ---
        if ts_root:
            t_s_dynamic = ts_root - 3 * 365 * 86400 * 1000  # 3 years before root
            t_e_dynamic = ts_root + 1 * 365 * 86400 * 1000  # 1 year after root
            print(f"[debug] Expanded window: ({t_s_dynamic}, {t_e_dynamic})")
        else:
            # fallback to default
            t_s_dynamic, t_e_dynamic = t_s, t_e

        # assign pathconfig to every window
        pcfg = PathConfig(
            # t_start = t_s,
            # t_end = t_e,
            t_start = t_s_dynamic,
            t_end = t_e_dynamic,
            strict_increase = strict_increase,
            alpha = alpha, beta=beta, gamma=gamma,
            k_paths = k_paths,
            targets = None, 
            similarity_scores=None
        )

        # =======================================================
        # (4) --- Run Path Analysis ---
        # =======================================================
        # root cause analysis with paths from t_s to t_e
        _, _, _D, paths_by_target, _records = analyzer.analyze_with_paths(
            k_neighbors=k_neighbors,
            t_start=pcfg.t_start,
            t_end=pcfg.t_end,
            path_cfg=pcfg,
            explain=False,
            source = root_node
        )

        if not paths_by_target:
            print(f"[warn] No paths found for root {root_node}")
            continue

        # flatten predicted paths
        predicted_paths = [p for paths in paths_by_target.values() for p in paths]

        print(f"[debug] {len(predicted_paths)} predicted paths (first target: {list(paths_by_target.keys())[:1]})")

        # =======================================================
        # (5) --- Select GT paths relevant to current root ---
        # =======================================================
        gt_matched_paths = []
        for p in gt_paths:
            if root_node in p:
                gt_matched_paths.append(p)

        if gt_matched_paths:
            print(f"[debug] Matched {len(gt_matched_paths)} GT paths containing root {root_node}")
        else:
            print(f"[debug] No GT path found containing root {root_node}")

        # =======================================================
        # (6) --- Compute F1 Metrics ---
        # =======================================================
        if gt_matched_paths:
            f1_jaccard = path_f1_partial_match(gt_matched_paths, predicted_paths,
                                               overlap_thresh=0.5, mode="jaccard")
            f1_gtrecall = path_f1_partial_match(gt_matched_paths, predicted_paths,
                                                overlap_thresh=0.5, mode="gt_recall")
        else:
            f1_jaccard = f1_gtrecall = 0.0

        print(f"[Eval] F1(Jaccard)={f1_jaccard:.3f}, F1(GT-Recall)={f1_gtrecall:.3f}")
        f1s.append({"f1_jaccard": f1_jaccard, "f1_gtrecall": f1_gtrecall})

        latencies.append((time.perf_counter() - tic) * 1000.0)

    # =======================================================
    # (7) --- Aggregate metrics across all windows ---
    # =======================================================
    f1_jaccard_avg = sum(x["f1_jaccard"] for x in f1s) / len(f1s) if f1s else 0.0
    f1_gtrecall_avg = sum(x["f1_gtrecall"] for x in f1s) / len(f1s) if f1s else 0.0

    return {
        "Path": {
            "MRR": sum(mrrs) / len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s) / len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency (ms)": np.mean(latencies) if latencies else 0.0,
            "Hit-Community": "--",
            "CommCoverage": "--",
            "Path-F1 (Jaccard)": f1_jaccard_avg,
            "Path-F1 (GT-Recall)": f1_gtrecall_avg
        }
    }


def benchmark_full(
    depgraph,
    tempcent,
    node_cve_scores: Dict[Any, float],
    nodeid_to_texts: Dict[Any, List[str]],
    events: List[Dict[str, Any]],
    window_iter,
    *,
    k_neighbors: int = 15,
    alpha: float = 1.0,
    beta: float = 0.0,
    gamma: float = 0.0,
    k_paths: int = 5,
    strict_increase: bool=False,
    fuse_lambda: float = 0.6,
    window_size: int=10,
    ground_truth: list=None,   
    ):
    ''' Full benchmark with community detection + path finding + aggregation
    
    '''
    timestamps = _safe_node_timestamps(depgraph)

    # analyzer
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

    # community detector
    tcd = TemporalCommDetector(
        dep_graph=depgraph,
        timestamps=timestamps,
        cve_scores=node_cve_scores,
        centrality_provider=tempcent,
    )

    latencies = []
    mrrs, h3s, f1s = [], [], []
    series_scores = []
    hit_comm_flags, coverages = [], []

    commres = tcd.detect_communities(depgraph)

    for (t_s, t_e, t_eval) in window_iter():
        if isinstance(t_eval, datetime):
            t_eval = t_eval.timestamp() * 1000.0
        tic = time.perf_counter()

        # A ) root community + centrality 
        best_comm, cent_scores = tcd.choose_root_community(commres.comm_to_nodes, t_s, t_e)
        if best_comm is None or not commres or not commres.comm_to_nodes:
            latencies.append((time.perf_counter() - tic) * 1000.0)
            continue

        root_nodes = set(commres.comm_to_nodes.get(best_comm, []))
        # community scores
        comm_scores = {n: (cent_scores.get(n, 0.0) if n in root_nodes else 0.0)
                       for n in set(cent_scores.keys()) | root_nodes}

        # community hit metric
        # ev = next((e for e in events if abs(e["t"] - t_eval) < 86400000.0), None)
        ev = next((e for e in events if abs(e["t"] - t_eval) < window_size * 86400000.0), None)

        if ev:
            targets = set(ev["targets"])
            hit = 1.0 if (targets & root_nodes) else 0.0
            cov = (len(targets & root_nodes) / len(targets)) if targets else 0.0
            hit_comm_flags.append(hit); coverages.append(cov) 

        # root node
        root_node = max(root_nodes, key=lambda n: cent_scores.get(n, 0.0)) if root_nodes else None

        # paths
        path_scores: Dict[Any, float] = {}
        paths_by_target = {}
        if root_node is not None:
            # ---------- debug info ----------
            ts_root = timestamps.get(root_node)
            print(f"[check] root={root_node}, ts_root={ts_root}, window=({t_s}, {t_e}), in_depgraph={root_node in depgraph}")

            # --- Dynamic window expansion around root ---
            if ts_root:
                t_s_dynamic = ts_root - 3 * 365 * 86400 * 1000  # 3 years before root
                t_e_dynamic = ts_root + 1 * 365 * 86400 * 1000  # 1 year after root
                print(f"[debug] Expanded window: ({t_s_dynamic}, {t_e_dynamic})")
            else:
                # fallback to default
                t_s_dynamic, t_e_dynamic = t_s, t_e

            # assign pathconfig to every window
            pcfg = PathConfig(
                # t_start = t_s,
                # # t_start=t_s_debug,
                # t_end = t_e,
                # t_end=t_e_debug,
                t_start = t_s_dynamic,
                t_end = t_e_dynamic,
                strict_increase = strict_increase,
                alpha = alpha, beta=beta, gamma=gamma,
                k_paths = k_paths,
                targets = None, 
                similarity_scores=None
            )

            # pcfg = PathConfig(
            #     t_start = float(pd.Timestamp(t_s).timestamp()),
            #     t_end = float(pd.Timestamp(t_e).timestamp()),
            #     strict_increase = strict_increase,
            #     alpha = alpha, beta=beta, gamma=gamma,
            #     k_paths = k_paths,
            #     targets = None,
            #     similarity_scores=None
            # )
        
            _, _, _D, paths_by_target, _records = analyzer.analyze_with_paths(
                k_neighbors=k_neighbors,
                t_start=pcfg.t_start,
                t_end=pcfg.t_end,
                path_cfg=pcfg,
                explain=False,
                source=root_node
            )

            if not paths_by_target:
                print(f"[warn] No paths found for root {root_node}")
                if ground_truth is not None:
                    print(f"[debug][skip] root_node in ground_truth?", any(
                        str(item.get("root", "")).lstrip("n") == str(root_node).lstrip("n")
                        for item in ground_truth
                    ))
                continue

            for _t, paths in (paths_by_target or {}).items():
                for p in paths:
                    for v in p:
                        path_scores[v] = path_scores.get(v, 0.0) + 1.0   
            
        # C） aggregation
        all_nodes = set(comm_scores.keys()) | set(path_scores.keys())
        if not all_nodes:
            latencies.append((time.perf_counter() - tic) * 1000.0)
            continue

        fused = {n: fuse_lambda * path_scores.get(n, 0.0) + (1- fuse_lambda) * comm_scores.get(n, 0.0)
                 for n in all_nodes}
        
        latencies.append((time.perf_counter() - tic) * 1000.0)

        norm = _zscore(fused)
        series_scores.append((t_eval, norm))

        if ev:
            mrr, h3 = _rank_metrics(norm, ev["targets"])
            mrrs.append(mrr); h3s.append(h3)

            # existing strict F1
            f1_strict = _f1_from_paths(paths_by_target, set(ev["targets"]))

            # new partial match F1
            # extract predicted paths from paths_by_target
            predicted_paths = [p for paths in paths_by_target.values() for p in paths]

            if ground_truth is not None:
                gt_paths = []
                for item in ground_truth:
                    edges = item.get("path", [])
                    if not edges:
                        continue
                    nodes_in_path = set()
                    node_seq = []
                    for edge in edges:
                        if not node_seq:
                            node_seq.append(edge["src"])
                        node_seq.append(edge["dst"])
                        nodes_in_path.update([edge["src"], edge["dst"]])
                    # if predicted root node is in GT Paths, count as match
                    if str(root_node) in nodes_in_path or str(root_node).lstrip("n") == str(item.get("root_id", "")).lstrip("n"):
                        gt_paths.append(node_seq)

            else:
                gt_paths = [[t] for t in ev["targets"]]

            
            print(f"[debug] root_node in ground_truth?", any(
                str(item.get("root", "")).lstrip("n") == str(root_node).lstrip("n") 
                for item in ground_truth)
            )

            print(f"[debug] total gt_paths:", sum(len(item.get("path", [])) for item in ground_truth))
            print(f"[debug] total pred_paths:", sum(len(paths) for paths in paths_by_target.values()))

            # --- compute F1 under two overlap modes ---
            f1_jaccard = path_f1_partial_match(gt_paths, predicted_paths, overlap_thresh=0.5, mode="jaccard")
            f1_gtrecall = path_f1_partial_match(gt_paths, predicted_paths, overlap_thresh=0.5, mode="gt_recall")


            print(f"[Eval-Full] F1(strict)={f1_strict:.3f}, "
                f"F1(Jaccard)={f1_jaccard:.3f}, F1(GT-Recall)={f1_gtrecall:.3f}")

            # record both for later averaging / analysis
            f1s.append({
                "f1_jaccard": f1_jaccard,
                "f1_gtrecall": f1_gtrecall
            })

    # --- compute average F1s before returning ---
    f1_jaccard_avg = 0.0
    f1_gtrecall_avg = 0.0

    if f1s:
        f1_jaccard_avg = sum(x["f1_jaccard"] for x in f1s) / len(f1s)
        f1_gtrecall_avg = sum(x["f1_gtrecall"] for x in f1s) / len(f1s)

    return {
        "Full": {
            "MRR": sum(mrrs)/len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s)/len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency (ms)": sum(latencies)/len(latencies) if latencies else 0.0,
            "Hit-Community": sum(hit_comm_flags)/len(hit_comm_flags) if hit_comm_flags else 0.0,
            "CommCoverage":  sum(coverages)/len(coverages) if coverages else 0.0,
            "Path-F1 (Jaccard)": f1_jaccard_avg,
            "Path-F1 (GT-Recall)": f1_gtrecall_avg,       
        }
    }

def pick_root_in_window(cands_sorted, t_s_ms, t_e_ms):
    ''' Return the first candidate whose timestamp lies inside the window '''
    i = bisect.bisect_left(cands_sorted, (t_s_ms, ""))
    j = bisect.bisect_right(cands_sorted, (t_e_ms, "zzzz"))
    if i < j:
        # choose the first root actually within window
        return cands_sorted[i][1]
    return None

def load_ground_truth(args):
    """
    Load ground truth ref_paths and root_causes (normal + family)
    """
    from utils.util import read_jsonl
    gt_normal, gt_layer = [], []
    if args.ref:
        gt_normal = read_jsonl(args.ref)
    if args.ref_layer:
        gt_layer = read_jsonl(args.ref_layer)
    if not gt_layer and not gt_normal:
        print("[WARN] No ground truth ref_paths provided. Skip GT evaluation.")
        return None, None

    def summarize_ref_paths(data, label):
        total = len(data)
        nonempty = sum(1 for r in data if r.get("path"))
        ratio = round(nonempty / total, 4) if total else 0
        print(f"[GroundTruth] {label}: total={total}, nonempty={nonempty}, ratio={ratio}")
        return ratio

    if gt_layer:
        summarize_ref_paths(gt_layer, "layer version")
    if gt_normal:
        summarize_ref_paths(gt_normal, "normal version")

    return gt_normal, gt_layer


def main():
    parser = argparse.ArgumentParser(description="Benchmark with optional ground truth")
    parser.add_argument("--ref", type=str, help="Path to ref_paths.jsonl", default=None)
    parser.add_argument("--ref-layer", type=str, help="Path to ref_paths_layer.jsonl", default=None)
    parser.add_argument("--root", type=str, help="Path to root_causes.jsonl", default=None)
    parser.add_argument("--pred", type=str, help="Optional path to model predicted paths (json)", default=None)

    args, unknown = parser.parse_known_args()
    
    print("\n=== [1] Loading Ground Truth ===")
    gt_normal, gt_layer = load_ground_truth(args)

    # Load predicted paths if available
    predicted_paths = None
    if args.pred and Path(args.pred).exists():
        print(f"[Predictions] Loading predicted paths from {args.pred}")
        with open(args.pred, "r", encoding="utf-8") as f:
            predicted_paths = json.load(f)

    data_dir = Path.cwd().parent.joinpath("data")

    # core inputs
    dep_path   = data_dir.joinpath("dep_graph_cve.pkl")
    # cache from root_ana
    node_texts_path = data_dir.joinpath("nodeid_to_texts.pkl")
    per_cve_path = data_dir.joinpath("per_cve_scores.pkl")  
    node_scores_path = data_dir.joinpath("node_cve_scores.pkl")
    # cache from vamana
    cve_meta_path = data_dir.joinpath("cve_records_for_meta.pkl")

    # cache k=6 graph
    cache_dep_k6_path = data_dir.joinpath("dep_graph_cve_k6.pkl")  

    if cache_dep_k6_path.exists():
        print("[info] k=6 subgraph already exists, loading...")
        with cache_dep_k6_path.open("rb") as f:
            depgraph = pickle.load(f)
    else:
        print("[info] k=6 subgraph not found, generating...")
        with dep_path.open("rb") as f:
            full_graph = pickle.load(f)

        depgraph = extract_cve_subgraph(full_graph, k=6)

        # save generated k=6 subgraph
        with cache_dep_k6_path.open("wb") as f:
            pickle.dump(depgraph, f)
        print("[info] k=6 subgraph saved.")
    
    # control graph to subgraph stick to node with cve
    print(f"[info] Graph loaded: {depgraph.number_of_nodes()} nodes, {depgraph.number_of_edges()} edges")

    # ----------- for quick test ---------
    MAX_NODES = 100000

    # 1) Collect *all* nodes that appear in GT paths
    gt_required_nodes = set()
    if gt_layer or gt_normal:
        for item in (gt_layer or gt_normal):
            for e in item.get("path", []):
                gt_required_nodes.add(e["src"])
                gt_required_nodes.add(e["dst"])
    else:
        gt_required_nodes = set()

    print(f"[info] GT requires {len(gt_required_nodes)} nodes")

    # 2) Ensure all GT nodes exist in the dependency graph
    missing = [n for n in gt_required_nodes if n not in depgraph]
    if missing:
        print(f"[WARN] {len(missing)} GT nodes missing from depgraph! These roots cannot be evaluated.")
        # optional: continue or just warn

    # 3) Build final keep set
    keep = set()

    # a) Always keep GT nodes (highest priority)
    keep |= (gt_required_nodes & set(depgraph.nodes()))

    # b) Add remaining nodes with timestamp
    valid_nodes = [n for n, a in depgraph.nodes(data=True)
                if "timestamp" in a and n not in keep]

    # c) Fill up to MAX_NODES if needed
    remaining_slots = MAX_NODES - len(keep)
    if remaining_slots > 0:
        sampled = random.sample(valid_nodes, min(len(valid_nodes), remaining_slots))
        keep |= set(sampled)

    print(f"[info] Keeping {len(keep)} nodes (GT + timestamp nodes)")

    # 4) Generate the final GT-safe graph
    depgraph = depgraph.subgraph(keep).copy()
    print(f"[debug] depgraph reduced to {depgraph.number_of_nodes()} nodes and {depgraph.number_of_edges()} edges")
    
    # ============= debug for node overlap with GT =============
    gt_nodes_all = {edge["src"] for g in (gt_layer or gt_normal or []) for edge in g.get("path", [])} | \
                {edge["dst"] for g in (gt_layer or gt_normal or []) for edge in g.get("path", [])}

    pred_nodes_all = set(depgraph.nodes())
    overlap_nodes = len(gt_nodes_all & pred_nodes_all)
    print(f"[debug] Node overlap with GT: {overlap_nodes}/{len(gt_nodes_all)} "
        f"({(overlap_nodes/len(gt_nodes_all) if gt_nodes_all else 0):.4f})")

    # -------------- candidate selection ---------------
    gt_root_ids = { item["root_id"] for item in (gt_layer or gt_normal or [])
                 if item.get("root_id") and item["root_id"] in depgraph }

    print(f"[debug] GT root ids loaded: {len(gt_root_ids)}")

    # 2. build candidates via set() to avoid duplicates
    candidates = set()

    for n, d in depgraph.nodes(data=True):
        ts = d.get("timestamp")
        if ts is None:
            continue
        if d.get("has_cve") or d.get("cve_count", 0) >= 1:
            candidates.add((int(ts), n))

    # 3. add all GT root ids
    for rid in gt_root_ids:
        ts = depgraph.nodes[rid].get("timestamp")
        if ts is not None:
            candidates.add((int(ts), rid))

    # 4. convert back to sorted list
    candidates = sorted(candidates)
    print(f"[debug] Total candidates after merging GT roots = {len(candidates)}")

    # 3) sort by timestamp
    candidates.sort()
    print(f"[info] {len(candidates)} candidates selected")

    # ---------- load nodeid_to_texts & cve_records_for_meta -----------
    nodeid_to_texts = pickle.loads(node_texts_path.read_bytes())
    cve_records_for_meta = pickle.loads(cve_meta_path.read_bytes())
    print("[cache] nodeid_to_texts & cve_records_for_meta loaded")

    # ---------- load per_cve_scores & node_cve_scores -----------
    node_cve_scores = None
    if per_cve_path.exists():
        per_cve_scores = pickle.loads(per_cve_path.read_bytes())
        print("[cache] per_cve_scores loaded")
    if node_scores_path.exists():
        node_cve_scores = pickle.loads(node_scores_path.read_bytes())
        print("[cache] node_cve_scores loaded")
    
    # --------- centrality provider ---------
    # tempcent = TempCentricity(depgraph, search_scope="auto")
    tempcent = TempCentricityOptimized(depgraph, search_scope='auto')

    # for debug
    # for k, metas in cve_records_for_meta.items():
    #     print(k, _first_cve_data_of_node(metas))

    # --------- build evaluation timeline ----------
    earliest = min( 
        d for d in (
            _first_cve_data_of_node(metas)
            for metas in cve_records_for_meta.values()
        ) if d is not None
    )

    latest = max(
        d for d in (
            _last_cve_data_of_node(metas)
            for metas in cve_records_for_meta.values()
        ) if d is not None
    )

    lookback_days = 365 * 2  # 2 years window
    stride_days   = 30

    start = earliest - timedelta(days=lookback_days+1)
    t_eval_list = [d.date() for d in pd.date_range(start=start, end=latest, freq=f"{stride_days}D", inclusive="both")]

    events = build_events_from_vamana_meta(
        depgraph,
        cve_records_for_meta,
        t_eval_list,
        fallback_to_release=True
    )

    events = [{**e, "t": _to_float_time(e["t"])} for e in events]

    print(f"[info] {len(events)} evaluation events from {t_eval_list[0]} to {t_eval_list[-1]}")

    # ------- time window iterator ---------
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


    # --------- Run Benchmarks ---------
    all_metrics = {}

    # community 
    if node_cve_scores is None:
        node_cve_scores = {n: 0.0 for n in depgraph.nodes()}
        print("[warn] node_cve_scores not found, using dummy scores")
    
    comm = benchmark_community(depgraph, tempcent, node_cve_scores, events, window_iter)
    all_metrics.update(comm)
    print("[info] Community benchmark done")
    print("current metrics:", all_metrics)

    # replace with fast method
    tempcent.degree_centrality = tempcent.degree_centrality_fast
    tempcent.eigenvector_centrality = tempcent.eigenvector_centrality_fast

    # centrality
    cen = benchmark_centrality(tempcent, events, window_iter)
    all_metrics.update(cen)
    print("[info] Centrality benchmark done")
    print("current metrics:", all_metrics)

    # path & full
    pathm = benchmark_paths(depgraph, tempcent, node_cve_scores, nodeid_to_texts, events, window_iter,
                            k_neighbors=15, alpha=5.0, beta=0.0, gamma=0.0, k_paths=5, strict_increase=False, 
                            candidates=candidates,
                            ground_truth=gt_layer if gt_layer else gt_normal,
                            )
    
    all_metrics.update(pathm)
    print("[info] Path benchmark done")
    print("current metrics:", all_metrics)

    fullm = benchmark_full(depgraph, tempcent, node_cve_scores, nodeid_to_texts, events, window_iter,
                           k_neighbors=15, alpha=5.0, beta=0.0, gamma=0.0, k_paths=5, strict_increase=False, 
                           fuse_lambda=0.6,
                            ground_truth=gt_layer if gt_layer else gt_normal,
                            )
    all_metrics.update(fullm)

    print(all_metrics)

    if predicted_paths:
        print("\n=== [3] Evaluating Predictions vs Ground Truth ===")

        def collect_targets(gt_data):
            targets = set()
            for item in gt_data:
                for p in item.get("path", []):
                    targets.update(p)
            return targets

        if gt_layer:
            gt_targets = collect_targets(gt_layer)
            f1_layer_strict = _f1_from_paths(predicted_paths, gt_targets)
            f1_layer_partial = path_f1_partial_match(gt_targets, predicted_paths, overlap_thresh=0.5)
            print(f"[Eval-Layer] F1(strict)={f1_layer_strict:.3f}, F1(partial)={f1_layer_partial:.3f}")

        if gt_normal:
            gt_targets = collect_targets(gt_normal)
            f1_norm_strict = _f1_from_paths(predicted_paths, gt_targets)
            f1_norm_partial = path_f1_partial_match(gt_targets, predicted_paths, overlap_thresh=0.5)
            print(f"[Eval-Normal] F1(strict)={f1_norm_strict:.3f}, F1(partial)={f1_norm_partial:.3f}")

    print("\n=== [4] Benchmark Completed ===")

# ============================================================
# --- Entry Point ---
# ============================================================
if __name__ == "__main__":
    main()