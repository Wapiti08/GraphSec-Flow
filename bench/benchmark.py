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
from bench.helper import _root_rank, _precision_at_k, _community_purity, _community_coverage, _edge_coverage
from bench.helper import avg, convert_edges_to_seq, build_root_to_nodepaths

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


def benchmark_centrality(tempcent: TempCentricityOptimized, 
                         events, window_iter, gt_root_ids, window_size=10, k_precision=5
):
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

    # root ranking helper
    def root_rank(scores, root):
        if root not in scores:
            return None
        sorted_nodes = sorted(scores, key=lambda x: scores[x], reverse=True)
        return sorted_nodes.index(root) + 1

    # dynamic centrality
    for name in ["Static-DC", "Static-EVC"]:
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

            ev = next((e for e in events if abs(e["t"] - t_eval) < window_size * 86400000.0), None)
            if ev:
                mrr, h3 = _rank_metrics(norm, ev["targets"])
                mrrs.append(mrr)
                h3s.append(h3)
        
            # root-identification over ALL GT roots
            for rid in gt_root_ids:
                if rid in norm:
                    rr = root_rank(norm, rid)
                    if rr:
                        root_ranks.append(rr)
                    precs.append(1.0 if rid in list(sorted(norm, key=lambda x: norm[x], reverse=True))[:k_precision] else 0.0)
                    rmrr, _ = _rank_metrics(norm, {rid})
                    root_mrrs.append(rmrr)

        results[name] = {
            "MRR": avg(mrrs),
            "Hits@3": avg(h3s),
            "LeadTime(days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency(ms)": avg(latencies),

            # Option-A root identification stats
            "RootRank": avg(root_ranks),
            f"Precision@{k_precision}": avg(precs),
            "RootMRR": avg(root_mrrs),
        }


    # dynamic centrality
    for name, fn in [
        ("Temporal-DC", lambda t_s, t_e: _pick_total(tempcent.degree_centrality(t_s, t_e))),
        ("Temporal-EVC", lambda t_s, t_e: tempcent.eigenvector_centrality_sparse(t_s, t_e)[0]),
    ]:
        latencies = []
        mrrs, h3s = [], []
        root_ranks, prec_list, root_mrr_list = [], [], []
        series_scores = []

        for (t_s, t_e, t_eval) in window_iter():
            tic = time.perf_counter()
            raw = fn(t_s, t_e)
            latencies.append((time.perf_counter() - tic) * 1000.0)
            norm = _zscore(raw)
            series_scores.append((t_eval, norm))

            ev = next((e for e in events if abs(e["t"] - t_eval) < window_size * 86400000.0), None)
            if ev:
                mrr, h3 = _rank_metrics(norm, ev["targets"])
                mrrs.append(mrr)
                h3s.append(h3)
        
            # root-identification over ALL GT roots
            for rid in gt_root_ids:
                if rid in norm:
                    rr = root_rank(norm, rid)
                    if rr:
                        root_ranks.append(rr)
                    precs.append(1.0 if rid in list(sorted(norm, key=lambda x: norm[x], reverse=True))[:k_precision] else 0.0)
                    rmrr, _ = _rank_metrics(norm, {rid})
                    root_mrrs.append(rmrr)

        results[name] = {
            "MRR": avg(mrrs),
            "Hits@3": avg(h3s),
            "LeadTime(days)": _lead_time(series_scores, events, thresh=0.8),
            "Latency(ms)": avg(latencies),

            # Option-A root identification stats
            "RootRank": avg(root_ranks),
            f"Precision@{k_precision}": avg(precs),
            "RootMRR": avg(root_mrrs),
        }

    return results


def benchmark_community(depgraph,
        temcent,
        node_cve_scores,
        events,
        window_iter,
        gt_root_ids, 
        window_size=10
    ):
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
    hit_list, cov_list, purity_list = [], [], []
    root_rank_list = []
    mrrs, h3s = [], []
    series_scores = []
    
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

        comm_nodes = set(commres.comm_to_nodes[best_comm])
        # ----- community metrics -----
        ev = next(
            (e for e in events if abs(e["t"] - t_eval) < window_size * 86400000),
            None
        )
        if ev:
            mrr, h3 = _rank_metrics(_zscore(cent_scores), ev["targets"])
            mrrs.append(mrr)
            h3s.append(h3)

        # GT roots coverage / purity
        for rid in gt_root_ids:
            if rid not in depgraph:
                continue
        
            # hit
            hit_list.append(1.0 if rid in comm_nodes else 0.0)

            # 1-hop neighborhood
            neigh = set(depgraph.neighbors(rid)) | {rid}
            cov_list.append(len(neigh & comm_nodes)/len(neigh))
            purity_list.append(len(neigh & comm_nodes)/len(comm_nodes))

            # rank inside community
            if rid in cent_scores:
                sorted_nodes = sorted(cent_scores, key=lambda x: cent_scores[x], reverse=True)
                root_rank_list.append(sorted_nodes.index(rid)+1)

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
    Path tracking benchmark using TRUE GT paths from ref_paths.

    Root selection strategy:
        - root is chosen by `pick_root_in_window(candidates)`
        - GT paths are those whose ground-truth root_id matches the chosen root_node

    New metrics:
        - Path-F1(Jaccard)
        - Path-F1(GT-Recall)
        - EdgeCoverage
        - PredictedPathCount
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

    for (t_s, t_e, t_eval) in window_iter():
        tic = time.perf_counter()

        # pick predicted root
        root_node = pick_root_in_window(candidates, int(t_s), int(t_e))
        if root_node is None:
            latencies.append((time.perf_counter()-tic)*1000)
            continue

        # time window expansion
        # ts_root = timestamps.get(root_node)
        # if ts_root:
        #     t_s_dyn = ts_root - 3*365*86400*1000
        #     t_e_dyn = ts_root + 1*365*86400*1000
        # else:
        #     t_s_dyn, t_e_dyn = t_s, t_e

        pcfg = PathConfig(
            t_start= t_s,
            t_end= t_e,
            # t_start=t_s_dyn,
            # t_end=t_e_dyn,
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

        # compute vs ALL GT roots
        node_gt_paths = []
        for rid in gt_root_ids:
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

def benchmark_full(
    depgraph,
    tempcent,
    node_cve_scores: Dict[Any, float],
    nodeid_to_texts: Dict[Any, List[str]],
    events: List[Dict[str, Any]],
    window_iter,
    gt_root_ids,
    gt_paths_by_root,        # ★ GT for path
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
    ''' Full benchmark integrating:
        (A) temporal community detection
        (B) root selection inside community
        (C) path search from predicted root
        (D) fusion scoring
    Ground truth is entirely from ref_paths:
        - root GT = gt_root_by_cve[cve_id]
        - path GT = gt_paths_by_root[root_id]
    
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

    commres = tcd.detect_communities(depgraph)

    for (t_s, t_e, t_eval) in window_iter():

        if isinstance(t_eval, datetime):
            t_eval = t_eval.timestamp()*1000

        # event-based ranking
        ev = next((e for e in events if abs(e["t"]-t_eval)<window_size*86400000), None)
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

        # GT root → ALL roots
        for rid in gt_root_ids:
            if rid not in depgraph:
                continue
            hit_list.append(1.0 if rid in comm_nodes else 0.0)
            neigh = set(depgraph.neighbors(rid))|{rid}
            cov_list.append(len(neigh & comm_nodes)/len(neigh))
            purity_list.append(len(neigh & comm_nodes)/len(comm_nodes))

            # rank of GT root inside community
            if rid in cent_scores:
                sorted_nodes = sorted(cent_scores, key=lambda x: cent_scores[x], reverse=True)
                root_rank_list.append(sorted_nodes.index(rid)+1)

        # time window expansion
        # ts_root = timestamps.get(predicted_root)
        # if ts_root:
        #     t_s_dyn = ts_root - 3*365*86400*1000
        #     t_e_dyn = ts_root + 1*365*86400*1000
        # else:
        #     t_s_dyn, t_e_dyn = t_s, t_e

        pcfg = PathConfig(
            t_start= t_s,
            t_end= t_e,
            # t_start=t_s_dyn,
            # t_end=t_e_dyn,
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
        for rid in gt_root_ids:
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
    gt_layer = []
    if args.ref_layer:
        gt_layer = read_jsonl(args.ref_layer)
    if not gt_layer:
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

    return gt_layer


def main():
    parser = argparse.ArgumentParser(description="Benchmark with optional ground truth")
    parser.add_argument("--ref-layer", type=str, help="Path to ref_paths_layer.jsonl", default=None)

    args, unknown = parser.parse_known_args()
    
    print("\n=== [1] Loading Ground Truth ===")
    gt_layer = load_ground_truth(args)
    gt_paths_by_root, gt_root_by_cve, gt_paths_by_cve = parse_ref_paths(gt_layer)

    data_dir = Path.cwd().joinpath("data")

    # core inputs
    dep_path   = data_dir.joinpath("dep_graph_cve.pkl")
    # cache from root_ana
    node_texts_path = data_dir.joinpath("nodeid_to_texts.pkl")
    per_cve_path = data_dir.joinpath("per_cve_scores.pkl")  
    node_scores_path = data_dir.joinpath("node_cve_scores.pkl")
    # cache from vamana
    cve_meta_path = data_dir.joinpath("cve_records_for_meta.pkl")

    with dep_path.open("rb") as f:
        depgraph = pickle.load(f)
    
    # control graph to subgraph stick to node with cve
    print(f"[info] Graph loaded: {depgraph.number_of_nodes()} nodes, {depgraph.number_of_edges()} edges")

    print("\n=== [Quick Test] Building structure-preserving subgraph ===")
    # 1) Collect *all* nodes that appear in GT paths
    gt_required_nodes = set()
    if gt_layer:
        for item in gt_layer:
            for e in item.get("path", []):
                gt_required_nodes.add(e["src"])
                gt_required_nodes.add(e["dst"])
    else:
        gt_required_nodes = set()

    print(f"[info] GT requires {len(gt_required_nodes)} nodes")

    # ------------------------------------------------------------
    # 2) Check missing GT nodes
    # ------------------------------------------------------------
    missing = [n for n in gt_required_nodes if n not in depgraph]
    if missing:
        print(f"[WARN] {len(missing)} GT nodes missing from depgraph → "
            f"these GT paths will have broken segments.")
    else:
        print("[info] All GT path nodes exist in depgraph.")

    # ------------------------------------------------------------
    # 3) Collect 1-hop neighbors
    # ------------------------------------------------------------
    one_hop = set()
    for n in gt_required_nodes:
        if n in depgraph:
            one_hop.update(depgraph.predecessors(n))
            one_hop.update(depgraph.successors(n))

    print(f"[info] 1-hop neighbors collected: {len(one_hop)}")

    # ------------------------------------------------------------
    # 4) Collect 2-hop neighbors (neighbors of 1-hop)
    # ------------------------------------------------------------
    two_hop = set()
    for n in one_hop:
        if n in depgraph:
            two_hop.update(depgraph.predecessors(n))
            two_hop.update(depgraph.successors(n))

    print(f"[info] 2-hop neighbors collected: {len(two_hop)}")

    three_hop = set()
    for n in two_hop:
        if n in depgraph:
            three_hop.update(depgraph.predecessors(n))
            three_hop.update(depgraph.successors(n))

    print(f"[info] 3-hop neighbors collected: {len(three_hop)}")

    # ------------------------------------------------------------
    # 5) Combine GT nodes + neighbors
    # ------------------------------------------------------------
    keep = set(gt_required_nodes) | one_hop | two_hop | three_hop
    print(f"[info] Total nodes before cap: {len(keep)}")

    # ------------------------------------------------------------
    # 7) Build subgraph
    # ------------------------------------------------------------
    depgraph = depgraph.subgraph(keep).copy()
    print(f"[debug] Final subgraph: {depgraph.number_of_nodes()} nodes, "
        f"{depgraph.number_of_edges()} edges")

    # ------------------------------------------------------------
    # 8) Debug GT path coverage
    # ------------------------------------------------------------
    gt_nodes_all = gt_required_nodes
    pred_nodes = set(depgraph.nodes())
    overlap = len(gt_nodes_all & pred_nodes)

    print(f"[debug] GT node retention: {overlap}/{len(gt_nodes_all)} "
        f"({overlap/len(gt_nodes_all):.4f})")
    print("=== Quick-Test Subgraph Ready ===\n")


    # -------------- candidate selection ---------------
    gt_root_ids = { item["root_id"] for item in (gt_layer or [])
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
    
    comm = benchmark_community(depgraph,
                tempcent,
                node_cve_scores,
                events,
                window_iter,
                gt_root_ids,)
    
    all_metrics.update(comm)
    print("[info] Community benchmark done")
    print("current metrics:", all_metrics)

    # replace with fast method
    tempcent.degree_centrality = tempcent.degree_centrality_fast
    tempcent.eigenvector_centrality = tempcent.eigenvector_centrality_fast

    # centrality
    cen = benchmark_centrality(tempcent, events, window_iter, gt_root_ids)
    all_metrics.update(cen)
    print("[info] Centrality benchmark done")
    print("current metrics:", all_metrics)

    # path & full
    pathm = benchmark_paths(depgraph, tempcent, node_cve_scores, nodeid_to_texts, events, window_iter,
                            gt_root_ids, gt_paths_by_root,
                            k_neighbors=15, alpha=5.0, beta=0.0, gamma=0.0, k_paths=5, strict_increase=False, 
                            candidates=candidates,
                            )
    
    all_metrics.update(pathm)
    print("[info] Path benchmark done")
    print("current metrics:", all_metrics)

    fullm = benchmark_full(depgraph, tempcent, node_cve_scores, nodeid_to_texts, events, window_iter,
                           gt_root_ids, gt_paths_by_root,    
                           k_neighbors=15, alpha=5.0, beta=0.0, gamma=0.0, k_paths=5, strict_increase=False, 
                           fuse_lambda=0.6,
                            )
    all_metrics.update(fullm)

    print(all_metrics)

    print("\n=== [4] Benchmark Completed ===")

# ============================================================
# --- Entry Point ---
# ============================================================
if __name__ == "__main__":
    main()