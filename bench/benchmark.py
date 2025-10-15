'''
 # @ Create Time: 2025-10-02 17:32:12
 # @ Modified time: 2025-10-02 17:32:13
 # @ Description: benchmark for different component settng ups
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import time
from eval.evaluation import _pick_total
# ------ import core modules ------
from cent.temp_cent import TempCentricity
from com.commdet import TemporalCommDetector
from src.path_track import PathConfig, RootCausePathAnalyzer
from search.vamana import VamanaSearch, CVEVector, VamanaOnCVE
from eval.evaluation import _zscore, _rank_metrics, _lead_time

# ------- import helper functions -------
from eval.evaluation import _zscore, _rank_metrics, _lead_time, _pick_total
from eval.events import build_events_from_vamana_meta
import pickle
from cve.cvescore import _normalize_cve_id
from utils.util import _first_nonempty, _synth_text_from_dict
from typing import Dict, List, Tuple, Optional, Any
from cve.cveinfo import osv_cve_api
from eval.events import _first_cve_data_of_node, _last_cve_data_of_node, _to_same_type
from datetime import datetime, timedelta
import pandas as pd
from bench.helper import load_cached_scores, _safe_node_timestamps, _mask_or_fill, _f1_from_paths

def benchmark_centrality(tempcent: TempCentricity, events, window_iter):
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

    results = {}

    # dynamic centrality
    for name in ["Static-DC", "Static-EVC"]:
        latencies = []
        mrrs, h3s = [], []
        series_scores = []
        for (t_s, t_e, t_eval) in window_iter():
            tic = time.perf_counter()
            raw = variants[name]()
            latencies.append((time.perf_counter() - tic) * 1000.0)
            norm = _zscore(raw)
            series_scores.append((t_eval, norm))
            ev = next((e for e in events if e['t'] == t_eval), None)
            if ev:
                mrr, h3 = _rank_metrics(norm, ev["targets"])
                mrrs.append(mrr)
                h3s.append(h3)
        
        results[name] = {
            "MRR": sum(mrrs) / len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s) / len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=1.0),
            "Latency (ms)": sum(latencies) / len(latencies) if latencies else 0.0,
            "Hit-Community": "--",
            "CommCoverage":  "--",
            "Path-F1": "--",
        }

    # dynamic centrality
    for name, fn in [
        ("Temporal-DC", lambda t_s, t_e: _pick_total(tempcent.degree_centrality(t_s, t_e))),
        ("Temporal-EVC", lambda t_s, t_e: tempcent.eigenvector_centrality(t_s, t_e)),
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
            ev = next((e for e in events if e["t"] == t_eval), None)
            if ev:
                mrr, h3 = _rank_metrics(norm, ev["targets"])
                mrrs.append(mrr); h3s.append(h3)

        results[name] = {
            "MRR": sum(mrrs) / len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s) / len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=1.0),
            "Latency (ms)": sum(latencies) / len(latencies) if latencies else 0.0,
            "Hit-Community": "--",
            "CommCoverage":  "--",
            "Path-F1": "--",
        }

    return results


def benchmark_community(depgraph, temcent, node_cve_scores: Dict[Any, float], events: List[Dict[str, Any]], window_iter):
    '''
    node_cve_scores: {node -> float} Cached per-node aggregate scores (from node_cve_scores.pkl)
    '''
    timestamps = _safe_node_timestamps(depgraph)

    # initialize community detector
    tcd = TemporalCommDetector(
        depgraph = depgraph,
        timestamps=timestamps,
        cve_scores=node_cve_scores,
        centrality_provider=temcent,
    )

    latencies = []
    mrrs, h3s = [], []
    series_scores = []
    hit_comm_flags = []
    coverages = []

    for (t_s, t_e, t_eval) in window_iter():
        tic = time.perf_counter()
        # return comm id and its score
        best_comm, cent_scores = tcd.choose_root_community(t_s, t_e)
        # return community result
        commres = tcd.detect_communities(t_s, t_e)
        latencies.append((time.perf_counter() - tic) * 1000.0)

        if best_comm is None or not commres or not commres.comm_to_nodes:
            continue

        # return the nodes in the best community
        root_nodes = set(commres.comm_to_nodes.get(best_comm, []))

        # ----- community metrics -----
        ev = next((e for e in events if e['t'] == t_eval), None)
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
            "LeadTime (days)": _lead_time(series_scores, events, thresh=1.0),
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
        strict_increase: bool=False
    ):
    ''' 
    automatically identify root source, construct temporal graph and weight edges,
    then find top-k paths from root to each target node, and evaluate the F1 score
    '''
    timestamps = _safe_node_timestamps(depgraph)

    # initialize path tracker
    embedder = CVEVector()
    ann = VamanaSearch()
    vamana = VamanaOnCVE(depgraph, nodeid_to_texts, embedder, ann)

    analyzer = RootCausePathAnalyzer(
        depgraph = depgraph,
        vamana = vamana,
        cve_scores = node_cve_scores,
        timestamps = timestamps,
        centrality=tempcent,
        search_scope="auto"
    )

    latencies = []
    mrrs, h3s, f1s = [], [], []
    series_scores = []

    for (t_s, t_e, t_eval) in window_iter():
        tic = time.perf_counter()
        # assign pathconfig to every window
        pcfg = PathConfig(
            t_start = float(pd.Timestamp(t_s).timestamp()),
            t_end = float(pd.Timestamp(t_e).timestamp()),
            strict_increase = strict_increase,
            alpha = alpha, beta=beta, gamma=gamma,
            k_paths = k_paths,
            targets = None, 
            similarity_scores=None
        )

        # root cause analysis with paths from t_s to t_e
        _, _, _D, paths_by_target, _records = analyzer.analyze_with_paths(
        k_neighbors=k_neighbors,
        t_start=pcfg.t_start,
        t_end=pcfg.t_end,
        path_cfg=pcfg,
        explain=False
        )

        # recrod frequency of nodes in paths
        node_score: Dict[Any, float] = {}
        for tgt, paths in paths_by_target.items():
            for p in paths:
                for n in p:
                    node_score[n] = node_score.get(n, 0.0) + 1.0
        
        latencies.append((time.perf_counter() - tic) * 1000.0)

        if not node_score:
            continue

        norm = _zscore(node_score)
        series_scores.append((t_eval, norm))

        ev = next((e for e in events if e['t'] == t_eval), None)
        if ev:
            mrr, h3 = _rank_metrics(norm, ev["targets"])
            mrrs.append(mrr); h3s.append(h3)
            f1 = _f1_from_paths(paths_by_target, set(ev["targets"]))
            f1s.append(f1)

    return {
        "Path": {
            "MRR": sum(mrrs)/len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s)/len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=1.0),
            "Latency (ms)": sum(latencies)/len(latencies) if latencies else 0.0,
            "Hit-Community": "--",
            "CommCoverage":  "--",
            "Path-F1": sum(f1s)/len(f1s) if f1s else 0.0,
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
    fuse_lambda: float = 0.6
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
        cve_scores=node_cve_scores,
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

    for (t_s, t_e, t_eval) in window_iter():
        tic = time.perf_counter()
        # A ) root community + centrality 
        best_comm, cent_scores = tcd.choose_root_community(t_s, t_e)
        commres = tcd.detect_communities(t_s, t_e)
        if best_comm is None or not commres or not commres.comm_to_nodes:
            latencies.append((time.perf_counter() - tic) * 1000.0)
            continue

        root_nodes = set(commres.comm_to_nodes.get(best_comm, []))
        # community scores
        comm_scores = {n: (cent_scores.get(n, 0.0) if n in root_nodes else 0.0)
                       for n in set(cent_scores.keys()) | root_nodes}

        # community hit metric
        ev = next((e for e in events if e['t'] == t_eval), None)
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
            pcfg = PathConfig(
                t_start = float(pd.Timestamp(t_s).timestamp()),
                t_end = float(pd.Timestamp(t_e).timestamp()),
                strict_increase = strict_increase,
                alpha = alpha, beta=beta, gamma=gamma,
                k_paths = k_paths,
                targets = None,
                similarity_scores=None
            )
        
        _, _, _D, paths_by_target, _records = analyzer.analyze_with_paths(
            k_neighbors=k_neighbors,
            t_start=pcfg.t_start,
            t_end=pcfg.t_end,
            path_cfg=pcfg,
            explain=False
        )

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
            f1s.append(_f1_from_paths(paths_by_target, set(ev["targets"])))

    return {
        "Full": {
            "MRR": sum(mrrs)/len(mrrs) if mrrs else 0.0,
            "Hits@3": sum(h3s)/len(h3s) if h3s else 0.0,
            "LeadTime (days)": _lead_time(series_scores, events, thresh=1.0),
            "Latency (ms)": sum(latencies)/len(latencies) if latencies else 0.0,
            "Hit-Community": sum(hit_comm_flags)/len(hit_comm_flags) if hit_comm_flags else 0.0,
            "CommCoverage":  sum(coverages)/len(coverages) if coverages else 0.0,
            "Path-F1": sum(f1s)/len(f1s) if f1s else 0.0,
        }
    }

if __name__ == "__main__":

    data_dir = Path.cwd().parent.joinpath("data")

    # core inputs
    dep_path   = data_dir.joinpath("dep_graph_cve.pkl")
    # cache from root_ana
    node_texts_path = data_dir.joinpath("nodeid_to_texts.pkl")
    per_cve_path = data_dir.joinpath("per_cve_scores.pkl")  
    node_scores_path = data_dir.joinpath("node_cve_scores.pkl")
    # cache from vamana
    cve_meta_path = data_dir.joinpath("cve_records_for_meta.pkl")

    # ---------- load dependency graph -----------
    with dep_path.open("rb") as f:
        depgraph = pickle.load(f)
    
    # ---------- load nodeid_to_texts & cve_records_for_meta -----------
    nodeid_to_texts = pickle.loads(node_texts_path.read_bytes())
    cve_records_for_meta = pickle.loads(cve_meta_path.read_bytes())
    print("[cache] nodeid_to_texts & cve_records_for_meta loaded")

    # ---------- load per_cve_scores & node_cve_scores -----------
    per_cve_scores = None
    node_cve_scores = None
    if per_cve_path.exists():
        per_cve_scores = pickle.loads(per_cve_path.read_bytes())
        print("[cache] per_cve_scores loaded")
    if node_scores_path.exists():
        node_cve_scores = pickle.loads(node_scores_path.read_bytes())
        print("[cache] node_cve_scores loaded")
    
    # --------- centrality provider ---------
    tempcent = TempCentricity(depgraph, search_scope="auto")

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

    lookback_days = 90
    stride_days   = 7

    start = earliest - timedelta(days=lookback_days+1)
    t_eval_list = [d.date() for d in pd.date_range(start=start, end=latest, freq=f"{stride_days}D", inclusive="both")]

    events = build_events_from_vamana_meta(
        depgraph,
        cve_records_for_meta,
        t_eval_list,
        fallback_to_release=True
    )
    print(f"[info] {len(events)} evaluation events from {t_eval_list[0]} to {t_eval_list[-1]}")

    # ------- time window iterator ---------
    ref_type = pd.Timestamp.now(tz="UTC")
    def window_iter():
        for d_eval in t_eval_list:
            d_s = d_eval - timedelta(days=lookback_days)
            d_e = d_eval
            yield (
                _to_same_type(d_s, ref_type),
                _to_same_type(d_e, ref_type),
                d_eval,
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

    # centrality
    cen = benchmark_centrality(tempcent, events, window_iter)
    all_metrics.update(cen)
    print("[info] Centrality benchmark done")
    print("current metrics:", all_metrics)

    # path & full
    pathm = benchmark_paths(depgraph, tempcent, node_cve_scores, nodeid_to_texts, events, window_iter,
                            k_neighbors=15, alpha=1.0, beta=0.0, gamma=0.0, k_paths=5, strict_increase=False)
    all_metrics.update(pathm)
    print("[info] Path benchmark done")
    print("current metrics:", all_metrics)

    fullm = benchmark_full(depgraph, tempcent, node_cve_scores, nodeid_to_texts, events, window_iter,
                           k_neighbors=15, alpha=1.0, beta=0.0, gamma=0.0, k_paths=5, strict_increase=False, fuse_lambda=0.6)
    all_metrics.update(fullm)

    print(all_metrics)