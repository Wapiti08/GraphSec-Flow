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
from com.commdet import VL
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
        


if __name__ == "__main__":

    # load dependency graph with cve info
    cve_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl")

    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)
    
    # generate cve_records_for_meta
    nodeid_to_texts: Dict[Any, List[str]] = {}
    cve_records_for_meta: Dict[Any, List[Dict[str, Any]]] = {}
    fallback_used = 0
    osv_hits = 0
    dropped = 0
    
    TEXT_KEYS = ["details", "summary", "description"]

    # warm up the persistent cache once per unique CVE id
    unique_cve_ids = {
        cid for _, attrs in depgraph.nodes(data=True) 
        for cid in ([_normalize_cve_id(x) for x in (attrs.get("cve_list") or [])])
        if cid
    }

    for cid in unique_cve_ids:
        try:
            _ = osv_cve_api(cid)
        except Exception:
            pass
    
    for nid, attrs in depgraph.nodes(data=True):
        raw_list = attrs.get("cve_list", []) or []
        texts: List[str] = []
        metas: List[Dict[str, Any]] = []

        for raw in raw_list:
            cid = _normalize_cve_id(raw)
            if not cid:
                dropped += 1
                continue

            # Try OSV first
            rec: Dict[str, Any] = {}
            try:
                rec = osv_cve_api(cid) or {}
            except Exception as e:
                rec = {"_error": str(e)}
            
            text = _first_nonempty(rec, TEXT_KEYS)
            
            # Fallback: synthesize a minimal text from the node's dict if OSV had nothing
            if not text and isinstance(raw, dict):
                text = _synth_text_from_dict(cid, raw)
                if text:
                    fallback_used += 1
            elif text:
                osv_hits += 1

            if not text:
                dropped += 1
                continue

            texts.append(text)
            metas.append({
                "name": rec.get("id") or rec.get("name") or cid,
                "severity": rec.get("severity") or rec.get("cvss") or rec.get("cvssScore"),
                "timestamp": rec.get("published") or rec.get("modified"),
            })
        
        if texts:
            nodeid_to_texts[nid] = texts
            cve_records_for_meta[nid] = metas
    
    if not nodeid_to_texts:
        raise RuntimeError("No CVE texts found. Nodes had empty cve_list or OSV lookups returned no detail.")

    # create tempcent instance
    tempcent = TempCentricity(depgraph, search_scope='auto')

    # -------- build t_eval_list --------------

    # global data bounds from cve_records_for_meta
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

    lookback_days = 90        # window length
    stride_days   = 7         # eval cadence (weekly)

    # start a bit earlier so the first window has context
    start = earliest - timedelta(days=lookback_days + 1)

    t_eval_list = [d.date() for d in pd.date_range(start=start, end=latest, freq=f"{stride_days}D", inclusive="both")]

    events = build_events_from_vamana_meta(
            depgraph,
            cve_records_for_meta,
            t_eval_list,
            fallback_to_release=True, 
    )

    # create window function
    ref_type = pd.Timestamp.now(tz="UTC")

    def window_iter():
        for d_eval in t_eval_list:
            d_s = d_eval - timedelta(days = lookback_days)
            d_e = d_eval
            yield (
                _to_same_type(d_s, ref_type),
                _to_same_type(d_e, ref_type),
                d_eval, 
            )

    metrics = benchmark_centrality(tempcent, events, window_iter)
    print(metrics)


