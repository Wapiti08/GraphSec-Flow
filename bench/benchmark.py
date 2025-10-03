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
from cent.temp_cent import TempCentricity
from eval.evaluation import _zscore, _rank_metrics, _lead_time, _pick_total
from eval.events import build_events_from_vamana_meta
import pickle


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


if __name__ == "__main__":

    # load dependency graph with cve info
    cve_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl")

    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)
    


    events = build_events_from_vamana_meta(
            depgraph,
            cve_records_for_meta,
            t_eval_list,
            fallback_to_release=True, 
    )

    metrics = benchmark_centrality(tempcent, events, window_iter)
    print(metrics)