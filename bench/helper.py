'''
 # @ Create Time: 2025-10-07 11:54:23
 # @ Modified time: 2025-10-07 11:54:24
 # @ Description: the help functions for benchmark and robustness evaluation
 '''

from pathlib import Path
import pickle
import time
from typing import Dict, List, Tuple, Optional, Any, Set

def load_cached_scores():
    data_dir = Path.cwd().parent.joinpath("data")

    per_cve_scores_path = data_dir.joinpath("per_cve_scores.pkl")
    node_cve_scores_path = data_dir.joinpath("node_cve_scores.pkl")

    if not per_cve_scores_path.exists() or not node_cve_scores_path.exists():
        raise FileNotFoundError("Cached score files not found. Please run the initial setup (root_ana) to generate them.")

    with per_cve_scores_path.open("rb") as fr:
        per_cve_scores = pickle.load(fr)
    with node_cve_scores_path.open("rb") as fr:
        node_cve_scores = pickle.load(fr)
    
    print(f"[load] Loaded {len(per_cve_scores)} CVE scores and {len(node_cve_scores)} node scores.")
    return per_cve_scores, node_cve_scores

def _safe_node_timestamps(depgraph):
    ts = {}
    for n, a in depgraph.nodes(data=True):
        v = a.get("timestamp")
        if v is None:
            continue
        try:
            ts[n] = float(v)
        except Exception:
            try:
                ts[n] = float(getattr(v, "timestamp"))
            except Exception:
                pass
    return ts

def _mask_or_fill(scores: Dict, keep: Set, fill=0.0) -> Dict:
    if not scores:
        return {}
    nodes = set(scores.keys()) | set(keep)
    return {n: (scores.get(n, 0.0) if n in keep else fill) for n in nodes}

def _f1_from_paths(paths_dict, targets: Set)-> float:
    if not paths_dict:
        return 0.0
    pred_nodes = set()
    for _t, paths in paths_dict.items():
        for p in paths:
            pred_nodes.update(p)
    if not pred_nodes or not targets:
        return 0.0
    
    tp = len(pred_nodes & targets)
    fp = len(pred_nodes - targets)
    fn = len(targets - pred_nodes)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    return (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

def path_f1_partial_match(gt_paths, pred_paths, overlap_thresh=0.5):
    """
    Compute Path-F1 with partial matching (by node overlap).
    """
    tp = 0
    fp = 0
    fn = 0

    for p_pred in pred_paths:
        pred_nodes = set(p_pred)
        matched = False
        for p_gt in gt_paths:
            gt_nodes = set(p_gt)
            overlap = len(pred_nodes & gt_nodes) / len(pred_nodes | gt_nodes)
            if overlap >= overlap_thresh:
                tp += 1
                matched = True
                break
        if not matched:
            fp += 1

    fn = len(gt_paths) - tp

    precision = tp / (tp + fp + 1e-9)
    recall = tp / (tp + fn + 1e-9)
    f1 = 2 * precision * recall / (precision + recall + 1e-9)
    return f1