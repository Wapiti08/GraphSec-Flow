'''
 # @ Create Time: 2025-10-07 11:54:23
 # @ Modified time: 2025-10-07 11:54:24
 # @ Description: the help functions for benchmark and robustness evaluation
 '''

from pathlib import Path
import pickle
import time
from typing import Dict, List, Tuple, Optional, Any, Set


def avg(values):
    """
    Safely compute average of a list.
    - Ignores None
    - Returns 0.0 for empty or all-None lists
    """
    if not values:
        return 0.0
    vals = [v for v in values if v is not None]
    if not vals:
        return 0.0
    return sum(vals) / len(vals)

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

def _root_rank(scores: Dict[Any, float], root_id):
    """Return the 1-based rank of the GT root in descending sorted list."""
    if root_id not in scores:
        return None
    sorted_nodes = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
    return sorted_nodes.index(root_id) + 1

def _precision_at_k(scores: Dict[Any, float], root_id, k=5):
    """Return 1.0 if GT root is in top-K of sorted ranking."""
    sorted_nodes = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
    return 1.0 if root_id in sorted_nodes[:k] else 0.0

def _community_purity(pred_comm: set, root_neighbors: set):
    """Purity = overlap / size of predicted community"""
    if not pred_comm:
        return 0.0
    return len(pred_comm & root_neighbors) / len(pred_comm)

def _community_coverage(pred_comm: set, root_neighbors: set):
    """Coverage = overlap / size of GT root neighborhood"""
    if not root_neighbors:
        return 0.0
    return len(pred_comm & root_neighbors) / len(root_neighbors)


def convert_edges_to_seq(edge_list):
    """Convert list of edges into a node sequence."""
    seq = []
    for e in edge_list:
        if not seq:
            seq.append(e["src"])
        seq.append(e["dst"])
    return seq


def build_root_to_nodepaths(gt_paths_by_root):
    """root_id -> [node_seq1, node_seq2, ...]"""
    root_to_nodepaths = defaultdict(list)
    for rid, edge_lists in gt_paths_by_root.items():
        for edges in edge_lists:
            seq = convert_edges_to_seq(edges)
            root_to_nodepaths[rid].append(seq)
    print(f"[GT] Loaded {sum(len(v) for v in root_to_nodepaths.values())} GT node paths.")
    return root_to_nodepaths


def _edge_coverage(gt_paths, pred_paths):
    """Compute edge-level recall between predicted and GT paths."""
    def edges(p):
        return {(p[i], p[i+1]) for i in range(len(p)-1)}

    gt_edges = set().union(*[edges(p) for p in gt_paths]) if gt_paths else set()
    pred_edges = set().union(*[edges(p) for p in pred_paths]) if pred_paths else set()

    if not gt_edges:
        return 0.0
    return len(gt_edges & pred_edges) / len(gt_edges)

def path_f1_partial_match(gt_paths, pred_paths, overlap_thresh=0.5, mode="jaccard"):
    """
    Compute Path-F1 with partial matching (by node overlap).
    Supports 'jaccard' or 'gt_recall' overlap mode.
    """
    if not gt_paths or not pred_paths:
        return 0.0

    tp = fp = 0
    for p_pred in pred_paths:
        pred_nodes = set(p_pred)
        matched = False
        for p_gt in gt_paths:
            gt_nodes = set(p_gt)
            if not gt_nodes:
                continue
            if mode == "gt_recall":
                overlap = len(pred_nodes & gt_nodes) / len(gt_nodes)
            else:
                overlap = len(pred_nodes & gt_nodes) / len(pred_nodes | gt_nodes)
            if overlap >= overlap_thresh:
                tp += 1
                matched = True
                break
        if not matched:
            fp += 1

    fn = max(0, len(gt_paths) - tp)
    precision = tp / (tp + fp + 1e-9)
    recall = tp / (tp + fn + 1e-9)
    f1 = 2 * precision * recall / (precision + recall + 1e-9)
    return f1