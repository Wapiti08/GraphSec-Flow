'''
 # @ Create Time: 2025-09-23 10:11:07
 # @ Modified time: 2025-09-23 10:11:13
 # @ Description: side evaluation from quantitative checks and qualitative checks

 MRR: mean reciprocal rank -> the closer to 1, the better

 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import json
from typing import Iterable, Dict, List, Tuple, Optional, Any
import numpy as np
import networkx as nx

def _sim_from_dist(d: float) -> float:
    # map Euclidean distance to a bounded similarity for readability
    return 1.0 / (1.0 + float(d))

def eval_node_self_recall(vac, k: int = 5, sample_size: Optional[int] = 200, seed: int = 42):
    ''' 
    query the index with each stored point's own vector and check whether
    the original **node** appears in the top-k aggregated results.
    
    args:
        - sample_size: the corpus is large, keep sample_size for eval (e.g., 200–1000 pids) so it runs fast.
    '''
    pids = list(vac.pid_to_pair.keys())
    n_total = len(pids)
    if sample_size and sample_size < n_total:
        rng = np.random.default_rng(seed)
        pids = list(rng.choice(pids, size=sample_size, replace=False))
    n = len(pids)

    hits = 0
    mrr = 0.0

    for pid in pids:
        q = vac.ann.data[pid]
        target_node, _ = vac.pid_to_pair[pid]
        neighbors = vac.search(q, k=k, return_explanations=False)
        try:
            r = neighbors.index(target_node) + 1  # 1-based rank
            hits += 1
            mrr += 1.0 / r
        except ValueError:
            pass

    metrics = {
        "samples": n,
        "node_recall_at_k": hits / max(1, n),
        "node_mrr": mrr / max(1, n),
        "k": k,
        "population": n_total,
    }

    print(f"[eval] node_recall@{k}: {metrics['node_recall_at_k']:.3f}  "
          f"MRR: {metrics['node_mrr']:.3f}  (n={n}/{n_total})")
    return metrics


def top_similar_cve_pairs(vac, per_point_k: int = 5, top_pairs: int = 20) -> List[Dict[str, Any]]:
    '''
    For each point, grab per_point_k nearest other points from the ANN.
    compute similarity, and return the globally top 'top_pairs'
    useful to inspect duplicates / cluster tightness

    '''
    pairs = []
    seen = set()
    for pid in vac.pid_to_pair.keys():
        q = vac.ann.data[pid]
        cand_pids = vac.ann.search(q, k = per_point_k + 1)
        for cp in cand_pids:
            # bypass the target
            if cp == pid:
                continue
            a, b = sorted((pid, cp))
            key = (a,b)
            if key in seen:
                continue
            seen.add(key)
            d = vac.ann._distance(vac.ann.data[a], vac.ann.data[b])
            sim = _sim_from_dist(d)
            n1, cidx1 = vac.pid_to_pair[a]
            n2, cidx2 = vac.pid_to_pair[b]

            text1 = vac.nodeid_to_texts.get(n1, [None])[cidx1]
            text2 = vac.nodeid_to_texts.get(n2, [None])[cidx2]
            pairs.append({
                "similarity": sim,
                "pid_a": a, "node_a": n1, "cve_idx_a": cidx1, "text_a_snip": (text1[:120] + "…") if text1 and len(text1) > 120 else text1,
                "pid_b": b, "node_b": n2, "cve_idx_b": cidx2, "text_b_snip": (text2[:120] + "…") if text2 and len(text2) > 120 else text2,
            })

    pairs.sort(key=lambda x: x["similarity"], reverse=True)
    return pairs[:top_pairs]

def print_top_similar_pairs(vac, per_point_k: int = 5, top_pairs: int = 10):
    rows = top_similar_cve_pairs(vac, per_point_k=per_point_k, top_pairs=top_pairs)
    print(f"\n[eval] Top {len(rows)} most similar CVE text pairs (by 1/(1+d)):")
    for i, r in enumerate(rows, 1):
        print(f"{i}. sim={r['similarity']:.4f}  "
              f"A: node={r['node_a']} idx={r['cve_idx_a']} | B: node={r['node_b']} idx={r['cve_idx_b']}")
        if r['text_a_snip'] and r['text_b_snip']:
            print(f"    A: {r['text_a_snip']}")
            print(f"    B: {r['text_b_snip']}")


def write_eval_report(path: str, **sections):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sections, f, indent=2)
        print(f"[eval] wrote report -> {path}")
    except Exception as e:
        print(f"[eval] failed to write report: {e}")

def _hop_distance(G, a, b, mode: str="either"):
    '''
    return the hop distance between nodes a and b in graph G

    mode:
        - "forward": only follow out-edges from a
        - "backward": only follow in-edges to a
        - "undirected": treat as undirected
        - "either": try first forward, then backward, then undirected

    '''
    if G is None or a is None or b is None:
        return None
    try:
        if mode == "forward":
            return nx.shortest_path_length(G, source=a, target=b)
        if mode == "reverse":
            return nx.shortest_path_length(G, source=b, target=a)
        if mode == "undirected":
            return nx.shortest_path_length(G.to_undirected(), source=a, target=b)
        
        # either
        try:
            return nx.shortest_path_length(G, source=a, target=b)
        except Exception:
            try:
                return nx.shortest_path_length(G, source=b, target=a)
            except Exception:
                return nx.shortest_path_length(G.to_undirected(), source=a, target=b)
    except Exception:
        return None