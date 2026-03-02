"""
Depth Limit Ablation
Validates the dmax=6 heuristic for ground-truth BFS construction.

Usage (run from project root):
    python validation/depth_ablation.py \
        --dep-graph  data/dep_graph_cve.pkl \
        --cve-meta   data/cve_meta.pkl \
        --predictions data/validation/predictions.json \
        --depths 2 3 4 6 8 \
        --out    data/validation/depth_ablation.json

What it measures for each dmax:
  • n_paths          total reference paths generated
  • n_unique_roots   unique CVE roots covered
  • mean_path_len    average BFS path length (edges)
  • max_path_len     maximum path length seen
  • recall_vs_6      fraction of dmax=6 paths also found at this depth
  • mrr              mean reciprocal rank against predictions.json
  • new_paths_ratio  fraction of paths first appearing at this depth
                     (marginal gain — flattens when deeper adds noise)
"""

import argparse
import json
import pickle
import sys
import time
from collections import defaultdict
from pathlib import Path

# ── path setup ──────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from ground.gt_builder import GTBuilder, DepGraph
from ground.helper import (
    build_release_index_from_depgraph,
    split_cve_meta_to_builder_inputs,
)
from utils.util import _safe_load_pickle
from cve.graph_cve import extract_cve_subgraph


# ────────────────────────────────────────────────────────────────────
# MRR helper
# ────────────────────────────────────────────────────────────────────
def compute_mrr(paths, predictions):
    """
    paths       : list of ReferencePath objects (for one dmax)
    predictions : dict  cve_id -> [node_id, ...]   (ranked list)

    For each (cve_id, root_id) in paths, look up the rank of root_id
    in predictions[cve_id] and accumulate reciprocal rank.
    Returns mean reciprocal rank (float).
    """
    rr_list = []
    for p in paths:
        cve  = p.cve_id
        root = p.root_id
        preds = predictions.get(cve, [])
        if not preds:
            continue
        try:
            rank = preds.index(root) + 1          # 1-indexed
            rr_list.append(1.0 / rank)
        except ValueError:
            rr_list.append(0.0)                   # root not in preds
    return sum(rr_list) / len(rr_list) if rr_list else 0.0


# ────────────────────────────────────────────────────────────────────
# Path-set fingerprint (cve_id + sorted edge set)
# ────────────────────────────────────────────────────────────────────
def path_fingerprint(p):
    edges = frozenset((e.src, e.dst) for e in p.path)
    return (p.cve_id, edges)


# ────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Depth-limit ablation for GT builder")
    ap.add_argument("--dep-graph",    required=True)
    ap.add_argument("--cve-meta",     default=None)
    ap.add_argument("--predictions",  required=True,
                    help="predictions.json from batch_predict.py")
    ap.add_argument("--depths",       type=int, nargs="+",
                    default=[2, 3, 4, 6, 8])
    ap.add_argument("--out",          default="data/validation/depth_ablation.json")
    ap.add_argument("--no-time-constraint", action="store_true")
    args = ap.parse_args()

    time_constrained = not args.no_time_constraint
    depths = sorted(args.depths)

    # ── 1. Load graph ────────────────────────────────────────────────
    print("Loading dependency graph …")
    t0 = time.time()
    loaded = _safe_load_pickle(Path(args.dep_graph))

    if not isinstance(loaded, DepGraph):
        print("  Converting networkx → DepGraph …")
        obj = {"nodes": [], "edges": []}
        for nid, data in loaded.nodes(data=True):
            obj["nodes"].append({"id": nid, **data})
        for src, dst, edata in loaded.edges(data=True):
            e = {"src": src, "dst": dst}
            if "time" in edata:
                e["time"] = edata["time"]
            obj["edges"].append(e)
        G = DepGraph.from_json(obj)
    else:
        G = loaded

    print(f"  Graph: {len(G.nodes):,} nodes, "
          f"{sum(len(v) for v in G.adj.values()):,} edges  "
          f"({time.time()-t0:.1f}s)")

    # ── 2. Load CVE metadata ─────────────────────────────────────────
    if args.cve_meta:
        print("Loading CVE metadata …")
        cve_meta = _safe_load_pickle(Path(args.cve_meta))
        osv_records, nvd_records = split_cve_meta_to_builder_inputs(cve_meta)
    else:
        osv_records, nvd_records = [], []
    print(f"  OSV: {len(osv_records):,}  NVD: {len(nvd_records):,}")

    # ── 3. Load predictions ──────────────────────────────────────────
    print("Loading predictions …")
    with open(args.predictions) as f:
        predictions = json.load(f)
    print(f"  {len(predictions):,} CVEs")

    # ── 4. Build roots ONCE ──────────────────────────────────────────
    print("\nBuilding root causes (once) …")
    builder = GTBuilder(
        dep_graph=G,
        osv_records=osv_records,
        nvd_records=nvd_records,
        prefer_upstream_direction=True,
    )
    t1 = time.time()
    roots = builder.build_root_causes()
    print(f"  {len(roots):,} roots  ({time.time()-t1:.1f}s)")

    # ── 5. Sweep depths ──────────────────────────────────────────────
    results   = {}
    paths_d6  = None   # reference set at dmax=6 for recall_vs_6

    for dmax in depths:
        print(f"\n── dmax={dmax} ──────────────────────────────────")
        t2 = time.time()

        paths = builder.build_reference_paths(
            roots=roots,
            max_depth=dmax,
            time_constrained=time_constrained,
        )
        elapsed = time.time() - t2

        # basic stats
        n_paths   = len(paths)
        cve_set   = {p.cve_id for p in paths}
        lengths   = [len(p.path) for p in paths]
        mean_len  = sum(lengths) / len(lengths) if lengths else 0.0
        max_len   = max(lengths) if lengths else 0

        # MRR against predictions
        mrr = compute_mrr(paths, predictions)

        # fingerprint set
        fps = {path_fingerprint(p) for p in paths}

        # marginal gain vs previous depth
        prev_depth = depths[depths.index(dmax) - 1] if depths.index(dmax) > 0 else None
        if prev_depth is not None and prev_depth in results:
            prev_fps = results[prev_depth]["_fps"]
            new_paths = fps - prev_fps
            new_ratio = len(new_paths) / len(fps) if fps else 0.0
        else:
            new_paths = fps
            new_ratio = 1.0

        # recall vs dmax=6 (filled after d=6 is processed)
        recall_vs_6 = None

        results[dmax] = {
            "dmax":           dmax,
            "n_paths":        n_paths,
            "n_unique_roots": len(cve_set),
            "mean_path_len":  round(mean_len, 3),
            "max_path_len":   max_len,
            "mrr":            round(mrr, 6),
            "new_paths_ratio":round(new_ratio, 4),
            "elapsed_s":      round(elapsed, 2),
            "_fps":           fps,           # internal — removed before save
        }

        if dmax == 6:
            paths_d6 = fps

        print(f"  paths={n_paths:,}  roots={len(cve_set):,}  "
              f"mean_len={mean_len:.2f}  MRR={mrr:.6f}  "
              f"new={new_ratio:.1%}  ({elapsed:.1f}s)")

    # ── 6. Back-fill recall_vs_6 ─────────────────────────────────────
    if paths_d6 is not None:
        for dmax, r in results.items():
            fps = r["_fps"]
            r["recall_vs_6"] = round(len(fps & paths_d6) / len(paths_d6), 4) \
                               if paths_d6 else None

    # ── 7. Clean & save ──────────────────────────────────────────────
    clean = {}
    for dmax, r in results.items():
        c = {k: v for k, v in r.items() if not k.startswith("_")}
        clean[dmax] = c

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(clean, f, indent=2)

    # ── 8. Print summary table ───────────────────────────────────────
    print("\n" + "="*75)
    print(" DEPTH ABLATION RESULTS ".center(75, "="))
    print("="*75)
    print(f"{'dmax':<6} {'Paths':>8} {'Roots':>7} {'AvgLen':>8} "
          f"{'MRR':>10} {'New%':>7} {'vs_6':>7}")
    print("-"*75)
    for dmax in depths:
        r = clean[str(dmax)] if str(dmax) in clean else clean[dmax]
        print(f"{dmax:<6} {r['n_paths']:>8,} {r['n_unique_roots']:>7,} "
              f"{r['mean_path_len']:>8.2f} {r['mrr']:>10.6f} "
              f"{r['new_paths_ratio']:>6.1%} "
              f"{str(r.get('recall_vs_6','—')):>7}")
    print("="*75)
    print(f"\n✓ Results saved → {args.out}")
    print("\nPaper interpretation guide:")
    print("  • MRR stable across depths  → choice of dmax does not inflate metrics")
    print("  • recall_vs_6 near 1.0 for dmax≥4 → dmax=6 is sufficient")
    print("  • new_paths_ratio drops sharply after dmax=6 → deeper adds noise")


if __name__ == "__main__":
    main()