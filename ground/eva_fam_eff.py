'''
 # @ Create Time: 2025-10-29 10:59:29
 # @ Modified time: 2025-10-29 11:08:36
 # @ Description:

 Evaluate the impact of family merging on dependency graph
and ground-truth path generation.
 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import os
from utils.util import _safe_load_pickle, read_jsonl
import json
from depdata.ana_fam_merge import debug_families, build_release_index_from_depgraph
import time
import subprocess

# ============================================================
# Helper: summarize ref_paths (non-empty ratio)
# ============================================================
def summarize_ref_paths(file_path: str, label: str):
    if not os.path.exists(file_path):
        print(f"[WARN] {label} file not found at {file_path}")
        return {"total": 0, "nonempty": 0, "ratio": 0.0}

    data = read_jsonl(file_path)
    total = len(data)
    nonempty = sum(1 for r in data if r.get("path"))
    ratio = round(nonempty / total, 4) if total else 0.0
    print(f"[{label}] total={total}, non_empty={nonempty}, ratio={ratio:.3f}")
    return {"total": total, "nonempty": nonempty, "ratio": ratio}

# ============================================================
# Core Evaluation Logic
# ============================================================
def evaluate_family_merge(depgraph_path, cve_meta_path, out_root, out_paths):
    start = time.time()
    print(f"=== [1] Load dependency graph ===")
    G = _safe_load_pickle(Path(depgraph_path))
    print(f"[Graph] nodes={len(G):,}, edges={len(G.edges):,}")

    # 输出路径
    ref_path_before = out_paths
    ref_path_after = out_paths.replace(".jsonl", "_family.jsonl")
    root_path_after = out_root.replace(".jsonl", "_family.jsonl")

    # Step 1: Run gt_builder (normal mode)
    print("\n=== [2] Build Ground Truth (Normal Mode) ===")
    subprocess.run(
        [
            sys.executable, "gt_builder.py",
            "--dep-graph", depgraph_path,
            "--cve-meta", cve_meta_path,
            "--out-root", out_root,
            "--out-paths", out_paths,
        ],
        check=True
    )
    stats_before = summarize_ref_paths(ref_path_before, "ref_paths (before merge)")

    # Step 2: Build family index (for inspection)
    print("\n=== [3] Build Family Merge Release Index ===")
    release_index = build_release_index_from_depgraph(G)
    debug_families(release_index, topn=10)

    # Step 3: Run gt_builder (family mode)
    print("\n=== [4] Build Ground Truth (Family Merge Mode) ===")
    env_fam = {**os.environ, "FAMILY_MODE": "1"}
    subprocess.run(
        [
            sys.executable, "gt_builder.py",
            "--dep-graph", depgraph_path,
            "--cve-meta", cve_meta_path,
            "--out-root", root_path_after,
            "--out-paths", ref_path_after,
        ],
        check=True,
        env=env_fam
    )
    stats_after = summarize_ref_paths(ref_path_after, "ref_paths_family (after merge)")

    # Step 4: Compare results
    delta = stats_after["ratio"] - stats_before["ratio"]
    print("\n=== [5] Comparison Summary ===")
    print(f"Non-empty path ratio: {stats_before['ratio']:.3f} → {stats_after['ratio']:.3f} ({delta:+.3f})")
    print(f"Runtime: {(time.time() - start):.1f}s")

    return {"before": stats_before, "after": stats_after, "delta": delta}


if __name__ == "__main__":
    depgraph_path = "/workspace/GraphSec-Flow/data/dep_graph_cve.pkl"
    cve_meta_path = "/workspace/GraphSec-Flow/data/cve_records_for_meta.pkl"
    out_root = "/workspace/GraphSec-Flow/data"
    out_causes = "/workspace/GraphSec-Flow/data/root_causes.jsonl"
    out_paths = "/workspace/GraphSec-Flow/data/ref_paths.jsonl"

    print("\n=== [4b] Build Ground Truth (Layer-Based Search Mode) ===")
    ref_path_layer = out_paths.replace(".jsonl", "_layer_subgraph_6.jsonl")
    root_path_layer = out_root.replace(".jsonl", "_layer_subgraph_6.jsonl")

    start = time.time()
    env_layer = {**os.environ, "LAYER_MODE": "1"}
    subprocess.run(
        [
            sys.executable, "gt_builder.py",
            "--dep-graph", depgraph_path,
            "--cve-meta", cve_meta_path,
            "--out-root", out_root,
            "--out-paths", out_root,
            # "--smoke-test",
        ],
        check=True,
        env=env_layer
    )

    stats_base = summarize_ref_paths(out_paths, "Baseline (Normal)")
    stats_layer = summarize_ref_paths(ref_path_layer, "Layer-Based (technical lag)")

    print("\n=== [5b] Layer-Based Comparison ===")
    print(f"Baseline ratio = {stats_base['ratio']:.3f}")
    print(f"Layer    ratio = {stats_layer['ratio']:.3f} "
          f"(Δ {stats_layer['ratio'] - stats_base['ratio']:+.3f})")
    print(f"Runtime: {(time.time() - start):.1f}s")

    # start from beginning
    # evaluate_family_merge(depgraph_path, cve_meta_path, out_root, out_paths)

    # start from step [3]
    # G = _safe_load_pickle(Path(depgraph_path))
    # print("\n=== [3] Build Family Merge Release Index ===")
    # release_index = build_release_index_from_depgraph(G)
    # debug_families(release_index, topn=10)

    # ref_path_before = out_paths
    # ref_path_after = out_paths.replace(".jsonl", "_family.jsonl")
    # root_path_after = out_root.replace(".jsonl", "_family.jsonl")

    # start = time.time()

    # # Step 3: Run gt_builder (family mode)
    # print("\n=== [4] Build Ground Truth (Family Merge Mode) ===")
    # env_fam = {**os.environ, "FAMILY_MODE": "1"}
    # subprocess.run(
    #     [
    #         sys.executable, "gt_builder.py",
    #         "--dep-graph", depgraph_path,
    #         "--cve-meta", cve_meta_path,
    #         "--out-root", root_path_after,
    #         "--out-paths", ref_path_after,
    #     ],
    #     check=True,
    #     env=env_fam
    # )
    # stats_before = summarize_ref_paths(out_paths, "ref_paths_family (after merge)")
    # stats_after = summarize_ref_paths(ref_path_after, "ref_paths_family (after merge)")

    # # Step 4: Compare results
    # delta = stats_after["ratio"] - stats_before["ratio"]
    # print("\n=== [5] Comparison Summary ===")
    # print(f"Non-empty path ratio: {stats_before['ratio']:.3f} → {stats_after['ratio']:.3f} ({delta:+.3f})")
    # print(f"Runtime: {(time.time() - start):.1f}s")

    # print({"before": stats_before, "after": stats_after, "delta": delta})
