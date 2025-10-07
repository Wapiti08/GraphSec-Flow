'''
 # @ Create Time: 2025-10-07 10:36:08
 # @ Modified time: 2025-10-07 10:36:10
 # @ Description: robustness evaluation for different component settng ups
 - edge deletion
 - timestamp perturbation
 - text shuffling
 
 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import copy, random
import re
from datetime import timedelta
from ground.gt_builder import DepGraph, GTBuilder

RND = random.Random(42)

def delete_edges(g: DepGraph, p: float) -> DepGraph:
    g2 = copy.deepcopy(g)

    # collect all edges
    all_edges = []
    for src, lst in g2.adj.items():
        for e in lst:
            all_edges.append((e.src, e.dst))
    
    # randomly delete p% edges
    k = int(len(all_edges) * p)
    to_del = set(RND.sample(all_edges, k)) if k>0 else set()
    # recontruct adj
    g2.adj = {src: [e for e in lst if (e.src, e.dst) not in to_del] for src, lst in g2.adj.items()}
    # synchronize rev_adj
    g2.rev = {}
    for src, lst in g2.adj.items():
        for e in lst:
            g2.rev.setdefault(e.dst, []).append(e)
    return g2

def perturb_timestamps(g: DepGraph, days_min=1, days_max=7) -> DepGraph:
    g2 = copy.deepcopy(g)
    for nid, node in g2.nodes.items():
        if node.time is None:
            continue
        delta = RND.randint(days_min, days_max)
        sign = -1 if RND.random() < 0.5 else 1
        node.time = node.time + sign * timedelta(days=delta)
    
    return g2

# ---------------------------
# Text shuffling: check whether semantic information matters, do not change verions
# ---------------------------

def shuffle_text(s: str) -> str:
    toks = re.findall(r"\w+|\W", s or "")
    RND.shuffle(toks)
    return "".join(toks)

def placebo_osv(osv_records):
    osv2 = copy.deepcopy(osv_records)
    for r in osv2:
        if "details" in r and isinstance(r["details"], str):
            r["details"] = shuffle_text(r["details"])
    
    return osv2


# ----------------------------
# Testing noise on gt_builder
# ----------------------------
def run_once(dep_graph, osv_records, nvd_records, *, prefer_upstream=True, time_constrained=True):
    builder = GTBuilder(
        dep_graph=dep_graph,
        osv_records=osv_records,
        nvd_records=nvd_records,
        prefer_upstream_direction=prefer_upstream,
    )
    roots = builder.build_root_causes()
    paths = builder.build_reference_paths(
        roots=roots,
        max_depth=6,
        time_constrained=time_constrained
    )
    return roots, paths