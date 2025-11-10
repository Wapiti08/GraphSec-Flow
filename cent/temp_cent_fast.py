'''
 # @ Create Time: 2025-06-24 16:42:30
 # @ Modified time: 2025-06-24 16:42:32
 # @ Description: temporal centricity calculation for nodes in a graph

the timestamp is one of the attributes of nodes

 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import networkx as nx
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures import ThreadPoolExecutor
import pickle
from wins.tempwins_tuning import recommend_window_params
from utils.helpers import agg_network_influence
import functools
from bisect import bisect_left, bisect_right
from cent.helper import _build_time_index, _iter_windows, _node_in_window
import numpy as np
import scipy.sparse as sp
from typing import List, Tuple, Optional, Dict, Callable
from scipy.sparse.linalg import eigsh
import time
from numba import njit, prange, set_num_threads
import numba
from scipy.sparse.linalg import lobpcg
from cent.temp_cent import TempCentricity, make_build_series_fn_warm, probe_topk_r_candidates
import multiprocessing
from cve.graph_cve import extract_cve_subgraph
import random
import os

random.seed(42)

# ==============================
# Global Thread Control
# ==============================
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"
numba.set_num_threads(4)


# ==============================
# Numba Kernel
# ==============================
@njit(parallel=True, fastmath=True)
def _masked_degree_csr(indptr, indices, mask):
    n = len(mask)
    deg = np.zeros(n, dtype=np.float32)
    for i in prange(n):
        if mask[i]:
            start, end = indptr[i], indptr[i+1]
            for j in range(start, end):
                nbr = indices[j]
                if mask[nbr]:
                    deg[i] += 1
    return deg

# ---------- helper for multiprocessing ----------
def _batch_compute_parallel(args):
    """Top-level helper so it can be pickled by ProcessPoolExecutor."""
    obj_ref, func_name, batch = args
    func = getattr(obj_ref, func_name)
    batch_results = []
    for (t_s, t_e) in batch:
        try:
            res = func(t_s, t_e)
            batch_results.append((t_s, t_e, res))
        except Exception as e:
            print(f"[warn] Window ({t_s},{t_e}) failed inside batch: {e}")
    return batch_results

# ------------ Optimized High-Level Class -------------

class TempCentricityOptimized(TempCentricity):
    """ 

    Optimized temporal centricity class using:
        - Numba parallel CSR traversal for degree_centrality_fast
        - lobpcg approximate eigenvector for eigenvector_centrality_fast
    """

    def __init__(self, graph, search_scope="auto", global_cover=0.95, n_threads=None):
        '''
        args:
            graph: a NetworkX graph with node attribute 'timestamp'
            search_scope: 'global' or 'local' or "auto"

        '''
        super().__init__(graph, search_scope, global_cover)
        if n_threads is None:
            n_threads = max(1, multiprocessing.cpu_count() - 1)
        set_num_threads(n_threads)
        print(f"[info] Using {n_threads} threads for Numba parallel loops")


    # ---------- fast degree centrality ----------
    def degree_centrality_fast(self, t_s, t_e):
        m, L, R = self._mask_for_window(t_s, t_e)
        if m is None:
            return {}
        
        mask = m.astype(np.bool_)
        n_win = int(mask.sum())

        if n_win < 2:
            return {}
        
        indptr = self._A.indptr
        indices = self._A.indices
        deg_all = _masked_degree_csr(indptr, indices, mask)
        vals = (deg_all / (n_win - 1)).astype(np.float32)

        nodes = self._nodes_sorted_by_t
        return {nodes[i]: float(vals[i]) for i in range(len(nodes)) if mask[i]}

    # --------- Fast Eigenvector Centrality ----------
    def eigenvector_centrality_fast(self, t_s, t_e, tol=1e-4):
        m, L, R = self._mask_for_window(t_s, t_e)
        if m is None:
            return {}
        
        A_win = self._A[L:R, L:R]
        n = A_win.shape[0]
        if n < 2:
            return {}

        # small subgraph shortcut
        if n < 10:
            deg = np.array(A_win.sum(axis=1)).ravel()
            s = deg.sum()
            if s == 0:
                return {}
            deg /= s
            nodes = self._nodes_sorted_by_t[L:R]
            return {nodes[i]: float(deg[i]) for i in range(n)}

        # regular eigenvector
        X = np.random.rand(n, 1)
        vals, vecs = lobpcg(A_win, X, tol=tol, maxiter=50)
        vec = np.abs(vecs[:, 0])
        vec /= (vec.sum() + 1e-12)
        nodes = self._nodes_sorted_by_t[L:R]
        return {nodes[i]: float(vec[i]) for i in range(n)}
    
    
    # ------------ Adaptive Parallel Temporal Series -------------
    def compute_series_parallel(self, window_list, mode="eigenvector", max_workers=None):
        n_nodes = self._A.shape[0]
        n_windows = len(window_list)
        if n_windows == 0:
            print("[warn] No windows provided.")
            return []
        
        if mode == "degree":
            func_name = "degree_centrality_fast"
        else:
            func_name = "eigenvector_centrality_fast"

        func = getattr(self, func_name)

        # ----------- Estimate window sizes -----------
        sizes = []
        for (t_s, t_e) in window_list[:min(50, len(window_list))]:
            m, L, R = self._mask_for_window(t_s, t_e)
            if m is not None:
                sizes.append(int(m.sum()))
        if sizes:
            print(f"[debug] Avg window size: {np.mean(sizes):.1f}, median: {np.median(sizes):.1f}")

        # ----------- Partition windows by size -----------
        small_windows, large_windows = [], []
        for (t_s, t_e) in window_list:
            m, L, R = self._mask_for_window(t_s, t_e)
            if m is None:
                continue
            n_sub = int(m.sum())
            (small_windows if n_sub < 100 else large_windows).append((t_s, t_e))

        # ----------- Process small windows serially -----------
        results = []
        if small_windows:
            print(f"[info] Processing {len(small_windows)} small windows serially ...")
            for (t_s, t_e) in small_windows:
                try:
                    results.append((t_s, t_e, func(t_s, t_e)))
                except Exception as e:
                    print(f"[warn] Small window ({t_s},{t_e}) failed: {e}")

        # ----------- Process large windows in parallel -----------
        if large_windows:
            if max_workers is None:
                max_workers = min(4, os.cpu_count() // 4)
            batch_size = max(50, min(100, len(large_windows) // max_workers))
            print(f"[info] Launching {len(large_windows)} large windows in {max_workers} workers (batch={batch_size})")

            batches = [large_windows[i:i + batch_size] for i in range(0, len(large_windows), batch_size)]
            t_start = time.perf_counter()

            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_batch_compute_parallel, (self, func_name, batch)): batch for batch in batches}
                for fut in as_completed(futures):
                    try:
                        batch_result = fut.result()
                        results.extend(batch_result)
                    except Exception as e:
                        print(f"[warn] Batch failed: {e}")

            t_end = time.perf_counter()
            print(f"[info] Parallel large-window section completed in {t_end - t_start:.2f}s")

        results.sort(key=lambda x: x[0])
        print(f"[info] Completed {len(results)} total window computations.")
        return results
    
    
if __name__ == "__main__":

    t0_total = time.perf_counter()

    # data path
    cve_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl")

    t0 = time.perf_counter()
    # load the graph
    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)

    # use subgraph for calculation
    depgraph = extract_cve_subgraph(depgraph, k =2)

    print(f"[info] Graph loaded: {depgraph.number_of_nodes()} nodes, "
          f"{depgraph.number_of_edges()} edges "
          f"(took {time.perf_counter() - t0:.2f}s)")
    
    # ---------- for quick debug ------------
    MAX_NODES = 100000
    if depgraph.number_of_nodes() > MAX_NODES:
        valid_nodes = [n for n, a in depgraph.nodes(data=True) if "timestamp" in a]
        # random sampling
        if len(valid_nodes) < MAX_NODES:
            print(f"[warn] only {len(valid_nodes)} nodes have timestamp, using all of them")
            keep = valid_nodes
        else:
            keep = random.sample(valid_nodes, MAX_NODES)
        depgraph = depgraph.subgraph(keep).copy()
        print(f"[debug] depgraph reduced to {depgraph.number_of_nodes()} nodes and {depgraph.number_of_edges()} edges")
    # ---------------------------------------

    # initialize tempcentricity
    t1 = time.perf_counter()

    tempcent = TempCentricityOptimized(depgraph, search_scope='auto')
    print(f"[info] TempCentricity initialized (took {time.perf_counter() - t1:.2f}s)")

    # replace with fast method
    tempcent.degree_centrality = tempcent.degree_centrality_fast
    tempcent.eigenvector_centrality = tempcent.eigenvector_centrality_fast

    # ------------- build_series_fn -------------
    t2 = time.perf_counter()

    build_series_fn = make_build_series_fn_warm(tempcent, 
                                                agg_fn=lambda pr: agg_network_influence(pr, method="entropy"),
                                                max_iter=150, tol=3e-4)
    print(f"[info] build_series_fn constructed (took {time.perf_counter() - t2:.2f}s)")
    
    # ------------- coarse-to-fine r search -----------------
    t3 = time.perf_counter()
    r_top = probe_topk_r_candidates(tempcent, r_candidates=(0.5, 0.7, 0.9), topk=2, agg="sum", n_jobs=-1)
    print(f"[info] initial r probing done (took {time.perf_counter() - t3:.2f}s)")

    refined = []
    for r in r_top:
        refined.extend([max(0.05, r-0.15), max(0.05, r-0.05), r, min(0.95, r+0.05), min(0.95, r+0.15)])
    
    t4 = time.perf_counter()
    r_top = probe_topk_r_candidates(tempcent, r_candidates=tuple(sorted(set(refined))), topk=3, agg="sum", n_jobs=-1)
    print(f"[info] refined r probing done (took {time.perf_counter() - t4:.2f}s)")

    # ------------------ recommend window params ------------------
    t5 = time.perf_counter()
    best = recommend_window_params(
        G = depgraph,
        build_series_fn = build_series_fn,
        N_min=100,
        alpha=0.8,
        coverage=0.95,
        r_candidates=r_top,
        beta=1.0
    )
    
    t5_end = time.perf_counter()
    print(f"[info] recommend_window_params finished (took {t5_end - t5:.2f}s)")
    print("[result] Best window params:", best)

    # ------------------ Total runtime ------------------
    total_time = time.perf_counter() - t0_total
    print(f"\n[summary] Total evaluation time: {total_time:.2f} seconds "
          f"({total_time/60:.2f} minutes)")



