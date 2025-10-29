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


try:
    from joblib import Parallel, delayed
    _HAS_JOBLIB = True
except Exception:
    _HAS_JOBLIB = False


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
        n_win = int(mask.sum*())

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
        if A_win.shape[0] < 2:
            return {}
        # Approximate eigenvector using few iterations
        n = A_win.shape[0]
        X = np.random.rand(n, 1)
        vals, vecs = lobpcg(A_win, X, tol=tol, maxiter=50)
        vec = np.abs(vecs[:, 0])
        vec /= (vec.sum() + 1e-12)
        nodes = self._nodes_sorted_by_t[L:R]
        return {nodes[i]: float(vec[i]) for i in range(n)}
    
    # ------------ Parallel Temporal Series -------------
    def compute_series_parallel(self, window_list, mode="eigenvector", max_workers=None):
        if max_workers is None:
            max_workers = max(1, multiprocessing.cpu_count() // 2)
        results = []
        func = self.degree_centrality_fast if mode == "degree" else self.eigenvector_centrality_fast
        with ProcessPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(func, t_s, t_e): (t_s, t_e) for t_s, t_e in window_list}
            for fut in as_completed(futures):
                ts, te = futures[fut]
                try:
                    res = fut.result()
                    results.append((ts, te, res))
                except Exception as e:
                    print(f"[warn] Window ({ts},{te}) failed: {e}")
        return results

if __name__ == "__main__":

    t0_total = time.perf_counter()

    # data path
    depdata_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    t0 = time.perf_counter()
    # load the graph
    with depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)

    print(f"[info] Graph loaded: {depgraph.number_of_nodes()} nodes, "
          f"{depgraph.number_of_edges()} edges "
          f"(took {time.perf_counter() - t0:.2f}s)")
    
    # ---------- for quick debug ------------
    # import random
    # MAX_NODES = 1000  
    # if depgraph.number_of_nodes() > MAX_NODES:
    #     valid_nodes = [n for n, a in depgraph.nodes(data=True) if "timestamp" in a]
    #     # random sampling
    #     if len(valid_nodes) < MAX_NODES:
    #         print(f"[warn] only {len(valid_nodes)} nodes have timestamp, using all of them")
    #         keep = valid_nodes
    #     else:
    #         keep = random.sample(valid_nodes, MAX_NODES)
    #     depgraph = depgraph.subgraph(keep).copy()
    #     print(f"[debug] depgraph reduced to {depgraph.number_of_nodes()} nodes and {depgraph.number_of_edges()} edges")
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



