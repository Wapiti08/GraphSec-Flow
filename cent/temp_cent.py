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
from cve.graph_cve import extract_cve_subgraph
import random

random.seed(42)

try:
    from joblib import Parallel, delayed
    _HAS_JOBLIB = True
except Exception:
    _HAS_JOBLIB = False

class TempCentricity:
    """ Calculate temporal centricity for nodes in a graph

    attributes:
        graph: adjacency list mapping node indices to list of neighbor indices
    """

    def __init__(self, graph, search_scope, global_cover = 0.95):
        '''
        args:
            graph: a NetworkX graph with node attribute 'timestamp'
            search_scope: 'global' or 'local' or "auto"

        '''
        self.graph = graph
        self.search_scope = search_scope
        self.global_cover = global_cover

        # preset time interval, used for half search
        nodes, ts = zip(*[(n, float(d.get("timestamp", 0))) for n, d in graph.nodes(data=True)]) if graph.number_of_nodes() else ([],[])
        order = np.argsort(ts)
        self._nodes_sorted_by_t = [nodes[i] for i in order]
        self._ts_sorted = [ts[i] for i in order]
        print(f"sorted timestamps: {self._ts_sorted[:10]} ... {self._ts_sorted[-10:]}")
        self._tmin, self._tmax = (self._ts_sorted[0], self._ts_sorted[-1]) if self._ts_sorted else (0, 0)

        # Map node -> position in timestamp order (so windows become contiguous-ish ranges)
        self._pos = {n: i for i, n in enumerate(self._nodes_sorted_by_t)}

        # Build a single CSR adjacency (undirected) in *timestamp order*
        idx = self._pos
        rows, cols = [], []
        for u, v in graph.edges():
            iu, iv = idx[u], idx[v]
            if iu == iv: 
                continue
            rows.append(iu); cols.append(iv)
            rows.append(iv); cols.append(iu)
        data = np.ones(len(rows), dtype=np.float32)
        n = len(self._nodes_sorted_by_t)
        self._A = sp.csr_matrix((data, (rows, cols)), shape=(n, n), dtype=np.float32)

        # calculate static baseline once
        self._static_dc = self._compute_static_dc()
        self._static_evc = self._compute_static_evc()
    
    def _coverage(self, t_s, t_e):
        if self._tmin is None or self._tmax is None:
            return 0.0
        if t_s is None or t_e is None:
            return 0.0
        
        total = (self._tmax - self._tmin + 1) or 1
        win = max(0, min(t_e, self._tmax + 1) - max(t_s, self._tmin))
        return win/total
    

    def _nodes_idx_in_window(self, t_s: int, t_e: int):
        """Return index range [L, R) in timestamp order."""
        if not self._ts_sorted:
            return 0, 0
        from bisect import bisect_left
        L = bisect_left(self._ts_sorted, t_s)
        R = bisect_left(self._ts_sorted, t_e)
        return L, R

    def _mask_for_window(self, t_s: int, t_e: int):
        """Fast boolean mask in timestamp index space."""
        L, R = self._nodes_idx_in_window(t_s, t_e)
        if L >= R:
            return None, L, R
        m = np.zeros(self._A.shape[0], dtype=bool)
        m[L:R] = True
        return m, L, R

    def _nodes_in_window(self, t_s: int, t_e: int):
        if not self._ts_sorted:
            return []
        L = bisect_left(self._ts_sorted, t_s)
        R = bisect_left(self._ts_sorted, t_e)
        if L >= R:
            return []
        # index nodes within interval
        return self._nodes_sorted_by_t[L:R]

    @staticmethod
    def _warm_start_vector(prev_nodes, prev_vec, curr_nodes):
        ''' Align the feature vector of the previous window to 
        the node order of the current window as a warm-start
        
        '''
        if prev_nodes is None or prev_vec is None:
            return None
        
        pos = {n: i for i, n in enumerate(prev_nodes)}
        v0 = np.zeros(len(curr_nodes), dtype=float)
        hit = 0
        for i, n in enumerate(curr_nodes):
            j = pos.get(n, None)
            if j is not None:
                v0[i] = prev_vec[j]
                hit += 1
        return v0 if hit > 0 else None
    
    @staticmethod
    def _to_csr_undirected(H):
        ''' Convert NetworkX subgraph to CSR (unweighted, no self-loops, automatic symmetric)
        
        '''
        nodes = list(H.nodes)
        if not nodes:
            return nodes, sp.csr_matrix((0,0), dtype=float)
        
        idx = {n: i for i, n in enumerate(nodes)}
        rows, cols = [], []
        for u, v in H.edges():
            iu, iv = idx[u], idx[v]
            if iu == iv:
                continue
            # undirected graph, add both directions
            rows.append(iu); cols.append(iv)
            rows.append(iv); cols.append(iu)
        data = np.ones(len(rows), dtype=float)
        A = sp.csr_matrix((data, (rows, cols)), shape=(len(nodes), len(nodes)), dtype=float)
        return nodes, A

    @staticmethod
    def _evc_sparse_power_iter(A: sp.csr_matrix, v0=None, max_iter=200, tol=1e-4):
        ''' Sparse power EVC (supports warm-start), only for undirected graphs
        
        '''
        n = A.shape[0]
        if n == 0:
            return np.empty((0,), dtype=float)
        x = (np.random.rand(n) if v0 is None else v0).astype(float)
        nrm = np.linalg.norm(x)
        x = x/(nrm + 1e-12)
        for _ in range(max_iter):
            x_last = x
            x = A.dot(x)
            nrm = np.linalg.norm(x)
            if nrm == 0:
                break
            x = x/(nrm + 1e-12)
            if np.linalg.norm(x - x_last) < tol:
                break
        return x
    

    @functools.lru_cache(maxsize=2048)
    def _extract_temporal_subgraph(self, t_s: int, t_e: int):
        '''
        Keep nodes with t_s <= node.timestamp < t_e, then take induced subgraph.

        '''
        if self.search_scope == 'global':
            return self.graph

        if self.search_scope == "auto" and self._coverage(t_s, t_e) >= self.global_cover:
            return self.graph
        
        nodes_in_window = self._nodes_in_window(t_s, t_e)

        # induced subgraph of selected nodes
        return self.graph.subgraph(nodes_in_window)

    # ----------- Static Centrality (baseline) -------------

    def _compute_static_dc(self):
        G = self.graph
        if G.is_directed():
            return {
                "in": nx.in_degree_centrality(G),
                "out": nx.out_degree_centrality(G),
                "total": nx.degree_centrality(G.to_undirected())
            }
        else:
            return nx.degree_centrality(G)

    def _compute_static_evc(self):
        G = self.graph
        if G.is_directed():
            # direct graph uses PageRank as the equalient
            return nx.pagerank(G)
        if self._A.shape[0] == 0:
            return {}
        # Sparse maximum eigenvector
        w,x = eigsh(self._A, k =1, which='LA', maxiter=1000, tol=1e-6)
        x = x[:, 0]
        x /= (np.linalg.norm(x) + 1e-12)
        nodes = self._nodes_sorted_by_t
        return {nodes[i]: float(x[i]) for i in range(len(nodes))}


    def static_degree(self):
        return self._static_dc
    
    def static_eigen(self):
        return self._static_evc
    
    # ------------ Dynamic time window ---------------
    @functools.lru_cache(maxsize=2048)
    def degree_centrality(self, t_s, t_e):
        '''
        compute degree centrality for nodes in the temporal window via CSR ops
        '''
        # Global shortcut
        if self.search_scope == "auto" and self._coverage(t_s, t_e) >= self.global_cover:
            return self._static_dc

        m, L, R = self._mask_for_window(t_s, t_e)
        if m is None:
            return {}
        n_win = int(m.sum())
        if n_win < 2:
            return {}
        
        mx = m.astype(np.float32)
        deg_all = (self._A @ mx)[m]
        vals = (deg_all / (n_win - 1)).astype(float)

        nodes = self._nodes_sorted_by_t[L:R]
        return {nodes[i]: float(vals[i]) for i in range(n_win)}
    
    @functools.lru_cache(maxsize=8192)
    def eigenvector_centrality(self, t_s, t_e):
        '''
        compute eigenvector centrality for nodes in the temporal subgraph
        '''
        H = self._extract_temporal_subgraph(t_s, t_e)
        # Eigenvector for undirected; for directed consider HITS/PageRank
        if H.is_directed():
            return nx.pagerank(H)
        else:
            return nx.eigenvector_centrality(H, max_iter=300, tol=1e-5)

    @functools.lru_cache(maxsize=8192)
    def eigenvector_centrality_sparse(self, t_s, t_e, v0=None, max_iter=150, tol=3e-4):
        if self.search_scope == "global" or (self.search_scope == "auto" and self._coverage(t_s, t_e) >= self.global_cover):
            G = self.graph
            if G.is_directed():
                pr = self._static_evc
                nodes = list(G.nodes())
                vec = np.array([pr.get(n, 0.0) for n in nodes], dtype=float)
                return pr, vec, nodes
            else:
                evc = self._static_evc
                nodes = list(G.nodes())
                vec = np.array([evc[n] for n in nodes], dtype=float)
                return evc, vec, nodes
            
        m, L, R = self._mask_for_window(t_s, t_e)
        if m is None:
            return {}, None, []

        A_win = self._A[L:R, L:R]
        n_win = A_win.shape[0]
        if n_win == 0:
            return {}, None, []
        nodes = self._nodes_sorted_by_t[L:R]
        if n_win == 1 or A_win.nnz == 0:
            evc = {nodes[i]: (1.0 if n_win == 1 else 0.0) for i in range(n_win)}
            vec = np.array([evc[n] for n in nodes], dtype=float) if n_win else None
            return evc, vec, nodes
        
        v0_local = None
        if v0 is not None and len(v0) == n_win:
            v0_local = v0 / (np.linalg.norm(v0) + 1e-12)

        try:
            # largest algebraic eigenpair; symmetric matrix
            w, x = eigsh(A_win, k=1, which='LA', v0=v0_local, maxiter=max_iter, tol=tol)
            x = x[:, 0]
            x /= (np.linalg.norm(x) + 1e-12)
        except Exception:
            x = self._evc_sparse_power_iter(A_win, v0=v0_local, max_iter=max_iter, tol=tol)

        evc = {nodes[i]: float(x[i]) for i in range(n_win)}
        return evc, x, nodes


# speed up tempcentricity computation with centrality based filtering first
def _probe_score_for_r_sparse(A: sp.csr_matrix, ts_sorted, r, top_agg="sum"):
    ''' CSR-based non-overlapping sliding window scoring via degree centrality
    args:
        A: sparse undirected adjacency for the whole graph, in the same order as ts_sorted
        ts_sorted: 
    '''    
    
    if not ts_sorted:
        return -np.inf
    
    t_min, t_max = ts_sorted[0], ts_sorted[-1]

    T = t_max - t_min
    if T<=0:
        return -np.inf
    
    win = max(1e-12, float(r) * T)
    step = win
    best = -np.inf
    N = len(ts_sorted)
    i = 0

    while i < N:
        t_s = ts_sorted[i]
        t_e = t_s + win
        # get right boundary
        R = bisect_left(ts_sorted, t_e, lo=i, hi=N)
        # Skip tiny windows
        if R - i < 2:
            i = max(i + 1, R)
            continue

        A_win = A[i:R, i:R]
        n_win = A_win.shape[0]
        if n_win >= 2 and A_win.nnz > 0:
            # internal degree
            deg_win = np.ravel(A_win.sum(axis=1))
            if top_agg == "sum":
                val = float(deg_win.sum() / (n_win - 1))
            elif top_agg == "max":
                val = float(deg_win.max() / (n_win - 1))
            else:
                val = float(deg_win.mean() / (n_win - 1))
            if val > best:
                best = val
        # first index >= t_s + step
        j = bisect_left(ts_sorted, t_s + step, lo=R, hi=N)
        i = max(j, R)
    return best


def _probe_score_for_r(G, r, top_agg="sum"):
    ''' Backward-compatible NX version (kept in case callers still import it) '''

    t_min, t_max = _build_time_index(G)
    T = t_max - t_min
    if T<=0:
        return -np.inf
    win = max(1e-12, float(r) * T)
    step = win
    best = -np.inf
    for t_s, t_e in _iter_windows(t_min, t_max, win, step):
        nodes = _node_in_window(G, t_s, t_e)
        if len(nodes) < 2:
            continue   
        H = G.subgraph(nodes)
        deg = nx.degree_centrality(H)
        if not deg:
            continue
        val = (sum(deg.values()) if top_agg == "sum"
               else (max(deg.values()) if top_agg == "max"
                     else np.mean(list(deg.values()))))
        if val > best:
            best = val
    return best


def probe_topk_r_candidates(obj, r_candidates, topk=5, agg="sum", n_jobs=-1):
    '''
    if 'obj' is a TempCentricity instance, use its internal CSR for fast scoring
    otherwise fallback to NetworkX version

    n_jobs: number of parallel jobs, -1 for all cores
    '''
    if isinstance(obj, TempCentricity):
        A = obj._A
        ts_sorted = obj._ts_sorted
        if _HAS_JOBLIB and (n_jobs == -1 or n_jobs > 1):
            scored = Parallel(n_jobs=n_jobs if n_jobs != -1 else -1, prefer="processes")(
                delayed(_probe_score_for_r_sparse)(A, ts_sorted, r, top_agg=agg)
                for r in r_candidates
            )
        else:
            scored = [_probe_score_for_r_sparse(A, ts_sorted, r, top_agg=agg) for r in r_candidates]
        pairs = list(zip(r_candidates, map(float, scored)))
        pairs.sort(key=lambda x: x[1], reverse=True)
        return tuple(r for r, _ in pairs[:topk])
    else:
        scored = []
        for r in r_candidates:
            s = _probe_score_for_r(obj, r, top_agg=agg)
            scored.append((r, float(s)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return tuple(r for r, _ in scored[:topk])
    
# -------------------- convenience wrapper example --------------------
def make_build_series_fn(tempcent_obj, agg_fn: Callable[[Dict], float]):
    """
    Returns a callable build_series_fn(win_size, step_size) that uses
    TempCentricity implementation and aggregation to produce a scalar series.
    tempcent_obj must implement .eigenvector_centrality(t_s, t_e)
    agg_fn maps from {node: centrality} -> scalar.
    """
    def build_series(win_size: float, step_size: float):
        # discover time range from underlying graph inside tempcent_obj if available
        G = getattr(tempcent_obj, "G", None) or getattr(tempcent_obj, "graph", None)
        if G is None:
            raise ValueError("tempcent_obj must carry the underlying graph as attribute G or graph.")
        ts_all = sorted(float(d.get("timestamp", 0)) for _, d in G.nodes(data=True) if d.get("timestamp", None) is not None)
        if not ts_all:
            return np.asarray([]), np.asarray([])
        t_min, t_max = ts_all[0], ts_all[-1]
        # sliding windows
        t = t_min
        centers, scalars = [], []
        while t < t_max:
            t_s, t_e = t, t + float(win_size)
            pr = tempcent_obj.eigenvector_centrality(t_s=t_s, t_e=t_e)
            if pr:
                centers.append((t_s + t_e) / 2.0)
                scalars.append(float(agg_fn(pr)))
            t += float(step_size)
        return np.asarray(centers, dtype=float), np.asarray(scalars, dtype=float)
    return build_series


def make_build_series_fn_warm(tempcent_obj: TempCentricity, agg_fn, max_iter=150, tol=1e-4):

    t_min, t_max = _build_time_index(tempcent_obj.graph)

    def build_series_fn(win_size, step_size, t_min_override=None, t_max_override=None):
        _t_min = t_min if t_min_override is None else t_min_override
        _t_max = t_max if t_max_override is None else t_max_override

        # ======== construct all time windows =========
        window_list = []
        for t_s, t_e in _iter_windows(_t_min, _t_max, win_size, step_size):
            nodes = _node_in_window(tempcent_obj.graph, t_s, t_e)
            if len(nodes) >= 2:
                window_list.append((t_s, t_e))
        
        if not window_list:
            return [], []

        print(f"[parallel] Computing {len(window_list)} windows via compute_series_parallel() ...")

        # parallel compute all windows
        results = tempcent_obj.compute_series_parallel(
            window_list, 
            mode="eigenvector",     
            max_workers=256      
        )

        # aggregate results
        centers, scalars = [], []
        for (t_s, t_e, scores) in results:
            try:
                val = float(agg_fn(scores))
                centers.append(0.5 * (t_s + t_e))
                scalars.append(val)
            except Exception as e:
                print(f"[warn] Aggregation failed for ({t_s},{t_e}): {e}")

        return np.asarray(centers, dtype=float), np.asarray(scalars, dtype=float)
    
    return build_series_fn

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
    MAX_NODES = 10000
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

    tempcent = TempCentricity(depgraph, search_scope='auto')
    print(f"[info] TempCentricity initialized (took {time.perf_counter() - t1:.2f}s)")

    # ------------- build_series_fn -------------
    t2 = time.perf_counter()

    build_series_fn = make_build_series_fn(tempcent, 
                                            agg_fn=lambda pr: agg_network_influence(pr, method="entropy"),
                                            )
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



