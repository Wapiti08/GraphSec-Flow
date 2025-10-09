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
import pickle
from wins.tempwins_tuning import make_build_series_fn, recommend_window_params
from utils.helpers import agg_network_influence
import functools
from bisect import bisect_left, bisect_right
from cent.helper import _build_time_index, _iter_windows, _node_in_window
import numpy as np
import scipy.sparse as sp

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
        nodes, ts = zip(*[(n, int(d.get("timestamp", 0))) for n, d in graph.nodes(data=True)]) if graph.number_of_nodes() else ([],[])
        self._nodes_sorted_by_t = [n for _, n in sorted(zip(ts, nodes))]
        self._ts_sorted = sorted(ts)
        self._tmin, self._tmax = (self._ts_sorted[0], self._ts_sorted[-1]) if self._ts_sorted else (0, 0)

        # calculate static baseline once
        self._static_dc = self._compute_static_dc()
        self._static_evc = self._compute_static_evc()
    
    def _coverage(self, t_s, t_e):
        total = (self._tmax - self._tmin + 1) or 1
        win = max(0, min(t_e, self._tmax + 1) - max(t_s, self._tmin))
        return win/total
    
    def _nodes_in_window(self, t_s: int, t_e: int):
        if not self._ts_sorted:
            return []
        L = bisect_left(self._ts_sorted, t_s)
        R = bisect_left(self._ts_sorted, t_e)
        if L >= R:
            return []
        # index nodes within interval
        return self._nodes_sorted_by_t[L:R]

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
        else:
            return nx.eigenvector_centrality(G, max_iter=1000, tol=1e-06)


    def static_degree(self):
        return self._static_dc
    
    def static_eigen(self):
        return self._static_evc
    
    # ------------ Dynamic time window ---------------
    @functools.lru_cache(maxsize=2048)
    def degree_centrality(self, t_s, t_e):
        '''
        compute degree centrality for nodes in the temporal subgraph
        '''
        H = self._extract_temporal_subgraph(t_s, t_e)

        # For DiGraph you can choose in/out/total:
        if H.is_directed():
            return {
                "in": nx.in_degree_centrality(H),
                "out": nx.out_degree_centrality(H),
                "total": nx.degree_centrality(H.to_undirected())
            }
        else:
            return nx.degree_centrality(H)
        
    @functools.lru_cache(maxsize=1024)
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


# speed up tempcentricity computation with centrality based filtering first
def _probe_score_for_r(G, r, top_agg="sum"):
    ''' Use degree centrality to run a circle on a non-overlapping sliding window with step=win, 
    and take the maximum window score as the score of r
    
    '''
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

def probe_topk_r_candidates(G, r_candidates, topk=5, agg="sum"):
    scored = []
    for r in r_candidates:
        s = _probe_score_for_r(G, r, top_agg=agg)
        scored.append((r, float(s)))
    scored.sort(key=lambda x: x[1], reverse=True)
    return tuple(r for r, _ in scored[:topk])


if __name__ == "__main__":
    # data path
    depdata_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    # load the graph
    with depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)

    # initialize tempcentricity
    tempcent = TempCentricity(depgraph, search_scope='auto')
    
    # create build_series_fn
    build_series_fn = make_build_series_fn(tempcent, agg_fn=lambda pr: agg_network_influence(pr, method="entropy"))

    r_top = probe_topk_r_candidates(depgraph, r_candidates=(0.5, 0.65, 0.8, 0.9), topk=3, agg="sum")

    best = recommend_window_params(
        G = depgraph,
        build_series_fn = build_series_fn,
        N_min=100,
        alpha=0.8,
        coverage=0.95,
        r_candidates=r_top,
        beta=1.0
    )

    print(best)



