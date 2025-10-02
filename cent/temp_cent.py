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

        # preset time interval
        ts = [int(d.get("timestamp", 0)) for _, d in graph.nodes(data=True)]
        self._tmin, self._tmax = (min(ts), max(ts)) if ts else (0,0)

        # calculate static baseline once
        self._static_dc = self._compute_static_dc()
        self._static_evc = self._compute_static_evc()
    
    def _coverage(self, t_s, t_e):
        total = (self._tmax - self._tmin + 1) or 1
        win = max(0, min(t_e, self._tmax + 1) - max(t_s, self._tmin))
        return win/total

    @functools.lru_cache(maxsize=512)
    def _extract_temporal_subgraph(self, t_s: int, t_e: int):
        '''
        Keep nodes with t_s <= node.timestamp < t_e, then take induced subgraph.

        '''
        if self.search_scope == 'global':
            return self.graph.copy()

        if self.search_scope == "auto" and self._coverage(t_s, t_e) >= self.global_cover:
            return self.graph.copy()

        nodes_in_window = [
            n for n, d in self.graph.nodes(data=True)
            if t_s <= int(d.get("timestamp", 0)) < t_e
        ]
        # induced subgraph of selected nodes
        return self.graph.subgraph(nodes_in_window).copy()

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
        

    def eigenvector_centrality(self, t_s, t_e):
        '''
        compute eigenvector centrality for nodes in the temporal subgraph
        '''
        H = self._extract_temporal_subgraph(t_s, t_e)
        # Eigenvector for undirected; for directed consider HITS/PageRank
        if H.is_directed():
            return nx.pagerank(H)
        else:
            return nx.eigenvector_centrality(H, max_iter=1000, tol=1e-06)

if __name__ == "__main__":
    # data path
    depdata_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    # load the graph
    with depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)

    # initialize tempcentricity
    tempcent = TempCentricity(depgraph, search_scope='auto')

    # calculate degree centrality in the time window
    # t_s, t_e = 100, 300

    # degree_cent = tempcent.degree_centrality(t_s, t_e)
    # print("degree centrality:", degree_cent)
    # eigen_cent = tempcent.eigenvector_centrality(t_s, t_e)
    # print("eigenvector centrality:", eigen_cent)

    # create build_series_fn
    build_series_fn = make_build_series_fn(tempcent, agg_fn=lambda pr: agg_network_influence(pr, method="entropy"))

    best = recommend_window_params(
        G = depgraph,
        build_series_fn = build_series_fn,
        N_min=100,
        alpha=0.8,
        coverage=0.95,
        r_candidates=(0.5, 0.65, 0.8),
        beta=1.0
    )

    print(best)



