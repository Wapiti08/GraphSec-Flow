'''
 # @ Create Time: 2025-06-24 16:42:30
 # @ Modified time: 2025-06-24 16:42:32
 # @ Description: temporal centricity calculation for nodes in a graph

the timestamp is one of the attributes of nodes

 '''
import networkx as nx
from pathlib import Path
import pickle

class TempCentricity:
    """ Calculate temporal centricity for nodes in a graph

    attributes:
        graph: adjacency list mapping node indices to list of neighbor indices
    """

    def __init__(self, graph):
        self.graph = graph

    def _extract_temporal_subgraph(self, t_s: int, t_e: int):
        '''
        Keep nodes with t_s <= node.timestamp < t_e, then take induced subgraph.

        '''
        nodes_in_window = [
            n for n, d in self.graph.nodes(data=True)
            if t_s <= int(d.get("timestamp", 0)) < t_e
        ]
        # induced subgraph of selected nodes
        return self.graph.subgraph(nodes_in_window).copy()

    def degree_centrality(self, t_s, t_e):
        '''
        compute degree centrality for nodes in the temporal subgraph
        '''
        H = self._extract_temporal_subgraph(t_s, t_e)
        degree_centrality = {}

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
    small_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_small.pkl")

    depdata_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    # load the graph
    with small_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)
    

    # initialize tempcentricity
    tempcent = TempCentricity(depgraph)

    # calculate degree centrality in the time window
    t_s, t_e = 100, 300

    degree_cent = tempcent.degree_centrality(t_s, t_e)
    print("degree centrality:", degree_cent)
    eigen_cent = tempcent.eigenvector_centrality(t_s, t_e)
    print("eigenvector centrality:", eigen_cent)



