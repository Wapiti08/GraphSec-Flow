'''
 # @ Create Time: 2025-06-24 16:42:30
 # @ Modified time: 2025-06-24 16:42:32
 # @ Description: temporal centricity calculation for nodes in a graph
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

    def _extract_temporal_subgraph(self, t_s, t_e):
        '''
        extract the temporal subgraph that only includes nodes and edges
        active during the time window [t_s, t_e]
        '''
        temporal_subgraph = nx.Graph()

        # add edges within the time window
        for u, v, data in self.graph.edges(data=True):
            print(u, v, data)
            if t_s <= data['timestamp'] <= t_e:
                temporal_subgraph.add_edge(u, v, timestamp=data['timestamp'])
        
        # add nodes involved in these edges
        for node in temporal_subgraph.nodes:
            if node not in self.graph:
                temporal_subgraph.add_node(node)

        return temporal_subgraph

    def degree_centrality(self, t_s, t_e):
        '''
        compute degree centrality for nodes in the temporal subgraph
        '''
        temporal_subgraph = self._extract_temporal_subgraph(t_s, t_e)
        degree_centrality = {}

        for node in temporal_subgraph.nodes:
            degree_centrality[node] = temporal_subgraph.degree(node)
        
        return degree_centrality
    
    def eigenvector_centrality(self, t_s, t_e):
        '''
        compute eigenvector centrality for nodes in the temporal subgraph
        '''
        temporal_subgraph = self._extract_temporal_subgraph(t_s, t_e)
        eigenvector_centrality = nx.eigenvector_centrality(temporal_subgraph)

        return eigenvector_centrality


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
    t_s, t_e = 0, 10
    temp_graph = tempcent._extract_temporal_subgraph(t_s, t_e)



