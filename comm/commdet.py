import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from community import community_louvain
import networkx as nx
from search.vamana import VamanaSearch

# Louvain Community Detection
def detect_communities(graph):
    G = nx.Graph(graph)
    partition = community_louvain.best_partition(G)
    return partition

class VLWithTempCent:
    def __init__(self, vamana: VamanaSearch, cve_data, timestamps, centrality):
        self.vamana = vamana
        self.cve_data = cve_data    
        self.timestamps = timestamps
        self.centrality = centrality
    
    

