import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from community import community_louvain
import networkx as nx
from search.vamana import VamanaSearch
from cent.temp_cent import TempCentricity

# Louvain Community Detection
def detect_communities(graph):
    G = nx.Graph(graph)
    partition = community_louvain.best_partition(G)
    return partition

class VLWithTempCent:
    def __init__(self, vamana: VamanaSearch, cve_data, timestamps, centrality: TempCentricity):
        self.vamana = vamana
        self.cve_data = cve_data    
        self.timestamps = timestamps
        self.centrality = centrality
    
    def _extract_temp_subgraph(self, t_s, t_e, ngbs):
        ''' extract a temporal subgrpah of the ngbs 
        
        '''
        temp_subgraph = nx.Graph()

        # add edges and nodes within the time window
        for u, v, data in self.vamana.graph.edges(data=True):
            if t_s <= data['timestamp'] <= t_e and u in ngbs and v in ngbs:
                temp_subgraph.add_edge(u, v, timestamp=data['timestamp'])

        return temp_subgraph
    
    def detect_root_cause(self, query_vector, k=10, t_s=None, t_e=None):
        ''' detect the root cause of a propagation based on vamana search and community detection
        the root cause is considered to be the node that starts the propagation path
        
        '''
        # step1: search for nearest neighbors using vamana search
        neighbors = self.vamana.search(query_vector, k=k)

        # step2: extract temporal subgraph
        temp_subgraph = self._extract_temp_subgraph(t_s, t_e, neighbors)

        # step3: detect communities in the temporal subgraph using louvain
        communities = community_louvain.best_partition(temp_subgraph)

        # step4:  Identify the root cause by considering both community structure and node properties
        # - Find the community with the most critical CVE and earliest timestamp

        community_sizes = {community: list(communities.values()).count(community) for \
                            community in set(communities.values())}
        
        # step5: score communities based on centrality, CVE, and timestamp
        root_cause_community = None
        max_score = -float('inf')

        for community, nodes in temp_subgraph.nodes.items():
            community_cves = [self.cve_data[n] for n in nodes]
            community_timestamps = [self.timestamps[n] for n in nodes]

            # calculate score for each community 
            centrality_scores = self.centrality.eigenvector_centrality(t_s, t_e)
            community_score = sum(centrality_scores.get(node, 0) for node in nodes) + \
                            sum(community_cves) - min(community_timestamps)

            # update root cause community if this one has a higher score
            if community_score > max_score:
                max_score = community_score
                root_cause_community = community
            
        # step 6: Identify the node within the root cause community with the highest centrality
        root_cause_node = max(
            [node for node, comm in communities.items() if comm == root_cause_community],
            key=lambda x: (self.cve_data.get(x, 0), self.timestamps.get(x, float('inf')), self.centrality.eigenvector_centrality(t_s, t_e).get(x, 0))
        )
        
        return root_cause_community, root_cause_node


if __name__ == "__main__":
    # data path
    small_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_small.pkl")
    # depdata_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    