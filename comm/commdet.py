import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from community import community_louvain
import networkx as nx
from search.vamana import VamanaSearch, VamanaOnCVE
from cent.temp_cent import TempCentricity

# Louvain Community Detection
def detect_communities(graph):
    G = nx.Graph(graph)
    partition = community_louvain.best_partition(G)
    return partition

class VLWithTempCent:
    '''
    key points:
        - timestamp is on node, filter out timestamp on node, generated subgraph on temporap depgraph
        - community detection with louvain
        - community score: sum (CVE) + sum (centrality) - min(timestamp) -> earlier has higher priority
        - the root node in community: 

    '''
    def __init__(self, vamana: VamanaOnCVE, cve_data, timestamps, centrality: TempCentricity):
        self.vamana = vamana
        self.cve_data = cve_data    
        self.timestamps = timestamps
        self.centrality = centrality
    
    def _extract_temp_subgraph(self, t_s, t_e, ngbs):
        ''' extract a temporal subgrpah limited to:
        - nodes in "ngbs"
        - nodes whoe timestamp is within [t_s, t_e] 
        - edges from the original graph whose endpoints are both included nodes
        Note: timestamps are on "nodes", not edges

        '''
        # allow open-ended windows
        if t_s is None:
            t_s = float("-inf")
        if t_e is None:
            t_e = float("inf")
        
        allowed_nodes = {
            n for n in ngbs 
            if (n in self.timestamps) and (t_s <= self.timestamps[n] <= t_e)
        }

        G = self.vamana.dep_graph
        temp_subgraph = G.subgraph(allowed_nodes).copy()
        nx.set_node_attributes(
            temp_subgraph, {n: {"timestamp": self.timestamps.get(n)} for n in temp_subgraph.nodes}
        )

        return temp_subgraph
    

    def detect_root_cause(self, query_vector, k=10, t_s=None, t_e=None):
        ''' detect the root cause of a propagation based on vamana search and community detection
        the root cause is considered to be the node that starts the propagation path
        
        '''
        # step1: search for nearest neighbors using vamana search
        neighbors = self.vamana.search(query_vector, k=k)
        # step2: extract temporal subgraph
        temp_subgraph = self._extract_temp_subgraph(t_s, t_e, neighbors)
        if temp_subgraph.number_of_nodes() == 0:
            print("[Info] Temporal subgraph empty under given window.")
            return None, None

        # step3: detect communities in the temporal subgraph using louvain
        communities = community_louvain.best_partition(temp_subgraph)   

        comm_to_nodes = {}
        for node, comm in communities.items():
            comm_to_nodes.setdefault(comm, []).append(node)
        
        cent_scores = self.centrality.eigenvector_centrality(t_s, t_e)

        def community_score(nodes):
            cve_sum = sum(self.cve_data.get(n, 0.0) for n in nodes)
            cent_sum = sum(cent_scores.get(n, 0.0) for n in nodes)
            min_ts = min(self.timestamps.get(n, float("inf")) for n in nodes)
            return cve_sum + cent_sum + min_ts
        
        root_comm, max_score = None, float("-inf")
        for comm, nodes in comm_to_nodes.items():
            score = community_score(nodes)
            if score > max_score:
                max_score = score
                root_comm = comm
        
        if root_comm is None:
            return None, None
        
        cand_nodes = [n for n, c in communities.items() if c == root_comm]

        def node_key(n):
            return (
                self.cve_data.get(n, 0.0),
                -self.timestamps.get(n, float("inf")),
                cent_scores.get(n, 0.0),
            )

        root_node = max(cand_nodes, key=node_key)
        return root_comm, root_node


if __name__ == "__main__":
    # data path
    small_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_small.pkl")
    # depdata_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    
    