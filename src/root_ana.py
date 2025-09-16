'''
 # @ Create Time: 2024-09-19 15:12:57
 # @ Modified time: 2024-09-19 15:43:24
 # @ Description: module to locate root cause software for vulnerablity
 '''
import sys 
from pathlib import Path 
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from typing import Dict, Iterable, Optional, Tuple
import networkx as nx
from search.vamana import VamanaOnCVE, VamanaSearch
from cent.temp_cent import TempCentricity
from com.commdet import TemporalCommDetector
import random
from cve.cveinfo import osv_cve_api 
from cve.cvevector import CVEVector
import pickle

SEV_WEIGHT = {'CRITICAL':5, 'HIGH':3, 'MODERATE':2, 'MEDIUM':2, 'LOW':1}

class RootCauseAnalyzer:
    '''
    orchestrates root-cause detection:
    1) Use Vamana to get nearest neighbors to a query vector
    2) Build a temporal subgraph over those candidates
    3) Detect a communities and score them temporally
    4) Choose a representative root node from the top community

    
    The root node is selected by a tie-breaker prioritizing:
      - higher CVE score
      - earlier timestamp
      - higher eigenvector centrality
    '''

    def __init__(
        self,
        vamana: VamanaOnCVE,
        cve_scores: Dict[int, float],
        timestamps: Dict[int, float],
        centrality: TempCentricity,
        ) -> None:
        self.vamana = vamana
        self.cve_scores = cve_scores
        self.timestamps = timestamps
        self.centrality = centrality   

        self._detector = TemporalCommDetector(
            dep_graph=vamana.dep_graph,
            timestamps=timestamps,
            cve_scores=cve_scores,
            centrality_provider=centrality,
        )

    def _node_rank_key(self, cent_scores: Dict[int, float]):
        def _key(n: int):
            return (
                self.cve_scores.get(n, 0.0),
                -self.timestamps.get(n, float("inf")),
                cent_scores.get(n, 0.0),
            )
        return _key

    def analyze(
            self,
            query_vector,
            k: int = 10,
            t_s: Optional[float] = None,
            t_e: Optional[float] = None,
        ) -> Tuple[Optional[int], Optional[int]]:
        """
        Returns (root_community_id, root_node_id). If no nodes survive the filters, returns (None, None).
        """
                # 1) nearest neighbors from Vamana
        neighbors = self.vamana.search(query_vector, k=k)

        # 2) temporal subgraph
        temp_subgraph = self._detector.extract_temporal_subgraph(t_s, t_e, neighbors)
        if temp_subgraph.number_of_nodes() == 0:
            return None, None

        # 3) communities
        comm_res = self._detector.detect_communities(temp_subgraph)
        if not comm_res.comm_to_nodes:
            return None, None

        # 4) score communities
        root_comm, cent_scores = self._detector.choose_root_community(
            comm_to_nodes=comm_res.comm_to_nodes,
            t_s=t_s,
            t_e=t_e,
        )
        if root_comm is None:
            return None, None

        # 5) pick root node from the chosen community
        cand_nodes = [n for n, c in comm_res.partition.items() if c == root_comm]
        root_node = max(cand_nodes, key=self._node_rank_key(cent_scores))
        return root_comm, root_node


if __name__ == "__main__":
    # data path
    # small_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_small.pkl")
    cve_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl")

    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)

    # create vamana instance
    vamanasearch = VamanaSearch()

    cve_nodes_ids = [(nid, attrs["cve_list"]) for nid, attrs in depgraph.nodes(data=True) if attrs['has_cve']]

    cve_data_list = [osv_cve_api(cve_id) for cve_id in cve_ids]

    cvevector = CVEVector()
    emb_list = [cvevector.encode(cve_data["details"]) for cve_data in cve_data_list]

    # get the distance of two vectors
    dist_vec_list = [vamanasearch._distance(emb_list[i], emb_list[i+1]) for i in range(len(emb_list)-1)]
    print(f"pairwise distances: {dist_vec_list}")

    # add vector to graph
    for vec in emb_list:
        print("added point id:", vamanasearch.add_point(vec))

    # build vamana-on-CVE
    nodeid_to_text = {cve_ids[i]: cve_data_list[i]["details"] for i in range(len(cve_ids))}
    vamanaoncve = VamanaOnCVE(depgraph, nodeid_to_text, cvevector)

    # mock CVE scores and timestamps
    nodes_ids = list(depgraph.nodes())

    
    # if your depgraph already has timestamps as node attributes, extract them; otherwise fake them
    timestamps = {n: depgraph.nodes[n].get("timestamp", random.uniform(0, 1000)) for n in nodes_ids}

    analyzer = RootCauseAnalyzer(
        vamana=vamanaoncve,
        cve_scores=node_to_cve_score,
        timestamps=timestamps,
        centrality=TempCentricity(depgraph),
    )

    root_comm, root_node = analyzer.analyze(emb_list[3], k=10, t_s=100, t_e=700)
    print(f"[Result] root community: {root_comm}, root node: {root_node}")