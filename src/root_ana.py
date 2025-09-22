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
import pickle


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

    def _node_rank_key(self, 
                       cent_scores: Dict[int, float],
                       node_score_override: Optional[Dict[int, float]] = None):
        node_score_override = node_score_override or {}

        def _key(n: int):
            # priopritize by CVE score, then timestamp, then centrality
            cve_score = node_score_override.get(n, self.cve_scores.get(n, 0.0))
            ts_key = -self.timestamps.get(n, float('inf'))  # earlier is better
            cent = cent_scores.get(n, 0.0)
            return (cve_score, ts_key, cent)

        return _key

    def analyze(
            self,
            query_vector,
            k: int = 10,
            t_s: Optional[float] = None,
            t_e: Optional[float] = None,
            explain: bool=True,
            cve_score_lookup: Optional[callable[[str],float]] = None, # cve_id -> score
        ) -> Tuple[Optional[int], Optional[int]]:
        """
        Returns (root_community_id, root_node_id). If no nodes survive the filters, returns (None, None).
        """
        # 1) search (with explain)
        res = self.vamana.search(query_vector, k=k, return_explanations=explain)
        if explain and isinstance(res, tuple):
            neighbors, explanations = res
        else:
            neighbors, explanations = res, None

        # 2) build temporal override scores
        node_score_override: Dict[int, float] = {}
        if explanations and cve_score_lookup:
            for node_id, info in explanations.items():
                cve_id = info.get("best_cve_id")
                if cve_id:
                    try:
                        node_score_override[node_id] = cve_score_lookup(cve_id)
                    except Exception as e:
                        pass

        # 3) temporal subgraph
        temp_subgraph = self._detector.extract_temporal_subgraph(t_s, t_e, neighbors)
        if temp_subgraph.number_of_nodes() == 0:
            return None, None

        # 4) communities
        comm_res = self._detector.detect_communities(temp_subgraph)
        if not comm_res.comm_to_nodes:
            return None, None

        # 5) score communities
        root_comm, cent_scores = self._detector.choose_root_community(
            comm_to_nodes=comm_res.comm_to_nodes,
            t_s=t_s,
            t_e=t_e,
        )
        if root_comm is None:
            return None, None

        # 6) pick root node from the chosen community
        cand_nodes = [n for n, c in comm_res.partition.items() if c == root_comm]
        root_node = max(cand_nodes, key=self._node_rank_key(cent_scores))
        return root_comm, root_node


if __name__ == "__main__":
    # data path
    cve_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl")

    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)

    