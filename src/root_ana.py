'''
 # @ Create Time: 2024-09-19 15:12:57
 # @ Modified time: 2024-09-19 15:43:24
 # @ Description: module to locate root cause software for vulnerablity
 '''
import sys 
from pathlib import Path 
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from typing import Dict, Iterable, Optional, Tuple,Callable
from search.vamana import VamanaOnCVE, VamanaSearch
from cve.cvevector import CVEVector
from cent.temp_cent import TempCentricity
from com.commdet import TemporalCommDetector
import random
from cve.cveinfo import osv_cve_api 
from cve.cvescore import load_cve_seve_json, cve_score_dict_gen, _normalize_cve_id
import pickle
from utils.util import _first_nonempty, _synth_text_from_dict   
import argparse


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
            cve_score_lookup: Optional[Callable[[str],float]] = None, # cve_id -> score
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


def main(query_vec = None, k=15):
    # data path
    cve_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl")
    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)

    nodes = list(depgraph.nodes)

    unique_cve_ids = {
        cid for _, attrs in depgraph.nodes(data=True) 
        for cid in ([_normalize_cve_id(x) for x in (attrs.get("cve_list") or [])])
        if cid
    }

    cve_agg_data_dict_path = Path.cwd().parent.joinpath("data", "aggregated_data.json")
    cve_agg_data_dict = load_cve_seve_json(cve_agg_data_dict_path)
    cve_scores = cve_score_dict_gen(unique_cve_ids, cve_agg_data_dict)

    try:
        timestamps = {n: float(depgraph.nodes[n]["timestamp"]) for n in nodes}
    except KeyError:
        raise KeyError("depgraph nodes missing 'timestamp' attribute")
    
    centrality = TempCentricity(depgraph)
    embedder = CVEVector()

    nodeid_to_texts = {}
    TEXT_KEYS = ["details", "summary", "description"]

    for nid, attrs in depgraph.nodes(data=True):
        raw_list = attrs.get("cve_list", []) or []
        texts = []
        for raw in raw_list:
            cid = _normalize_cve_id(raw)
            try:
                rec = osv_cve_api(cid) or {}
            except Exception as e:
                rec = {"_error": str(e)}
            text = _first_nonempty(rec, TEXT_KEYS)
            if not text and isinstance(raw, dict):
                text = _synth_text_from_dict(cid, raw)
            texts.append(text)
        if texts:
            nodeid_to_texts[nid] = texts

    if not nodeid_to_texts:
        raise RuntimeError("No CVE texts found.")

    ann = VamanaSearch()
    vamana = VamanaOnCVE(depgraph, nodeid_to_texts, embedder, ann)

    analyzer = RootCauseAnalyzer(
        vamana=vamana,
        cve_scores=cve_scores,
        timestamps=timestamps,
        centrality=centrality,
    )
    
    all_ts = sorted(timestamps.values())
    t_s = all_ts[len(all_ts) // 4]
    t_e = all_ts[3 * len(all_ts) // 4]

    def _cve_score_lookup(cve_id: str) -> float:
        return cve_scores.get(cve_id, 0.0)

    query_vec = query_vec or [random.random() for _ in range(16)]
    print("Running RootCauseAnalyzer...")

    root_comm, root_node = analyzer.analyze(
        query_vector=query_vec,
        k=k,
        t_s=t_s,
        t_e=t_e,
        explain=True,
        cve_score_lookup=_cve_score_lookup,
    )

    if root_comm is None or root_node is None:
        print("No root cause detected in the given window.")
    else:
        nd = depgraph.nodes[root_node]
        print(f"Root community: {root_comm}")
        print(f"Root node: {root_node}")
        print({
            "cve_id": nd.get("cve_id"),
            "cve_score": cve_scores[root_node],
            "timestamp": timestamps[root_node],
        })

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run RootCauseAnalyzer on a query vector")
    parser.add_argument("--query", type=float, nargs="+", help="Query vector as a list of floats")
    parser.add_argument("--k", type=int, default=15, help="Number of nearest neighbors")
    args = parser.parse_args()

    main(query_vec=args.query, k=args.k)