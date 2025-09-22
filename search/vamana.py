'''
 # @ Create Time: 2025-06-24 12:01:26
 # @ Modified time: 2025-06-24 12:01:28
 # @ Description: greedy search from the closest neighbors to a specified point in graph p
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import numpy as np
import heapq
from cve.cvevector import CVEVector
import networkx as nx
from cve import cveinfo
from cve.cveinfo import osv_cve_api
from typing import Dict, List, Tuple, Optional, Any
import math
import heapq
from collections import defaultdict
import time
import pickle

class VamanaSearch:
    """ implementation of the vamana algorithm for approximate nearest neighbor search

    attributes:
        data: list of vector (numpy arrays) 
        graph: adjacency list mapping node indicies to list of neighbor indices
        entry_point: the entrypoint of graph
    """
    def __init__(self, M=5, ef_construction=100):
        self.M = M
        self.ef_construction = ef_construction
        self.data = []
        self.graph = {}
        self.entry_point = None  # index of the graph entry point

    def _distance(self, a, b):
        ''' compute Eudlidean distance between two vectors a and b
        
        '''
        return np.linalg.norm(a - b)
    
    def _select_neighbors(self, candidates, M):
        ''' heuristic to select up to M best neighbors from candidates

        implements the "occlusion" heuristic: iterates in order of increasing distance,
        adds if it is not closer to any already chosen neighbor.
        
        '''
        selected = []
        for dist, idx in sorted(candidates, key=lambda x: x[0]):
            good = True
            for _, s in selected:
                # if candidate idx is closer to s than is s to idx, skip
                if self._distance(self.data[idx], self.data[s]) < dist:
                    good = False
                    break
            if good:
                selected.append((dist, idx))
            if len(selected) >= M:
                break  
        return [idx for _, idx in selected]

    def search(self, query, k=10):
        ''' approximate K-NN search for a query vector
        
        1. Start at entry_point
        2. Greedy search: move to neighbors if they are closer
        3. maintain a priority queue of visited candidates up to size ef.
        4. return top k unique points found
        '''
        if self.entry_point is None:
            return []
        
        # initial best point
        current = self.entry_point
        curr_dist = self._distance(query, self.data[current])
        
        improved = True
        # greedy search to reach a local minima
        while improved:
            improved = False
            for neighbor in self.graph[current]:    
                d = self._distance(query, self.data[neighbor])
                if d < curr_dist:
                    # move to neighbor
                    current = neighbor
                    curr_dist = d
                    improved = True
        
        # best-first search around local minima
        visited = set([current])
        heap = [(curr_dist, current)]
        topk = [] # will store (-dist, idx) for max-heap

        ef = max(self.ef_construction, k)  # ensure ef is at least k

        while heap and len(visited) < ef:
            dist_top, idx_top = heapq.heappop(heap)
            # add to topk: in order to work as a maximum heap, we use negative distances
            heapq.heappush(topk, (-dist_top, idx_top))
            # explore neighbors
            for n in self.graph[idx_top]:
                if n in visited:
                    continue
                visited.add(n)
                d = self._distance(query, self.data[n])
                # candidate for topk
                heapq.heappush(heap, (d, n))

        # extract k best from topk
        result = [idx for _, idx in heapq.nsmallest(k, topk)]
        # if topk is not enough, fill current
        if not result:
            result = [current]
        return result

    def add_point(self, vector):
        ''' insert a new vector into the graph
        1. If first pint, initialize the graph and set entry point
        2. Else, search the graph to find ef_construction nearest neighbors,
        3. Select up to M neighbors using heuristic
        4. Link bi-directionally
        
        '''
        idx = len(self.data)
        self.data.append(np.array(vector))
        self.graph[idx] = []

        if self.entry_point is None:
            # first point
            self.entry_point = idx
            return idx
        
        # 1. Search for candidates using a best-first search
        candidates = self.search(vector, k = self.ef_construction)
        # build list of (distance, idx)
        dist_candidates = [(self._distance(vector, self.data[i]), i) for i in candidates]
        # 2. Prune candidates to M best neighbors
        neighbors = self._select_neighbors(dist_candidates, self.M)
        # 3. Link new node with chosen neighbors
        for n in neighbors:
            self.graph[idx].append(n)
            self.graph[n].append(idx)
        
        return idx

    
class VamanaOnCVE:
    '''
    Reduce the index granularity to (node_id, cve_idx). During searches, first hit (node, cve).
    Then perform max aggregation at the node level, ultimately returning a list of node_ids 
    (compatible with RootCauseAnalyzer).

    '''
    def __init__(self, dep_graph: nx.Graph, nodeid_to_texts: Dict[Any, List[str]], 
                 cvevector, vamana_search: VamanaSearch):
        '''
        args:
            dep_graph: networkx graph
            nodeid_to_texts: node_id -> [cve_text1, cve_text2, ...]
            cvevector: instance of CVEVector
            vamana_search: instance of VamanaSearch
        '''
        self.dep_graph = dep_graph
        self.nodeid_to_texts = nodeid_to_texts
        self.embedder = cvevector
        self.ann = vamana_search

        # build two reflection
        ## from point_id -> (node_id, cve_idx)
        self.pid_to_pair: Dict[int, Tuple[Any, int]] = {}
        ## from node_id -> list of point_id
        self.node_to_pids: Dict[Any, List[int]] = defaultdict(list)

        # build node weight
        self.cve_meta: Dict[Tuple[Any, int], Dict[str, Any]] = {}

    def build(self, cve_records: Optional[Dict[Any, List[Dict[str, Any]]]] = None):
        for node_id, texts in self.nodeid_to_texts.items():
            for i, text in enumerate(texts):
                vec = self.embedder.encode(text)
                pid = self.ann.add_point(vec)
                self.pid_to_pair[pid] = (node_id, i)
                self.node_to_pids[node_id].append(pid)
                if cve_records and node_id in cve_records and i < len(cve_records[node_id]):
                    self.cve_meta[(node_id, i)] = {
                        "cve_id": cve_records[node_id][i].get("name"),
                        "severity": cve_records[node_id][i].get("severity"),
                        "timestamp": cve_records[node_id][i].get("timestamp"),
                    }

    def _agg_node_scores(
            self,
            raw_hits: List[Tuple[int, float]],
            agg: str="max"
        ):
        per_node = defaultdict(list)
        for pid, sim in raw_hits:
            node_id, _ = self.pid_to_pair[pid]
            per_node[node_id].append((pid, sim))
        
        node_scores: Dict[Any, float] = {}
        node_best: Dict[Any, Tuple[int, float]] = {}
        # different strategies to aggregate node scores
        for node_id, arr in per_node.items():
            if agg == "mean":
                val = sum(s for _, s in arr) / len(arr)
                best_pid, best_s = max(arr, key=lambda x: x[1])
            elif agg == "sum":
                val = sum(s for _, s in arr)
                best_pid, best_s = max(arr, key=lambda x: x[1])
            else: # max
                best_pid, best_s = max(arr, key=lambda x: x[1])
                val = best_s
            node_scores[node_id] = val
            node_best[node_id] = (best_pid, best_s)
        
        return node_scores, node_best


    def search(self, 
               query_vec, 
               k = 10,
               M: Optional[int] = None,
               agg: str = "max",
               return_explanations: bool=False):
        '''
        input: query_vec (np.na)
        output: k dependent graph node_id (plus optional explanations)
        '''
        # choose enough candidates from node-level
        M = M or max(50, k*5)

        # VamanaSearch.search returns a list of point_ids only, so compute sims here
        candidate_pids = self.ann.search(query_vec, k=M) # -> [([point_id, similarity])]
        raw_hits: List[Tuple[int, float]] = []

        for pid in candidate_pids:
            # define similarity as negative euclidean distance (larger is better)
            sim = -self.ann._distance(query_vec, self.ann.data[pid])
            raw_hits.append((pid, sim))


        node_scores, node_best = self._agg_node_scores(raw_hits, agg=agg)
        top_nodes = heapq.nlargest(k, node_scores.items(), key=lambda x: x[1])
        neighbors = [n for n, _ in top_nodes]

        if not return_explanations:
            return neighbors
        
        # build explanations
        explanations: Dict[Any, Dict[str, Any]] = {}
        for node_id, _ in top_nodes:
            best_pid, best_s = node_best[node_id]
            n, cidx = self.pid_to_pair[best_pid]
            meta = self.cve_meta.get((n, cidx), {})
            explanations[node_id] = {
                'best_point_id': best_pid,
                'best_similarity': best_s,
                'best_cve_id': meta.get("cve_id"),
                "best_severity": meta.get("severity"),
                "best_timestamp_ms": meta.get("timestamp"),
                "best_text": self.nodeid_to_texts.get(node_id, [None])[cidx] if node_id in self.nodeid_to_texts else None,
            }

        return neighbors, explanations

if __name__ =="__main__":

    # load dependency graph with cve info
    cve_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl")

    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)
    
    assert isinstance(depgraph, nx.Graph), "dep_graph_cve.pkl should contain a networkx.Graph or {'graph': nx.Graph}"

    # ============ extract node -> [cve_texts] ============
    # each node has ""cve_list"" = ["CVE-xxxx"]

    nodeid_to_texts: Dict[Any, List[str]] = {}
    cve_records_for_meta: Dict[Any, List[Dict[str, Any]]] = {}

    def _first_nonempty(d: Dict[str, Any], keys: List[str]) -> Optional[str]:
        for k in keys:
            v = d.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None
    
    TEXT_KEYS = ["details", "summary", "description"]

    # warm up the persistent cache once per unique CVE id
    unique_cve_ids = {
        cve_id for _, attrs in depgraph.nodes(data=True) 
        for cve_id in (attrs.get("cve_list") or []) 
        if isinstance(cve_id, str)
    }

    for cid in unique_cve_ids:
        try:
            _ = osv_cve_api(cid)
        except Exception:
            pass
    
    for nid, attrs in depgraph.nodes(data=True):
        cve_ids = attrs.get("cve_list", []) or []
        texts: List[str] = []
        metas: List[Dict[str, Any]] = []

        for cve_id in cve_ids:
            if not isinstance(cve_id, str):
                continue
            try:
                rec = osv_cve_api(cve_id) or {}
            except Exception as e:
                rec = {"_error": str(e)}
            
            text = _first_nonempty(rec, text_keys=TEXT_KEYS)
            if not text:
                continue

            texts.append(text)
            metas.append({
                "name": rec.get("id") or rec.get("name") or cve_id,
                "severity": rec.get("severity") or rec.get("cvss") or rec.get("cvssScore"),
                "timestamp": rec.get("published") or rec.get("modified"),
            })
        
        if texts:
            nodeid_to_texts[nid] = texts
            cve_records_for_meta[nid] = metas
    

    if not nodeid_to_texts:
        raise RuntimeError("No CVE texts found. Nodes had empty cve_list or OSV lookups returned no detail.")

    # build embedder 
    embedder = CVEVector()

    # ------------ build vamana search -------------






    