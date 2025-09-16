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

SEV_WEIGHT = {'CRITICAL':5, 'HIGH':3, 'MODERATE':2, 'MEDIUM':2, 'LOW':1}

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

    # assign weight based on CVE severity
    @staticmethod
    def _severity_weight(sev: Optional[str]) -> float:
        if sev is None:
            return 1.0
        
        sev = sev.upper()
        if sev in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
            return float(SEV_WEIGHT[sev])

        return 1.0
    
    # assign weight based on timestamp
    @staticmethod
    def _time_decay(ts_ms: Optional[int], now_ms: Optional[int] = None, half_life_days: float = 90.0) -> float:
        if ts_ms is None:
            return 1.0
        if now_ms is None:
            now_ms = int(time.time() * 1000) 
        
        dt_ms = max(0, now_ms - ts_ms)
        dt_days = (now_ms - ts_ms) / 86400000

        return 0.5 ** (dt_days / half_life_days)

    def build(self, cve_records: Optional[Dict[Any, List[Dict[str, Any]]]] = None):
        


    def search(self, query_vec, k = 10):
        '''
        input: query_vec (np.na)
        output: k dependent graph node_id
        '''
        nn_ann_idx = self.ann.search(query_vec, k = k)
        return [self.ann_to_node[i] for i in nn_ann_idx if i in self.ann_to_node]


if __name__ =="__main__":
    # testing vamana search:
    vamanasearch = VamanaSearch()

    # include three groups of CVEs: log4shell, spectre, shellshock
    cve_ids = ["CVE-2021-44228", 'CVE-2021-45046', 'CVE-2021-45105', 'CVE-2021-4104',
               'CVE-2017-5753', "CVE-2017-5715", "CVE-2017-5754",
               "CVE-2014-6271", "CVE-2014-7169", "CVE-2014-7186"]

    cve_data_list = [osv_cve_api(cve_id) for cve_id in cve_ids]

    cvevector = CVEVector()
    emb_list = [cvevector.encode(cve_data["details"]) for cve_data in cve_data_list] 


    # get the distance of two vectors
    dist_vec_list = [vamanasearch._distance(emb_list[i], emb_list[i+1]) for i, _ in enumerate(emb_list) if i< len(emb_list)-1]
    print(f"the distance is {dist_vec_list}")

    # add vector to graph
    for vec in emb_list:
        print(vamanasearch.add_point(vec))
    
    # testing VamanaOnCVE
    dep_graph = vamanasearch.graph

    nodeid_to_text = {cve_ids[i]: cve_data_list[i]["details"] for i in range(len(cve_ids))}

    vamanaoncve = VamanaOnCVE(dep_graph, nodeid_to_text, cvevector)

    results = vamanaoncve.search(emb_list[3])

    print(f"query {emb_list[3]} on graph with cve info is: \n{results}")
    