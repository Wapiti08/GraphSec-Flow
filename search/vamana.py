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
from cve.cvescore import _normalize_cve_id,_nvd_pick_cvss_v31, _nvd_extract_references, _nvd_infer_packages_from_cpe
from cve.cvescore import _osv_pick_cvss_v3, _osv_extract_references, _osv_infer_packages, _osv_extract_fix_commits
from typing import Dict, List, Tuple, Optional, Any
import math
import heapq
from collections import defaultdict
import time
import pickle
from search.sideeval import eval_node_self_recall, print_top_similar_pairs, write_eval_report
from utils.util import _first_nonempty, _synth_text_from_dict


class VamanaSearch:
    """ implementation of the vamana algorithm for approximate nearest neighbor search

    attributes:
        data: list of vector (numpy arrays) 
        graph: adjacency list mapping node indicies to list of neighbor indices
        entry_point: the entrypoint of graph
    """
    def __init__(self, M=32, ef_construction=200, ef_search=128):
        '''
        args:
            m: max number of neighbors per node
            ef_construction: size of the priority queue during construction
        '''
        self.M = M
        self.ef_construction = ef_construction
        self.ef_search = ef_search
        self.data = []
        self.graph = {}
        self.entry_point = None  # index of the graph entry point

    def _distance(self, a, b):
        ''' compute distance between two vectors a and b
        
        '''
        # test wtih euclidean distance
        # return np.linalg.norm(a - b)

        # test wtih cosine distance
        a = a / (np.linalg.norm(a) + 1e-12)
        b = b / (np.linalg.norm(b) + 1e-12)

        return 1.0 - float(np.dot(a, b))

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

        ef = max(self.ef_search, k)  # ensure ef is at least k

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
                # normalize vector --- important
                vec = vec / (np.linalg.norm(vec) + 1e-12)
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
            agg: str="mean"
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
               agg: str = "mean",
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
            sim = float(np.dot(query_vec, self.ann.data[pid]))
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

def _append_meta_from_raw(metas: List[Dict[str, Any]], rec: Dict[str, Any]) -> None:
    '''
    Append a normalized metadata record into `metas` based on `rec`.

    '''
    
    if not rec or not isinstance(rec, dict):
        return

    src = rec.get("source")
    data = rec.get("data") if isinstance(rec.get("data"), dict) else None

    if src == "nvd" and isinstance(data, dict):
        for it in (data.get("vulnerabilities") or []):
            cve = it.get("cve") or {}
            cid = cve.get("id")
            base, vec, sev_src = _nvd_pick_cvss_v31(cve)
            metas.append({
                "name": cid,
                "timestamp": cve.get("published") or cve.get("lastModified"),
                "severity": {
                    "base_score": base,
                    "vector": vec,
                    "source": sev_src or "NVD",
                },
                "references": _nvd_extract_references(cve),
                "packages": _nvd_infer_packages_from_cpe(cve),
                "source": "NVD",
            })
        return
    
    osv_data = data if data else rec
    if "id" in osv_data or "affected" in osv_data or "references" in osv_data:
        cid = osv_data.get("id")
        base, vec, sev_src = _osv_pick_cvss_v3(osv_data)
        metas.append({
            "name": cid,
            "timestamp": osv_data.get("published") or osv_data.get("modified"),
            "severity": {
                "base_score": base,
                "vector": vec,
                "source": sev_src or "OSV",
            },
            "references": _osv_extract_references(osv_data),
            "packages": _osv_infer_packages(osv_data),
            "fix_commits": _osv_extract_fix_commits(osv_data),
            "source": "OSV",
        })
        return
    return


def _load_or_build_texts_and_meta(depgraph, force_rebuild=False):
    '''
    return:
        - nodeid_to_texts: Dict[Any, List[str]]
        - cve_records_for_meta: Dict[Any, List[Dict[str, Any]]]
    '''

    data_dir = Path.cwd().parent.joinpath("data")
    
    node_texts_path = data_dir.joinpath("nodeid_to_texts.pkl")
    cve_meta_path = data_dir.joinpath("cve_records_for_meta.pkl")

    # use cache if exists
    if (not force_rebuild) and node_texts_path.exists() and cve_meta_path.exists():
        nodeid_to_texts = pickle.loads(node_texts_path.read_bytes())
        cve_records_for_meta = pickle.loads(cve_meta_path.read_bytes())
        print(f"[cache] Loaded nodeid_to_texts & cve_records_for_meta from {data_dir}")
        return nodeid_to_texts, cve_records_for_meta
    
    print("[info] Rebuilding nodeid_to_texts & cve_records_for_meta from depgraph...")
    TEXT_KEYS = ["details", "summary", "description"]
    nodeid_to_texts: Dict[Any, List[str]] = {}
    cve_records_for_meta: Dict[Any, List[Dict[str, Any]]] = {}
    fallback_used = 0
    osv_hits = 0
    dropped = 0

    # warm up the persistent cache once per unique CVE id
    unique_cve_ids = {
        cid for _, attrs in depgraph.nodes(data=True) 
        for cid in ([_normalize_cve_id(x) for x in (attrs.get("cve_list") or [])])
        if cid
    }

    # warm up the persistent cache once per unique CVE id
    for cid in unique_cve_ids:
        try:
            _ = osv_cve_api(cid)
        except Exception:
            pass
    
    # build for each node
    for nid, attrs in depgraph.nodes(data=True):
        raw_list = attrs.get("cve_list", []) or []
        texts: List[str] = []
        metas: List[Dict[str, Any]] = []

        for raw in raw_list:
            cid = _normalize_cve_id(raw)
            if not cid:
                dropped += 1
                continue

            # Try OSV first
            rec: Dict[str, Any] = {}
            try:
                rec = osv_cve_api(cid) or {}
            except Exception as e:
                rec = {"_error": str(e)}
            
            if "source" in rec:
                rec = rec["data"]
                
            text = _first_nonempty(rec, TEXT_KEYS)
            
            # Fallback: synthesize a minimal text from the node's dict if OSV had nothing
            if not text and isinstance(raw, dict):
                text = _synth_text_from_dict(cid, raw)
                if text:
                    fallback_used += 1
            elif text:
                osv_hits += 1

            if not text:
                dropped += 1
                continue

            texts.append(text)
            _append_meta_from_raw(metas, rec)
        
        if texts:
            nodeid_to_texts[nid] = texts
            cve_records_for_meta[nid] = metas
    
    if not nodeid_to_texts:
        raise RuntimeError("No CVE texts found. Nodes had empty cve_list or OSV lookups returned no detail.")

    # write cache
    node_texts_path.write_bytes(pickle.dumps(nodeid_to_texts))
    cve_meta_path.write_bytes(pickle.dumps(cve_records_for_meta))
    print(f"[build] Wrote nodeid_to_texts & cve_records_for_meta to {data_dir}")
    print(f"[build] Wrote cve_records_for_meta to {data_dir}")

    print({
        "nodes_indexed": len(nodeid_to_texts),
        "total_nodes": depgraph.number_of_nodes(),
        "osv_hits": osv_hits,
        "fallback_used": fallback_used,
        "dropped_entries": dropped,
    })

    return nodeid_to_texts, cve_records_for_meta


if __name__ =="__main__":

    # load dependency graph with cve info
    cve_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl")

    with cve_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)
    assert isinstance(depgraph, nx.Graph), "dep_graph_cve.pkl should contain a networkx.Graph or {'graph': nx.Graph}"

    # read cache or build nodeid_to_texts and cve_records_for_meta
    nodeid_to_texts, cve_records_for_meta = _load_or_build_texts_and_meta(depgraph, force_rebuild=False)

    # ---------- build embedder -----------
    embedder = CVEVector()
    ann = VamanaSearch()
    vac = VamanaOnCVE(depgraph, nodeid_to_texts, embedder, ann)
    vac.build(cve_records=cve_records_for_meta)

    # quick coverage from your build phase
    coverage = {
        "nodes_indexed": len(nodeid_to_texts),
        "total_nodes": depgraph.number_of_nodes(),
    }

    # 1) Quantitative reliability
    metrics = eval_node_self_recall(vac, k=5, sample_size=200)

    # 2) Qualitative evidence 
    print_top_similar_pairs(vac, per_point_k=5, top_pairs=10)
 
    # 3) Persist a small JSON report for reproducibility
    write_eval_report(
        "vamana_eval_report.json",
        coverage=coverage,
        metrics=metrics,
        params={
            "M": vac.ann.M,
            "ef_construction": vac.ann.ef_construction,
            "agg": "mean",
            # euclidean distance d is converted to similarity as 1/(1+d)
            # "similarity": "1/(1+euclidean)"
            # cosine distance d is converted to similarity as 1-d
            "similarity": "1-cosine"
        }
    )

    # ------------ form a query vector ------------
    any_node = next(iter(nodeid_to_texts))
    sample_text = nodeid_to_texts[any_node][0]
    print(f"[info] Using node {any_node}'s first CVE text as the query.")

    query_vec = embedder.encode(sample_text)
    # normalize query
    query_vec = query_vec / (np.linalg.norm(query_vec) + 1e-12)

    # ------------ run search and print results ------------
    start = time.time()
    neighbors, explanations = vac.search(query_vec, k=5, agg="mean", return_explanations=True)
    ms = (time.time() - start) * 1000.0

    print("\n Top-5 nodes (nearest by CVE text):")
    for rank, nid in enumerate(neighbors, 1):
        exp = explanations.get(nid, {})
        print(f"{rank}. node={nid}  sim={exp.get('best_similarity'):.4f}  "
              f"cve={exp.get('best_cve_id') or 'N/A'}  severity={exp.get('best_severity') or 'N/A'}")
        bt = exp.get("best_text")
        if bt:
            snip = (bt[:140] + "…") if len(bt) > 140 else bt
            print(f"   text: {snip}")
    print(f"\nSearch finished in {ms:.1f} ms")

    