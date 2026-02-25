from dataclasses import dataclass
from typing import List, Optional, Dict, Iterable, Tuple, Set
from functools import lru_cache

import networkx as nx
import community.community_louvain as community_louvain

@dataclass
class CommunityResult:
    ''' container for community detection result
    
    '''
    partition: Dict[int, int] # node -> community id
    comm_to_nodes: Dict[int, List[int]] # community id -> list od nodes


class TemporalCommDetector:
    ''' 
    Temporal graph-based community detection and scoring
    - timestamp live on Nodes, not edges
    - filter by a time window and an optional node whitelist (e.g., nearest neighbors from a search index).
    - community detection uses louvain
    - community score = sum(CVE) + sum(centrality) - min(timestamp)   (earlier communities get higher priority).
    
    '''
    def __init__(self,
                 dep_graph: nx.Graph,
                timestamps: Dict[int, float],
                cve_scores: Dict[int, float],
                centrality_provider, # expects .eigenvector_centrality(t_s, t_e) -> Dict[node, float]
                 ) -> None:
        self.dep_graph = dep_graph
        self.timestamps = timestamps
        self.cve_scores = cve_scores
        self.centrality_provider = centrality_provider
    
    # --------------- subgraph extraction ---------------
    
    def extract_temporal_subgraph(
                self,
                t_s: Optional[float],
                t_e: Optional[float],
                node_whitelist: Iterable[int],
                ) -> nx.Graph:
        ''' 
        Build a temporal subgraph limited to:
            - nodes in node_whitelist
            - nodes with t_s <= timestamp <= t_e (open-ended if None)
            - edges induced by the kept nodes from the original graph
        
        '''

        # for debug 
        print("whitelist size:", len(list(node_whitelist)))
        print("min/max ts in map:", 
            (min(self.timestamps.values()) if self.timestamps else None,
            max(self.timestamps.values()) if self.timestamps else None))

        if t_s is None:
            t_s = float("-inf")
        if t_e is None:
            t_e = float("inf")

        if t_s == float("-inf") and t_e == float("inf"):
            return self.dep_graph

        allowed_nodes = {
            n for n in node_whitelist
            if (n in self.timestamps) and (t_s <= self.timestamps[n] <= t_e)
        }

        temp_subgraph = self.dep_graph.subgraph(allowed_nodes)
        nx.set_node_attributes(
            temp_subgraph, {n: {"timestamp": self.timestamps.get(n)} for n in temp_subgraph.nodes}
        )
        return temp_subgraph

    # --------------- community detection ---------------

    def detect_communities(self, subgraph: nx.Graph) -> CommunityResult:
        """Run Louvain on the provided subgraph and return the node->community mapping and reverse index."""
        if subgraph.number_of_nodes() == 0:
            return CommunityResult(partition={}, comm_to_nodes={})
        
        if subgraph.number_of_edges() == 0:
            # make the single node its own community
            partition = {n: i for i, n in enumerate(subgraph.nodes())}
            comm_to_nodes = {i: [n] for i, n in enumerate(subgraph.nodes())}
            return CommunityResult(partition=partition, comm_to_nodes=comm_to_nodes)

        # Convert to undirected if needed
        if subgraph.is_directed():
            subgraph = subgraph.to_undirected()

        partition = community_louvain.best_partition(subgraph)
        comm_to_nodes: Dict[int, List[int]] = {}
        for node, comm in partition.items():
            comm_to_nodes.setdefault(comm, []).append(node)
        
        return CommunityResult(partition=partition, comm_to_nodes=comm_to_nodes)
    
    # --------- scoring ---------
    def _community_score(
        self,
        nodes: Iterable[int],
        cent_scores: Dict[int, float],
        ) -> float:
        cve_sum = sum(self.cve_scores.get(n, 0.0) for n in nodes)
        cent_sum = sum(cent_scores.get(n, 0.0) for n in nodes)
        # earlier (smaller) timestamps should increase priority -> subtract min timestamp
        min_ts = min(self.timestamps.get(n, float("inf")) for n in nodes)
        return cve_sum + cent_sum - min_ts
    
    
    def timestamp_of(self, nid):
        data = self.dep_graph.nodes.get(nid, {})
        ts = data.get("timestamp")
        if ts:
            return float(ts)
        else:
            return None

    def choose_root_community(
        self,
        comm_to_nodes: Dict[int, List[int]],
        t_s: Optional[float],
        t_e: Optional[float],
        node_subset: Optional[Set] = None,
        ) -> Tuple[Optional[int], Dict[int, float]]:
        '''
        select the best community id according to the scoring rule
        returns (best_comm_id, comm_scores)

        Optimizations:
          [Opt 1] node_subset: compute centrality only on community nodes,
                  not the full 14M-node graph. Falls back to all comm nodes
                  if not provided.
          [Opt 2] _cent_cache: cache centrality results keyed by (t_s, t_e,
                  frozenset(subset)) so repeated window calls with same params
                  are instant.

        '''
        # [Opt 1] restrict centrality to community nodes only
        if node_subset is None:
            node_subset = set(n for nodes in comm_to_nodes.values() for n in nodes)

        # [Opt 2] cache key: round timestamps to nearest second to absorb float noise
        cache_key = (round(t_s or 0), round(t_e or 0), frozenset(node_subset))
        if not hasattr(self, '_cent_cache'):
            self._cent_cache = {}
        
        if cache_key in self._cent_cache:
            evc_dict = self._cent_cache[cache_key]
        else:
            # compute centrality only on the relevant subset of nodes
            sub = self.dep_graph.subgraph(node_subset)
            try:
                if sub.number_of_nodes() > 1 and sub.number_of_edges() > 0:
                    ug = sub.to_undirected() if sub.is_directed() else sub
                    evc_dict = nx.eigenvector_centrality(
                        ug, max_iter=200, tol=1e-6, weight=None
                    )
                else:
                    evc_dict = {n: 1.0 for n in sub.nodes()}
            except Exception:
                # fallback: degree centrality (always fast and never fails)
                evc_dict = {n: sub.degree(n) for n in sub.nodes()}

            self._cent_cache[cache_key] = evc_dict

            # keep cache bounded to avoid memory blowup (~500 entries max)
            if len(self._cent_cache) > 500:
                oldest = next(iter(self._cent_cache))
                del self._cent_cache[oldest]

        best_comm = None
        best_score = float("-inf")
        
        if not evc_dict:
            for comm, nodes in comm_to_nodes.items():
                cve_sum = sum(self.cve_scores.get(n, 0.0) for n in nodes)
                min_ts = min(self.timestamps.get(n, float("inf")) for n in nodes)
                score = cve_sum - min_ts
                if score > best_score:
                    best_score = score
                    best_comm = comm
            
            return best_comm, evc_dict
        
        for comm, nodes in comm_to_nodes.items():
            if not nodes:
                continue
            score = self._community_score(nodes, evc_dict)
            if score > best_score:
                best_score = score
                best_comm = comm

        return best_comm, evc_dict
        