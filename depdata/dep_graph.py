'''
 # @ Create Time: 2024-11-17 12:01:10
 # @ Modified time: 2024-11-17 12:01:21
 # @ Description: extract the dependency nodes only and construct new dependency based on timeline info
 '''

from __future__ import annotations

from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path
from bisect import bisect_left
import logging
import pickle
import networkx as nx
import json
import os
from typing import Dict, Iterable, Iterator, List, Tuple, Any, Optional


logger = logging.getLogger(__name__)

# worker globals & helpers
_G: Dict[str, Any] = {}

def _worker_init(settings):
    '''
    Called once per worker. Stores large, read-only structures to avoid
    resending them with every task.
    '''
    _G.update(settings)

def _releases_in_range(software_id: str, start_ts: int, end_ts: int ) -> Iterator[str]:
    '''
    return release IDs for a software where timestamp in [start_ts, end_ts)
    user pre-sorted lists + bisect for O(log n) indexing    
    '''
    rels = _G['soft_to_rel'].get(software_id)
    if not rels:
        return iter(())
    ts_list = _G['soft_ts_lists'][software_id]
    i = bisect_left(ts_list, start_ts)
    j = bisect_left(ts_list, end_ts)
    # yield only release ids
    return (rels[k][0] for k in range(i, j))

def process_edges_chunk(chunk: List[Tuple[str, str, Dict[str, Any]]]):
    '''
    worker: consume a chunk of edges, produce:
        - edges_out: list of (u, v)
        - node_attrs: dict node_id -> {attrs}
    '''
    nodes      =  _G['nodes']
    is_release =  _G["is_release"]
    get_ts     = _G['get_timestamp']
    time_ranges = _G["time_ranges"]
    release_nodes = _G["release_nodes"]
    release_ts   = _G['release_ts']   # precomputed for release ids (fast path)

    edges_out: List[Tuple[str, str]] = []
    node_attrs: Dict[str, Dict[str, Any]] = {}

    def _ensure_attrs(nid: str):
        if nid not in node_attrs:
            n = nodes[nid]
            node_attrs[nid] = {
                "version": n.get("version", ""),
                "timestamp": n.get("timestamp", "")
            }
        
    for src, tgt, _ in chunk:
        # only consider release sources
        src_node = nodes[src]
        if not is_release(src_node):
            continue

        src_lo, src_hi = time_ranges.get(src, (0, float('inf')))

        tgt_node = nodes[tgt]
        # Case A: target is software (not a release) -> connect to its releases in range
        if not is_release(tgt_node):
            for rel in _releases_in_range(tgt, src_lo, src_hi):
                if rel in release_nodes:
                    edges_out.append((src, rel))
                    _ensure_attrs(src)
                    _ensure_attrs(rel)
        
        # Case B: target is a release -> direct edge if in rane
        else:
            tgt_ts = release_ts.get(tgt)
            if tgt_ts is None:
                tgt_ts = get_ts(tgt_node)
                release_ts[tgt] = tgt_ts 
            if src_lo <= tgt_ts < src_hi:
                edges_out.append((src, tgt))
                _ensure_attrs(src)
                _ensure_attrs(tgt)
    # return edges and node attributes
    return edges_out, node_attrs

# --------------------------------------------------------------
# Main class
# --------------------------------------------------------------

class DepGraph:
    def __init__(self, nodes: Dict[str, Dict[str, Any]],
                edges: List[Tuple[str, str, Dict[str, Any]]]):
        '''
        nodes: {node_id: {labels, version, timestamp, type, value, ...}}
        edges: [(src_id, tgt_id, {'label': ...}), ...]
        '''
        self.nodes = nodes
        self.edges = edges
        self.get_addvalue_edges()

    # ------------------------ Utility helpers ------------------------

    def str_to_json(self, maybe_str: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(maybe_str, str):
            return None
        try:
            clean = maybe_str.replace('\\"', '"')
            return json.loads(clean)
        except Exception:
            return None

    def get_timestamp(self, node: Dict[str, Any]) -> int:
        try:
            return int(node.get("timestamp", 0))
        except Exception:
            return 0

    def is_release(self, node: Dict[str, Any]) -> bool:
        labels = node.get("labels", [])
        if isinstance(labels, str):
            return labels == ":Release"
        # handle list-like
        try:
            return ":Release" in labels
        except Exception:
            return False

    # ------------------------ AddedValue / CVE ------------------------

    def get_addvalue_edges(self) -> None:
        """Build source->list of AddedValue node ids for label=='addedValues'."""
        self.addvalue_dict: Dict[str, List[str]] = defaultdict(list)
        for source, target, edge_att in self.edges:
            if edge_att.get('label') == "addedValues":
                self.addvalue_dict[source].append(target)

    def cve_check(self, source: str) -> bool:
        """Return True if any AddedValue node attached to `source` has non-empty 'cve'."""
        for node_id in self.addvalue_dict.get(source, []):
            node = self.nodes.get(node_id, {})
            if node.get('type') == "CVE":
                data = self.str_to_json(node.get("value", "{}")) or {}
                if data.get('cve'):
                    return True
        return False

    # ------------------------ Neighborhood & filters ------------------------

    def covt_ngb_format(self) -> Dict[str, List[str]]:
        """Build adjacency as {src: [tgt, ...]} from triple edges."""
        node_ngbs: Dict[str, List[str]] = {}
        for source, target, _ in self.edges:
            node_ngbs.setdefault(source, []).append(target)
        return node_ngbs

    def get_releases(self) -> Dict[str, Dict[str, Any]]:
        return {nid: data for nid, data in self.nodes.items() if self.is_release(data)}


    def get_cve_releases(self) -> Dict[str, Dict[str, Any]]:
        """If you want only releases that have CVE AddedValues attached."""
        return {
            nid: data for nid, data in self.nodes.items()
            if data.get('labels') == ":AddedValue" and self.cve_check(nid)
        }
    
    
    def rel_to_soft(self) -> Dict[str, str]:
        """
        Build release->software mapping from:
          - 'relationship_AR': source=software, target=release
          - 'dependency': source=release, target=software
        """
        release_to_software: Dict[str, str] = {}
        for src, tgt, attr in self.edges:
            label = attr.get('label')
            if label == "relationship_AR":
                # software -> release
                release_to_software[tgt] = src
            elif label == "dependency":
                # release -> software
                release_to_software[src] = tgt
        return release_to_software
    

    def soft_to_rel(self, release_to_software: Dict[str, str]
                    ) -> Dict[str, List[Tuple[str, int]]]:
        """
        Group releases by software with timestamps, sorted ascending by ts.
        Returns: {software_id: [(release_id, ts), ...]}
        """
        software_releases: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
        for release, software in release_to_software.items():
            node = self.nodes.get(release)
            if not node or not self.is_release(node):
                continue
            ts = self.get_timestamp(node)
            software_releases[software].append((release, ts))
        for s, rels in software_releases.items():
            rels.sort(key=lambda x: x[1])
        return software_releases
    
    def time_ranges(self, software_to_release: Dict[str, List[Tuple[str, int]]]
                ) -> Dict[str, Tuple[int, float]]:
        '''
        for each release, define a half-open validity range [ts_i, ts_{i+1})
        within the same software line; last one is open-ended (inf).
        Returns: {release_id: (start_ts, end_ts)}
        '''
        tr: Dict[str, Tuple[int, float]] = {}
        for _soft, rels in software_to_release.items():
            if not rels:
                continue
            ts_list = [ts for _, ts in rels] + [float('inf')]
            for i, (rid, ts) in enumerate(rels):
                tr[rid] = (ts, ts_list[i + 1])
        
        return tr
    
    def filter_edges(self) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
        """
        Yield only edges we care about (dependency and relationship_AR),
        preserving original direction:
          - dependency: software -> release
          - relationship_AR: release  -> software
        """
        for src, tgt, attr in self.edges:
            label = attr.get('label')
            if label in {'dependency', 'relationship_AR'}:
                yield (src, tgt, attr)
    
    # ---------------------- Chunking ----------------------
    
    @staticmethod
    def _chunk_generator(generator: Iterable[Any], chunk_size: int) -> Iterator[List[Any]]:
        ''' yield lists of size chunk_size from an iterable/generator
        
        '''
        chunk: List[Any] = []
        for item in generator:
            chunk.append(item)
            if len(chunk) == chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk
    
    # -------------------- Parallel build ---------------------
    
    def dep_graph_build_parallel(
        self,
        filtered_edges: Iterable[Tuple[str, str, Dict[str, Any]]],
        time_ranges: Dict[str, Tuple[int, float]],
        processes: Optional[int] = None,
        progress: bool = True,

    ) -> nx.DiGraph:
        ''' build a dependency DiGraph in parallel
        - filtered_edges: iterable of (src, tgt, attr) from self.filter_edges()
        - time_ranges: release_id -> (start_ts, end_ts)
        
        '''
        try:
            from tqdm import tqdm  # lazy import
        except Exception:
            progress = False

        release_nodes_dict = self.get_releases()
        release_nodes_set = set(release_nodes_dict.keys())

        # precomputations (once, in parent)
        rel_to_soft_map = self.rel_to_soft()
        # {soft: [(rel, ts), ...]}
        soft_to_rel = self.soft_to_rel(rel_to_soft_map)
        soft_ts_lists = {s: [ts for _, ts in rels] for s, rels in soft_to_rel.items()}
        release_ts = {rid: self.get_timestamp(self.nodes[rid]) for rid in release_nodes_set}

        # materialize edges 
        fedges = list(filtered_edges)
        total_edges = len(fedges)

        nproc = processes or cpu_count()
        factor = 4
        chunk_size = max(1, total_edges // (nproc * factor)) if total_edges else 1
        
        logger.debug("dep_graph_build_parallel: total_edges=%d nproc=%d chunk_size=%d",
                total_edges, nproc, chunk_size)
        
        # Pool with globals via initializer
        with Pool(
            processes=nproc,
            initializer = _worker_init,
            initargs=(dict(
                nodes=self.nodes,
                is_release=self.is_release,
                get_timestamp=self.get_timestamp,
                time_ranges=time_ranges,
                release_nodes=release_nodes_set,
                release_ts=release_ts,
                soft_to_rel=soft_to_rel,
                soft_ts_lists=soft_ts_lists,
            ),),
        ) as pool:
            iterator = pool.imap_unordered(
                process_edges_chunk,
                self._chunk_generator(fedges, chunk_size),
                chunksize=1,
            )
            if progress and total_edges:
                from tqdm import tqdm
                iterator = tqdm(
                    iterator,
                    total=(total_edges + chunk_size - 1) // chunk_size,
                    desc="Parallel graph build",
                )
            results = list(iterator)

        # combine into a single graph (in-memory, no disk roundtrip)
        combined = nx.DiGraph()
        for edges_out, attrs in results:
            if attrs:
                combined.add_nodes_from((nid, a) for nid, a in attrs.items())
            if edges_out:
                combined.add_edges_from(edges_out)
        
        return combined
    

    # ------------ save/load --------------

    @staticmethod
    def graph_save(new_graph: nx.Graph, graph_path: Path) -> None:
        with graph_path.open('wb') as fw:
            pickle.dump(new_graph, fw, protocol=pickle.HIGHEST_PROTOCOL)

    @staticmethod
    def graph_load(graph_path: Path) -> nx.Graph:
        with graph_path.open('rb') as fr:
            return pickle.load(fr)
        

def load_data(file_path: Path) -> Tuple[Dict[str, Dict[str, Any]],
                                        List[Tuple[str, str, Dict[str, Any]]]]:
    with file_path.open('rb') as f:
        data = pickle.load(f)
    return data['nodes'], data['edges']


if __name__ == "__main__":
    # Configure logging once (safe for multiprocessing on spawn)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s]: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    fh = logging.FileHandler('dep_graph.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(fh)


    nodes_edges_path = Path.cwd().parent.joinpath("data", 'graph_nodes_edges.pkl')
    dep_graph_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    nodes, edges = load_data(nodes_edges_path)
    dg = DepGraph(nodes, edges)
    # Build mappings & ranges
    rel2soft = dg.rel_to_soft()
    soft2rel = dg.soft_to_rel(rel2soft)
    tranges = dg.time_ranges(soft2rel)
    # Filter edges and build combined graph
    filt = dg.filter_edges()
    G = dg.dep_graph_build_parallel(filt, tranges)
    # Save
    dg.graph_save(G, dep_graph_path)