'''
check the origin of the cve, check whether it is original or propagated or forked

core logic:
    - input: (node_id, cve_id) --- the node has cve attached
    - output: the origin of CVE + root node + propagation path

solution for technical lag:
    1. not only search direct neighbors of targeted node
    2. search all version of same software
    3. find the earliest version

'''

import networkx as nx
from typing import Dict, List, Set, Tuple, Optional, Literal
from collections import deque, defaultdict
from dataclasses import dataclass
import re

@dataclass
class CVEOriginResult:
    ''' CVE origin analysis result
    
    '''
    cve_id: str
    target_node: str
    origin_type: Literal["original", "propagated", "forked", "unknown"]
    root_node: Optional[str]  
    propagation_path: List[str] 
    confidence: float  
    evidence: Dict 

class CVEOriginAnalyzer:
    """
    self-contained CVE origin analysis module
    
    research questions, check whether the CVE-X is
        - original vulnerability
        - propagated vulnerability
        - forked vulnerability

    overcome potential missing from technical lag
    
    """

    def __init__(self, dep_graph, timestamps: Dict[str, float], edge_direction: Literal["auto", "late_to_early"] = "auto"): 
        '''
        Args:
            dep_graph: Networkx dependency graph (A -> B means A depends on B)
            timestamps: {node_id, timestamp}
        '''
        self.G = dep_graph
        self.timestamps = timestamps

        if edge_direction == "auto":
            self.edge_direction = self._detect_edge_direction()
        else:
            self.edge_direction = edge_direction

        # build version index
        self._build_version_index()
        
        print(f"[Enhanced] Edge direction: {self.edge_direction}")
        print(f"[Enhanced] Total software families: {len(self.software_to_versions)}")

    def _detect_edge_direction(self) -> str:
        """automatically detect direction"""
        if not self.G.is_directed():
            return "undirected"
        
        sample_edges = list(self.G.edges())[:100]
        late_to_early = sum(
            1 for u, v in sample_edges
            if self.timestamps.get(u, 0) >= self.timestamps.get(v, 0)
        )
        
        return "late_to_early" if late_to_early > 50 else "early_to_late" 

    def _build_version_index(self):
        """
        construct software and version index for all nodes in the graph,
        
        parse node_id into (software_name, version)
        e.g.,：'numpy:1.19.0' -> software='numpy', version='1.19.0'
        """
        self.software_to_versions = defaultdict(list)  # software -> [(node_id, timestamp), ...]
        self.node_to_software = {}  # node_id -> software_name
        
        for node in self.G.nodes():
            attrs = self.G.nodes[node]  

            # extract release information
            release = attrs.get("release", "")
            if not release:
                continue

            software, version = self._parse_release(release)
            
            if software:
                ts = self.timestamps.get(node, 0)
                self.software_to_versions[software].append((node, ts))
                self.node_to_software[node] = software
        
        # ranking according to timestamp
        for software in self.software_to_versions:
            self.software_to_versions[software].sort(key=lambda x: x[1])        

    def _parse_release(self, release_str: str) -> Tuple[Optional[str], Optional[str]]:
        ''' parse release string

        supported formats:
            - 'numpy:1.19.0' -> ('numpy', '1.19.0')
            - 'org.springframework:spring-core:5.3.0' -> ('org.springframework:spring-core', '5.3.0')
        
        '''
        release_str = str(release_str)

        for sep in [':', '@', '#']:
            if sep in release_str:
                parts = release_str.rsplit(sep, 1)
                if len(parts) == 2:
                    software, version = parts
                    
                    if self._looks_like_version(version):
                        return software, version
        
        return None, None

    def _looks_like_version(self, s: str) -> bool:
        """check whether string like version number"""
        return bool(re.search(r'\d+\.\d+', s))

    def _get_upstream_neighbors(self, node: str) -> List[str]:
        """ get upstream neighbors (consider edge direction)         
        
        """
        if self.edge_direction == "late_to_early":
            return list(self.G.successors(node))
        elif self.edge_direction == "early_to_late":
            return list(self.G.predecessors(node))
        else:
            neighbors = list(self.G.neighbors(node))
            ts_current = self.timestamps.get(node, float('inf'))
            return [n for n in neighbors 
                    if self.timestamps.get(n, float('inf')) < ts_current]

    def find_all_nodes_with_cve(self, cve_id: str) -> Set[str]:
        """ 
        find all nodes with the given CVE attached

        """
        nodes_with_cve = set()
        for node, attrs in self.G.nodes(data=True):
            cve_list = attrs.get("cve_list", [])

            for cve_entry in cve_list:
                if isinstance(cve_entry, dict):
                    cve_name = cve_entry.get('name', '')
                else:
                    cve_name = str(cve_entry)
            
                if self._normalize_cve(cve_name) == self._normalize_cve(cve_id):
                    nodes_with_cve.add(node)
                    break
        
        return nodes_with_cve
    
    def _normalize_cve(self, cve_str: str) -> str:
        cve_str = str(cve_str).upper().strip()
        if not cve_str.startswith('CVE-'):
            cve_str = f'CVE-{cve_str}'
        return cve_str
    
    def find_upstream_with_cve(
        self, 
        target_node: str, 
        cve_id: str,
        max_depth: int = 10,
        include_sibling_versions: bool = True
    ) -> List[Tuple[str, List[str], int]]:
        """
        Enhanced Upstream Search

        Args:
            target_node: Target node
            cve_id: CVE ID
            max_depth: Maximum search depth
            include_sibling_versions: Whether to include other versions of the same software

        Returns:
            [(upstream_node, path, depth), ...]

        """
        # all nodes with this cve
        nodes_with_cve = self.find_all_nodes_with_cve(cve_id)

        # standard graph search
        graph_upstream = self._graph_based_search(
            target_node, nodes_with_cve, max_depth
        )

        # if including sibling versions, also search other versions of the same software
        if include_sibling_versions:
            version_upstream = self._version_based_search(
                target_node, nodes_with_cve
            )
            
            # aggregate results
            all_upstream = graph_upstream + version_upstream

            # deduplicate and sort by depth
            seen = {}
            for node, path, depth in all_upstream:
                if node not in seen or depth < seen[node][1]:
                    seen[node] = (path, depth)
            
            result = [(node, path, depth) for node, (path, depth) in seen.items()]
        else:
            result = graph_upstream

        # ranking by timestamp
        result.sort(key=lambda x: self.timestamps.get(x[0], float('inf')))

        return result
        
    def _graph_based_search(
        self,
        target_node: str,
        nodes_with_cve: Set[str],
        max_depth: int
    ) -> List[Tuple[str, List[str], int]]:
        """
        graph search based on standard BFS
        """
        visited = {target_node}
        queue = deque([(target_node, [target_node], 0)])
        upstream_with_cve = []
        
        while queue:
            current, path, depth = queue.popleft()
            
            if depth >= max_depth:
                continue
            
            for upstream in self._get_upstream_neighbors(current):
                if upstream in visited:
                    continue
                
                visited.add(upstream)
                new_path = path + [upstream]
                
                if upstream in nodes_with_cve:
                    upstream_with_cve.append((upstream, new_path, depth + 1))
                
                queue.append((upstream, new_path, depth + 1))
        
        return upstream_with_cve
    
    def _version_based_search(
         self,
        target_node: str,
        nodes_with_cve: Set[str]
    ) -> List[Tuple[str, List[str], int]]:
        """
        Version-based search

        For each upstream software found in the graph, check all versions of that software

        Find other versions that also contain the CVE.

        """
        version_upstream = []
        
        # get the upstream neighbors of the target node
        direct_upstream = self._get_upstream_neighbors(target_node)

        for upstream_node in direct_upstream:
            software = self.node_to_software.get(upstream_node)
            
            if not software:
                continue

            # get all versions
            all_versions = self.software_to_versions.get(software, [])

            for other_node, other_ts in all_versions:
                if other_node in nodes_with_cve and other_node != upstream_node:
                    # path：target -> upstream_node -> other_node 
                    path = [target_node, upstream_node, other_node]
                    depth = 2 
                    
                    version_upstream.append((other_node, path, depth))
        
        return version_upstream

    def analyze_origin(
        self,
        target_node: str,
        cve_id: str,
        enable_version_search: bool = True  
    ) -> CVEOriginResult:
        """
        analyse CVE origin

        Args:
            target_node: Target node

            cve_id: CVE ID

            enable_version_search: Whether to enable version search

        """
        target_timestamp = self.timestamps.get(target_node, float('inf'))

        upstream_with_cve = self.find_upstream_with_cve(
            target_node,
            cve_id,
            include_sibling_versions=enable_version_search
        )
        # find earliest upstream with CVE
        earlier_upstream = [
            (node, path, depth)
            for node, path, depth in upstream_with_cve
            if self.timestamps.get(node, float('inf')) < target_timestamp
        ]

        if earlier_upstream:
            # progapation type
            earliest_node, path, depth = earlier_upstream[0]
            time_delta = target_timestamp - self.timestamps.get(earliest_node, 0)

            confidence = self._calculate_propagation_confidence(
                path_length = depth,
                time_delta = time_delta,
                num_upstream = len(earlier_upstream)
            )

            # check whether can use version search to find earlier version with CVE
            found_via_version_search = any(
                node for node, _, d in earlier_upstream
                if d == 2
            )

            return CVEOriginResult(
                cve_id=cve_id,
                    target_node=target_node,
                    origin_type="propagated",
                    root_node=earliest_node,
                    propagation_path=path,
                    confidence=confidence,
                    evidence={
                        'earliest_upstream': earliest_node,
                        'earliest_timestamp': self.timestamps.get(earliest_node),
                        'target_timestamp': target_timestamp,
                        'time_delta_days': time_delta / (24 * 3600) if time_delta != float('inf') else None,
                        'propagation_depth': depth,
                        'all_upstream_count': len(upstream_with_cve),
                        'earlier_upstream_count': len(earlier_upstream),
                        'found_via_version_search': found_via_version_search,
                        'version_search_enabled': enable_version_search
                    }
                )
        else:
            confidence = self._calculate_original_confidence(
                has_any_upstream = len(upstream_with_cve) > 0,
            )
            return CVEOriginResult(
                cve_id=cve_id,
                target_node=target_node,
                origin_type="original",
                root_node=target_node,
                propagation_path=[target_node],
                confidence=confidence,
                evidence={
                    'reason': 'no_earlier_upstream',
                    'total_nodes_with_cve': len(self.find_all_nodes_with_cve(cve_id)),
                    'upstream_with_cve': len(upstream_with_cve),
                    'timestamp': target_timestamp,
                    'version_search_enabled': enable_version_search
                }
            )


    def _calculate_propagation_confidence(
        self, path_length: int, time_delta: float, num_upstream: int
        ) -> float:
        ''' calculate propagation confidence
        
        '''
        path_score = max(0, 1.0 - (path_length - 1) * 0.15)
        
        time_delta_days = time_delta / (24 * 3600) if time_delta != float('inf') else 0
        if 1 <= time_delta_days <= 365:
            time_score = 1.0
        elif time_delta_days > 365:
            time_score = 0.8
        else:
            time_score = 0.5
        
        upstream_score = min(1.0, num_upstream / 3)
        
        return max(0.0, min(1.0, 
            0.5 * path_score + 0.3 * time_score + 0.2 * upstream_score
        ))

    def _calculate_original_confidence(self, has_any_upstream: bool) -> float:
        ''' calculate original confidence
        
        '''
        return 0.9 if not has_any_upstream else 0.7

def test_enhanced_analyzer():
    """Test analyzer"""
    import pickle
    from pathlib import Path
    
    data_dir = Path.cwd().joinpath("data")
    
    with open(data_dir / "dep_graph_cve.pkl", "rb") as f:
        G = pickle.load(f)
    
    timestamps = {n: float(G.nodes[n]["timestamp"]) 
                  for n in G.nodes() 
                  if "timestamp" in G.nodes[n]}
    
    print("="*70)
    print(" Origin Analyzer Test ".center(70, "="))
    print("="*70)
    
    # Create analyzer
    analyzer = CVEOriginAnalyzer(G, timestamps)
    
    # Find test sample
    for node in G.nodes():
        cve_list = G.nodes[node].get('cve_list', [])
        if cve_list:
            test_node = node
            if isinstance(cve_list[0], dict):
                test_cve = cve_list[0].get('name')
            else:
                test_cve = str(cve_list[0])
            
            print(f"\nTest Sample:")
            print(f"  Node: {test_node}")
            print(f"  CVE: {test_cve}")
            
            # Comparison: version search disabled
            print("\n--- Version Search Disabled ---")
            result1 = analyzer.analyze_origin(test_node, test_cve, enable_version_search=False)
            print(f"  Origin: {result1.origin_type}")
            print(f"  Root Node: {result1.root_node}")
            print(f"  Path Length: {len(result1.propagation_path)}")
            
            # Version search enabled
            print("\n--- Version Search Enabled ---")
            result2 = analyzer.analyze_origin(test_node, test_cve, enable_version_search=True)
            print(f"  Origin: {result2.origin_type}")
            print(f"  Root Node: {result2.root_node}")
            print(f"  Path Length: {len(result2.propagation_path)}")
            print(f"  Found via version search: {result2.evidence.get('found_via_version_search')}")
            
            if result1.root_node != result2.root_node:
                print("\n⚠️ Note: Version search found a different root node!")
                print(f"  Disabled: {result1.root_node} (ts={timestamps.get(result1.root_node)})")
                print(f"  Enabled: {result2.root_node} (ts={timestamps.get(result2.root_node)})")
            
            break

if __name__ == "__main__":
    # test_enhanced_analyzer()
    import pickle
    from pathlib import Path
    data_dir = Path.cwd().joinpath("data")

    with open(data_dir / "dep_graph_cve.pkl", "rb") as f:
        G = pickle.load(f)

    timestamps = {n: float(G.nodes[n]["timestamp"]) 
                for n in G.nodes() 
                if "timestamp" in G.nodes[n]}

    analyzer = CVEOriginAnalyzer(G, timestamps)

    print("\n" + "="*70)
    print(" Batch Analysis - All CVEs ".center(70, "="))
    print("="*70)

    # Batch analysis
    all_origins = {}
    count = 0

    for node in G.nodes():
        cve_list = G.nodes[node].get('cve_list', [])
        
        for cve_entry in cve_list:
            if isinstance(cve_entry, dict):
                cve_id = cve_entry.get('name', '')
            else:
                cve_id = str(cve_entry)
            
            if not cve_id:
                continue
            
            try:
                result = analyzer.analyze_origin(
                    node, cve_id,
                    enable_version_search=True  # Enable version search
                )
                all_origins[(node, cve_id)] = result
                
                count += 1
                if count % 1000 == 0:
                    print(f"[Progress] Analyzed {count} CVE instances...")
            
            except Exception as e:
                print(f"[WARN] Failed: {node}/{cve_id}: {e}")

    # Statistics
    total = len(all_origins)
    original = sum(1 for r in all_origins.values() if r.origin_type == 'original')
    propagated = sum(1 for r in all_origins.values() if r.origin_type == 'propagated')
    version_improved = sum(
        1 for r in all_origins.values() 
        if r.origin_type == 'propagated' 
        and r.evidence.get('found_via_version_search')
    )

    print("\n" + "="*70)
    print(" Final Statistics ".center(70, "="))
    print("="*70)
    print(f"\nTotal: {total}")
    print(f"  Original CVEs: {original} ({original/total:.1%})")
    print(f"  Propagated CVEs: {propagated} ({propagated/total:.1%})")
    print(f"\nVersion search improved: {version_improved}/{propagated} ({version_improved/propagated:.1%})")

    # Save results
    with open(data_dir / "cve_origins.pkl", "wb") as f:
        pickle.dump({
            'all_origins': all_origins,
            'stats': {
                'total': total,
                'original': original,
                'propagated': propagated,
                'version_improved': version_improved
            }
        }, f)

    print(f"\n✓ Results saved to {data_dir / 'cve_origins.pkl'}")
    print("="*70)