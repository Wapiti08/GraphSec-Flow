"""
Graph-based Baseline Localizers for Temporal Root Cause Localization

Implements classic graph analysis methods adapted for version-level localization:
1. PageRank-based Localization
2. Betweenness-based Localization
3. Temporal PageRank Localization
4. Community-only Localization (Louvain)

These serve as strong baselines for comparison in the paper.

"""

import networkx as nx
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import community as community_louvain
 
 
def _extract_package_version(node_id, node_data) -> Tuple[str, str, str]:
    """
    Extract package and version from Maven coordinate format in release attribute
    
    Maven format: groupId:artifactId:version
    Example: org.apache.tomcat:tomcat-catalina:9.0.1
    
    Returns:
        (package, version, version_string) or (None, None, None)
    """
    # The graph has no independent 'package' attribute, so skip strategy 1
    
    # Strategy 2: Parse Maven coordinates from 'release' attribute
    release = node_data.get('release', '')
    if release:
        # Maven format: groupId:artifactId:version
        parts = release.split(':')
        
        if len(parts) >= 3:
            # Standard Maven coordinate
            group_id = parts[0]
            artifact_id = parts[1]
            version = parts[2]
            
            # Use artifactId as package name (not groupId)
            # Example: org.apache.tomcat:tomcat-catalina:9.0.1 -> package=tomcat-catalina
            package = artifact_id
            
            # However, GT uses simplified names (e.g., 'tomcat'), not the full artifactId
            # So we also try to extract simplified names
            # Example: tomcat-catalina -> tomcat, jenkins-core -> jenkins
            
            # Simplification strategy: take the first part of artifactId (split by '-')
            simple_package = artifact_id.split('-')[0] if '-' in artifact_id else artifact_id
            
            version_string = f"{simple_package}@{version}"
            
            return simple_package, version, version_string
        
        elif len(parts) == 2:
            # Might be package:version format
            package = parts[0]
            version = parts[1]
            return package, version, f"{package}@{version}"
    
    # Strategy 3: Get version number directly from 'version' attribute
    # But without package name, cannot use
    version = node_data.get('version', '')
    if version:
        # No package name, cannot build valid package@version
        pass
    
    # Strategy 4: Node ID format (as last fallback)
    node_str = str(node_id)
    if '@' in node_str:
        try:
            pkg, ver = node_str.rsplit('@', 1)
            return pkg, ver, node_str
        except ValueError:
            pass
    
    return None, None, None
 
 
def _build_package_mapping(graph, verbose=True):
    """
    Build package name mapping table, supporting multiple package name matches
    
    Returns:
        dict: {
            'simple_name': [list of (node_id, full_package, version)],
            'artifact_id': [list of (node_id, full_package, version)],
            ...
        }
    """
    package_index = defaultdict(list)
    
    if verbose:
        print("[INFO] Building package index from Maven coordinates...")
    
    for node_id in graph.nodes():
        node_data = graph.nodes[node_id]
        
        simple_pkg, version, version_string = _extract_package_version(node_id, node_data)
        
        if simple_pkg and version:
            timestamp = node_data.get('timestamp', 0)
            release = node_data.get('release', '')
            
            # Store under simplified package name
            package_index[simple_pkg].append({
                'version': version,
                'node_id': node_id,
                'timestamp': timestamp,
                'version_string': version_string,
                'release': release
            })
            
            # If release is a full Maven coordinate, also store the full artifactId
            if ':' in release:
                parts = release.split(':')
                if len(parts) >= 2:
                    full_artifact_id = parts[1]
                    if full_artifact_id != simple_pkg:
                        package_index[full_artifact_id].append({
                            'version': version,
                            'node_id': node_id,
                            'timestamp': timestamp,
                            'version_string': f"{full_artifact_id}@{version}",
                            'release': release
                        })
    
    # Sort by timestamp
    for pkg in package_index:
        package_index[pkg].sort(key=lambda x: x['timestamp'])
    
    if verbose:
        print(f"[INFO] Found {len(package_index)} unique package identifiers")
        if len(package_index) > 0:
            # Show some examples
            sample_pkgs = list(package_index.keys())[:5]
            print(f"[INFO] Sample packages: {sample_pkgs}")
            
            # Check if common packages like tomcat, jenkins exist
            common_pkgs = ['tomcat', 'jenkins', 'elasticsearch', 'spring']
            found_common = [p for p in common_pkgs if p in package_index]
            if found_common:
                print(f"[INFO] Found common packages: {found_common}")
                for pkg in found_common:
                    print(f"       {pkg}: {len(package_index[pkg])} versions")
    
    return package_index
 
 
class PageRankLocalizer:
    """PageRank-based localization (FIXED for Maven coordinates)"""
 
    def __init__(self, dep_graph):
        self.graph = dep_graph
        self.package_versions = _build_package_mapping(dep_graph, verbose=True)
 
    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Localize using PageRank"""
        
        # Try multiple package name formats
        versions = self.package_versions.get(package, [])
        
        if not versions:
            # Try to find partial match
            matching_keys = [k for k in self.package_versions.keys() if package.lower() in k.lower()]
            if matching_keys:
                print(f"[PageRank] Package '{package}' not found, but found similar: {matching_keys[:3]}")
                versions = self.package_versions.get(matching_keys[0], [])
            else:
                print(f"[PageRank] WARNING: No versions found for package '{package}'")
                available = list(self.package_versions.keys())[:10]
                print(f"[PageRank] Available packages (sample): {available}")
                return {'origin_version': None, 'method': 'pagerank_failed'}
        
        # build version subgraph
        version_nodes = [v['node_id'] for v in versions]
        version_subgraph = self.graph.subgraph(version_nodes).copy()
        
        if version_subgraph.number_of_nodes() == 0:
            origin = versions[0]
            discovered = versions[-1]
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': origin['version_string'],
                'discovered_version': discovered['version_string'],
                'confidence': 0.3,
                'method': 'pagerank_fallback'
            }
        
        # run pagerank
        try:
            pagerank_scores = nx.pagerank(version_subgraph, max_iter=100)
        except:
            pagerank_scores = {n: version_subgraph.degree(n) for n in version_subgraph.nodes()}
        
        # normalize scores
        max_score = max(pagerank_scores.values()) if pagerank_scores else 1.0
        pagerank_scores = {k: v/max_score for k, v in pagerank_scores.items()}
 
        # select earliest version with high score 
        high_score_versions = [
            v for v in versions 
            if pagerank_scores.get(v['node_id'], 0) > 0.5
        ]
 
        if high_score_versions:
            origin = high_score_versions[0]
        else:
            origin = max(versions, key=lambda v: pagerank_scores.get(v['node_id'], 0))
        
        discovered = versions[-1]
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': origin['version_string'],
            'discovered_version': discovered['version_string'],
            'confidence': 0.5,
            'method': 'pagerank',
            'version_sequence': [v['version'] for v in versions]
        }
 
 
class BetweennessLocalizer:
    """Betweenness-based localization (FIXED for Maven coordinates)"""
    
    def __init__(self, dep_graph):
        self.graph = dep_graph
        self.package_versions = _build_package_mapping(dep_graph, verbose=True)
    
    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Localize using Betweenness Centrality"""
        
        versions = self.package_versions.get(package, [])
        
        if not versions:
            matching_keys = [k for k in self.package_versions.keys() if package.lower() in k.lower()]
            if matching_keys:
                print(f"[Betweenness] Package '{package}' not found, using similar: {matching_keys[0]}")
                versions = self.package_versions.get(matching_keys[0], [])
            else:
                print(f"[Betweenness] WARNING: No versions found for package '{package}'")
                return {'origin_version': None, 'method': 'betweenness_failed'}
        
        version_nodes = [v['node_id'] for v in versions]
        version_subgraph = self.graph.subgraph(version_nodes).copy()
        
        if version_subgraph.number_of_nodes() == 0:
            origin = versions[0]
            discovered = versions[-1]
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': origin['version_string'],
                'discovered_version': discovered['version_string'],
                'confidence': 0.3,
                'method': 'betweenness_fallback'
            }
        
        try:
            betweenness_scores = nx.betweenness_centrality(version_subgraph)
        except:
            betweenness_scores = {n: version_subgraph.degree(n) for n in version_subgraph.nodes()}
        
        max_score = max(betweenness_scores.values()) if betweenness_scores else 1.0
        betweenness_scores = {k: v/max_score for k, v in betweenness_scores.items()}
        
        high_score_versions = [
            v for v in versions 
            if betweenness_scores.get(v['node_id'], 0) > 0.4
        ]
        
        if high_score_versions:
            origin = high_score_versions[0]
        else:
            origin = max(versions, key=lambda v: betweenness_scores.get(v['node_id'], 0))
        
        discovered = versions[-1]
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': origin['version_string'],
            'discovered_version': discovered['version_string'],
            'confidence': 0.5,
            'method': 'betweenness',
            'version_sequence': [v['version'] for v in versions]
        }
 
 
class TemporalPageRankLocalizer:
    """Temporal PageRank-based localization (FIXED for Maven coordinates)"""
    
    def __init__(self, dep_graph):
        self.graph = dep_graph
        self.package_versions = _build_package_mapping(dep_graph, verbose=True)
    
    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Localize using Temporal PageRank"""
        
        versions = self.package_versions.get(package, [])
        
        if not versions:
            matching_keys = [k for k in self.package_versions.keys() if package.lower() in k.lower()]
            if matching_keys:
                print(f"[TemporalPageRank] Package '{package}' not found, using similar: {matching_keys[0]}")
                versions = self.package_versions.get(matching_keys[0], [])
            else:
                print(f"[TemporalPageRank] WARNING: No versions found for package '{package}'")
                return {'origin_version': None, 'method': 'temporal_pagerank_failed'}
        
        version_nodes = [v['node_id'] for v in versions]
        version_subgraph = self.graph.subgraph(version_nodes).copy()
        
        if version_subgraph.number_of_nodes() == 0:
            origin = versions[0]
            discovered = versions[-1]
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': origin['version_string'],
                'discovered_version': discovered['version_string'],
                'confidence': 0.3,
                'method': 'temporal_pagerank_fallback'
            }
        
        timestamps = {v['node_id']: v['timestamp'] for v in versions}
        
        min_ts = min(timestamps.values())
        max_ts = max(timestamps.values())
        time_span = max(1, max_ts - min_ts)
        
        for u, v in version_subgraph.edges():
            ts_u = timestamps.get(u, max_ts)
            ts_v = timestamps.get(v, max_ts)
            avg_ts = (ts_u + ts_v) / 2
            
            temporal_weight = 1.0 - (avg_ts - min_ts) / time_span
            version_subgraph[u][v]['weight'] = max(0.1, temporal_weight)
        
        try:
            pagerank_scores = nx.pagerank(
                version_subgraph, 
                max_iter=100,
                weight='weight'
            )
        except:
            pagerank_scores = {n: version_subgraph.degree(n) for n in version_subgraph.nodes()}
        
        max_score = max(pagerank_scores.values()) if pagerank_scores else 1.0
        pagerank_scores = {k: v/max_score for k, v in pagerank_scores.items()}
        
        high_score_versions = [
            v for v in versions 
            if pagerank_scores.get(v['node_id'], 0) > 0.5
        ]
        
        if high_score_versions:
            origin = high_score_versions[0]
        else:
            origin = max(versions, key=lambda v: pagerank_scores.get(v['node_id'], 0))
        
        discovered = versions[-1]
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': origin['version_string'],
            'discovered_version': discovered['version_string'],
            'confidence': 0.6,
            'method': 'temporal_pagerank',
            'version_sequence': [v['version'] for v in versions]
        }
 
 
class CommunityOnlyLocalizer:
    """Community detection only (FIXED for Maven coordinates)"""
    
    def __init__(self, dep_graph):
        self.graph = dep_graph
        self.package_versions = _build_package_mapping(dep_graph, verbose=True)
    
    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Localize using Community Detection only"""
        
        versions = self.package_versions.get(package, [])
        
        if not versions:
            matching_keys = [k for k in self.package_versions.keys() if package.lower() in k.lower()]
            if matching_keys:
                print(f"[CommunityOnly] Package '{package}' not found, using similar: {matching_keys[0]}")
                versions = self.package_versions.get(matching_keys[0], [])
            else:
                print(f"[CommunityOnly] WARNING: No versions found for package '{package}'")
                return {'origin_version': None, 'method': 'community_failed'}
        
        version_nodes = [v['node_id'] for v in versions]
        version_subgraph = self.graph.subgraph(version_nodes).copy()
        
        if version_subgraph.number_of_nodes() == 0:
            origin = versions[0]
            discovered = versions[-1]
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': origin['version_string'],
                'discovered_version': discovered['version_string'],
                'confidence': 0.3,
                'method': 'community_fallback'
            }
        
        undirected_graph = version_subgraph.to_undirected()
        
        try:
            partition = community_louvain.best_partition(undirected_graph)
        except:
            partition = {n: 0 for n in undirected_graph.nodes()}
        
        community_sizes = defaultdict(int)
        for node, comm in partition.items():
            community_sizes[comm] += 1
        
        largest_community = max(community_sizes, key=community_sizes.get)
        
        community_versions = [
            v for v in versions 
            if partition.get(v['node_id']) == largest_community
        ]
        
        if community_versions:
            origin = community_versions[0]
        else:
            origin = versions[0]
        
        discovered = versions[-1]
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': origin['version_string'],
            'discovered_version': discovered['version_string'],
            'confidence': 0.6,
            'method': 'community_louvain',
            'version_sequence': [v['version'] for v in versions]
        }
 