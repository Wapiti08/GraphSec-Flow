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
from typing import Dict, List, Optional
import community as community_louvain  # python-louvain package

class PageRankLocalizer:
    """
    Baseline: PageRank-based localization
    
    Strategy:
    - Run PageRank on version subgraph
    - Select earliest version with high PageRank score
    - Assumes important versions are central in dependency graph
    """

    def __init__(self, dep_graph):
        self.graph = dep_graph
        self._build_package_index()

    def _build_package_index(self):
        """Build package → versions index"""

        self.package_versions = defaultdict(list)

        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            node_str = str(node_id)

            if '@' in node_str:
                package, version = node_str.rsplit('@', 1)
                timestamp = node_data.get('timestamp', 0)
                
                self.package_versions[package].append({
                    'version': version,
                    'node_id': node_id,
                    'timestamp': timestamp
                })
        
        for package in self.package_versions:
            self.package_versions[package].sort(key=lambda x: x['timestamp'])

    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Localize using PageRank"""

        versions = self.package_versions.get(package, [])

        if not versions:
            return {'origin_version': None, 'method': 'pagerank_failed'}
        
        # build version subgraph
        version_nodes = [v['node_id'] for v in versions]
        version_subgraph = self.graph.subgraph(version_nodes).copy()
        
        if version_subgraph.number_of_nodes() == 0:
            # Fallback: return earliest
            origin = versions[0]
            discovered = versions[-1]
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': f"{package}@{origin['version']}",
                'discovered_version': f"{package}@{discovered['version']}",
                'confidence': 0.3,
                'method': 'pagerank_fallback'
            }
        
        # run pagerank
        try:
            pagerank_scores = nx.pagerank(version_subgraph, max_iter=100)
        except:
            # If PageRank fails, use degree centrality
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
            origin = high_score_versions[0]  # Earliest high-score version
        else:
            # If no high scores, just pick highest
            origin = max(versions, key=lambda v: pagerank_scores.get(v['node_id'], 0))
        
        discovered = versions[-1]
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': f"{package}@{origin['version']}",
            'discovered_version': f"{package}@{discovered['version']}",
            'confidence': 0.5,
            'method': 'pagerank',
            'version_sequence': [v['version'] for v in versions]
        }

class BetweennessLocalizer:
    """
    Baseline: Betweenness Centrality-based localization
    
    Strategy:
    - Compute betweenness centrality for versions
    - Select earliest version with high betweenness
    - Assumes origin versions are on critical paths
    """
    def __init__(self, dep_graph):
        self.graph = dep_graph
        self._build_package_index()
    
    def _build_package_index(self):
        """Build package → versions index"""
        self.package_versions = defaultdict(list)
        
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            node_str = str(node_id)
            
            if '@' in node_str:
                package, version = node_str.rsplit('@', 1)
                timestamp = node_data.get('timestamp', 0)
                
                self.package_versions[package].append({
                    'version': version,
                    'node_id': node_id,
                    'timestamp': timestamp
                })
        
        for package in self.package_versions:
            self.package_versions[package].sort(key=lambda x: x['timestamp'])
    
    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Localize using Betweenness Centrality"""
        
        versions = self.package_versions.get(package, [])
        
        if not versions:
            return {'origin_version': None, 'method': 'betweenness_failed'}
        
        # Build version subgraph
        version_nodes = [v['node_id'] for v in versions]
        version_subgraph = self.graph.subgraph(version_nodes).copy()
        
        if version_subgraph.number_of_nodes() == 0:
            origin = versions[0]
            discovered = versions[-1]
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': f"{package}@{origin['version']}",
                'discovered_version': f"{package}@{discovered['version']}",
                'confidence': 0.3,
                'method': 'betweenness_fallback'
            }
        
        # Compute Betweenness Centrality
        try:
            betweenness_scores = nx.betweenness_centrality(version_subgraph)
        except:
            # Fallback: use degree
            betweenness_scores = {n: version_subgraph.degree(n) for n in version_subgraph.nodes()}
        
        # Normalize
        max_score = max(betweenness_scores.values()) if betweenness_scores else 1.0
        betweenness_scores = {k: v/max_score for k, v in betweenness_scores.items()}
        
        # Select earliest high-betweenness version
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
            'origin_version': f"{package}@{origin['version']}",
            'discovered_version': f"{package}@{discovered['version']}",
            'confidence': 0.5,
            'method': 'betweenness',
            'version_sequence': [v['version'] for v in versions]
        }


class TemporalPageRankLocalizer:
    """
    Baseline: Temporal PageRank-based localization
    
    Strategy:
    - Run PageRank with temporal edge weights
    - Earlier edges have higher weights
    - Select earliest high-score version
    """
    
    def __init__(self, dep_graph):
        self.graph = dep_graph
        self._build_package_index()
    
    def _build_package_index(self):
        """Build package → versions index"""
        self.package_versions = defaultdict(list)
        
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            node_str = str(node_id)
            
            if '@' in node_str:
                package, version = node_str.rsplit('@', 1)
                timestamp = node_data.get('timestamp', 0)
                
                self.package_versions[package].append({
                    'version': version,
                    'node_id': node_id,
                    'timestamp': timestamp
                })
        
        for package in self.package_versions:
            self.package_versions[package].sort(key=lambda x: x['timestamp'])
    
    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Localize using Temporal PageRank"""
        
        versions = self.package_versions.get(package, [])
        
        if not versions:
            return {'origin_version': None, 'method': 'temporal_pagerank_failed'}
        
        # Build version subgraph
        version_nodes = [v['node_id'] for v in versions]
        version_subgraph = self.graph.subgraph(version_nodes).copy()
        
        if version_subgraph.number_of_nodes() == 0:
            origin = versions[0]
            discovered = versions[-1]
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': f"{package}@{origin['version']}",
                'discovered_version': f"{package}@{discovered['version']}",
                'confidence': 0.3,
                'method': 'temporal_pagerank_fallback'
            }
        
        # Add temporal weights to edges
        # Earlier connections have higher weights
        timestamps = {v['node_id']: v['timestamp'] for v in versions}
        
        min_ts = min(timestamps.values())
        max_ts = max(timestamps.values())
        time_span = max(1, max_ts - min_ts)
        
        for u, v in version_subgraph.edges():
            # Weight based on earliness
            ts_u = timestamps.get(u, max_ts)
            ts_v = timestamps.get(v, max_ts)
            avg_ts = (ts_u + ts_v) / 2
            
            # Earlier edges get higher weights
            temporal_weight = 1.0 - (avg_ts - min_ts) / time_span
            version_subgraph[u][v]['weight'] = max(0.1, temporal_weight)
        
        # Run weighted PageRank
        try:
            pagerank_scores = nx.pagerank(
                version_subgraph, 
                max_iter=100,
                weight='weight'
            )
        except:
            pagerank_scores = {n: version_subgraph.degree(n) for n in version_subgraph.nodes()}
        
        # Normalize
        max_score = max(pagerank_scores.values()) if pagerank_scores else 1.0
        pagerank_scores = {k: v/max_score for k, v in pagerank_scores.items()}
        
        # Select earliest high-score version
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
            'origin_version': f"{package}@{origin['version']}",
            'discovered_version': f"{package}@{discovered['version']}",
            'confidence': 0.6,
            'method': 'temporal_pagerank',
            'version_sequence': [v['version'] for v in versions]
        }


class CommunityOnlyLocalizer:
    """
    Baseline: Community detection only (Louvain)
    
    Strategy:
    - Run Louvain community detection on version graph
    - Find largest community
    - Select earliest version in that community
    """
    
    def __init__(self, dep_graph):
        self.graph = dep_graph
        self._build_package_index()
    
    def _build_package_index(self):
        """Build package → versions index"""
        self.package_versions = defaultdict(list)
        
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            node_str = str(node_id)
            
            if '@' in node_str:
                package, version = node_str.rsplit('@', 1)
                timestamp = node_data.get('timestamp', 0)
                
                self.package_versions[package].append({
                    'version': version,
                    'node_id': node_id,
                    'timestamp': timestamp
                })
        
        for package in self.package_versions:
            self.package_versions[package].sort(key=lambda x: x['timestamp'])
    
    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Localize using Community Detection only"""
        
        versions = self.package_versions.get(package, [])
        
        if not versions:
            return {'origin_version': None, 'method': 'community_failed'}
        
        # Build version subgraph
        version_nodes = [v['node_id'] for v in versions]
        version_subgraph = self.graph.subgraph(version_nodes).copy()
        
        if version_subgraph.number_of_nodes() == 0:
            origin = versions[0]
            discovered = versions[-1]
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': f"{package}@{origin['version']}",
                'discovered_version': f"{package}@{discovered['version']}",
                'confidence': 0.3,
                'method': 'community_fallback'
            }
        
        # Convert to undirected for community detection
        undirected_graph = version_subgraph.to_undirected()
        
        # Run Louvain community detection
        try:
            partition = community_louvain.best_partition(undirected_graph)
        except:
            # Fallback: all in one community
            partition = {n: 0 for n in undirected_graph.nodes()}
        
        # Find largest community
        community_sizes = defaultdict(int)
        for node, comm in partition.items():
            community_sizes[comm] += 1
        
        largest_community = max(community_sizes, key=community_sizes.get)
        
        # Get versions in largest community
        community_versions = [
            v for v in versions 
            if partition.get(v['node_id']) == largest_community
        ]
        
        if community_versions:
            origin = community_versions[0]  # Earliest in community
        else:
            origin = versions[0]
        
        discovered = versions[-1]
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': f"{package}@{origin['version']}",
            'discovered_version': f"{package}@{discovered['version']}",
            'confidence': 0.6,
            'method': 'community_louvain',
            'version_sequence': [v['version'] for v in versions]
        }