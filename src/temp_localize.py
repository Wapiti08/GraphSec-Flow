"""
Temporal Root Cause Localization Algorithm

Integrates with existing RootCauseAnalyzer from root_ana.py
to find the origin version where a vulnerability was introduced.

Usage:
    from temporal_localization import TemporalLocalizer
    
    localizer = TemporalLocalizer(
        dep_graph=G,
        cve_embedder=CVEVector(),
        node_cve_scores=node_scores,
        timestamps=timestamps
    )
    
    result = localizer.localize_origin(
        cve_id='CVE-2023-1234',
        cve_description='...',
        discovered_version='express@3.0.5'
    )
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from typing import Dict, List, Optional, Tuple
import networkx as nx
import numpy as np
from collections import defaultdict
import time

# Import existing components
from search.vamana import VamanaOnCVE, VamanaSearch
from cve.cvevector import CVEVector
from cent.temp_cent import TempCentricity
from com.commdet import TemporalCommDetector

class TemporalLocalizer:
    """
    Localize the origin version of a vulnerability using temporal analysis
    
    Combines:
    - Vector search (Vamana) for CVE similarity
    - Temporal community detection for version clustering
    - Time-aware scoring for origin selection
    """

    def __init__(
        self,
        dep_graph: nx.DiGraph,
        cve_embedder: CVEVector,
        node_cve_scores: Dict,
        timestamps: Dict,
        node_texts: Optional[Dict] = None,
        # Ablation flags
        use_vector_search: bool = True,
        use_temporal: bool = True,
        use_community: bool = True
    ):
        """
        Args:
            dep_graph: Dependency graph (NetworkX)
            cve_embedder: CVE description embedder
            node_cve_scores: {node_id: cve_score}
            timestamps: {node_id: timestamp}
            node_texts: {node_id: [cve_texts]} for vector search
            use_vector_search: Enable/disable Vamana vector search (ablation)
            use_temporal: Enable/disable temporal analysis (ablation)
            use_community: Enable/disable community detection (ablation)
        """
        self.graph = dep_graph
        self.embedder = cve_embedder
        self.node_cve_scores = node_cve_scores
        self.timestamps = timestamps
        self.node_texts = node_texts or {}

        # Ablation flags
        self.use_vector_search = use_vector_search
        self.use_temporal = use_temporal
        self.use_community = use_community

        # build package index
        self._build_package_index()

        # Initialize Vamana search (if node_texts provided)
        if self.node_texts:
            ann = VamanaSearch()
            self.vamana = VamanaOnCVE(dep_graph, node_texts, cve_embedder, ann)
            self.vamana.build()
        else:
            self.vamana = None
        
        # Initialize temporal detector
        centrality = TempCentricity(dep_graph, "global")
        self._detector = TemporalCommDetector(
            dep_graph=dep_graph,
            timestamps=timestamps,
            cve_scores=node_cve_scores,
            centrality_provider=centrality
        )

    def _build_package_index(self):
        """Build index: package -> [(version, node_id, timestamp)]"""
        self.package_versions = defaultdict(list)
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            release = node_data.get('release', '')
            if not release:
                continue
            parts = release.split(':')
            if len(parts) >= 3:
                artifact_id = parts[1]
                version = parts[2]
            elif len(parts) == 2:
                artifact_id = parts[0]
                version = parts[1]
            else:
                continue
            timestamp = node_data.get('timestamp', 0)
            self.package_versions[artifact_id].append({
                'version': version,
                'node_id': node_id,
                'timestamp': timestamp
            })
        for package in self.package_versions:
            self.package_versions[package].sort(key=lambda x: x['timestamp'])
    
    def _parse_node(self, node_id, node_data):
        """Extract package and version from node"""
        release = node_data.get('release', '')
        if release:
            parts = release.split(':')
            if len(parts) >= 3:
                artifact_id = parts[1]
                version = parts[2]
                return artifact_id, version
            elif len(parts) == 2:
                return parts[0], parts[1]
        # Fallback: try node_id
        node_str = str(node_id)
        if '@' in node_str:
            pkg, ver = node_str.rsplit('@', 1)
            return pkg, ver
        return None, None
    # ========================================================================
    # Core Localization Algorithm
    # ========================================================================

    def localize_origin(
        self,
        cve_id: str,
        cve_description: str,
        discovered_version: Optional[str] = None,
        k: int = 15,
        use_vector_search: Optional[bool] = None  # Override instance flag if needed
    )-> Dict:
        """
        Main algorithm: localize the origin version of a CVE

        Args:
            cve_id: CVE identifier
            cve_description: CVE description text
            discovered_version: Version where CVE was discovered (package@version)
            k: Number of nearest neighbors for vector search
            use_vector_search: Whether to use Vamana search

        Returns:
            {
                'cve_id': str,
                'package': str,
                'origin_version': str,
                'discovered_version': str,
                'confidence': float,
                'method': str,
                'version_sequence': [str],
                'ranked_candidates': [str],
                'time_ms': int
            }
        """
        start_time = time.perf_counter()

        # Use instance flag unless overridden
        use_vector = use_vector_search if use_vector_search is not None else self.use_vector_search

        # Extract package from discovered_version
        if discovered_version and '@' in discovered_version:
            package = discovered_version.split('@')[0]
        else:
            # Try to infer package from graph
            package = self._infer_package_from_cve(cve_id)

        if not package:
            return self._failed_result(cve_id, 'No package found')

        # Get all versions of this package
        versions_info = self.package_versions.get(package, [])

        if not versions_info:
            return self._failed_result(cve_id, f'No versions found for {package}')
        
        # Strategy: Combine vector search + temporal analysis
        if use_vector and self.vamana:
            result = self._localize_with_vector_search(
                cve_id, cve_description, package, versions_info, k
            )
        else:
            result = self._localize_temporal_only(
                cve_id, package, versions_info, discovered_version
            )
        
        # Add timing
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        result['time_ms'] = elapsed_ms
        
        return result
    
    def _localize_with_vector_search(
        self,
        cve_id: str,
        cve_description: str,
        package: str,
        versions_info: List[Dict],
        k: int
    ) -> Dict:
        """Localize using vector search + temporal analysis"""
        # 1. Embed CVE description
        query_vector = self.embedder.encode(cve_description)
        
        # 2. Search for similar CVE nodes
        search_result = self.vamana.search(
            query_vector,
            k=k,
            return_explanations=True
        )

        if isinstance(search_result, tuple):
            neighbors, explanations = search_result
        else:
            neighbors = search_result
            explanations = None

        # Filter neighbors to only include this package
        package_node_ids = {v['node_id'] for v in versions_info}
        package_neighbors = [n for n in neighbors if n in package_node_ids]
        
        # If community detection is disabled, consider more candidates
        if not self.use_community:
            # Include more neighbors from related packages (broader search)
            # This simulates not using community-based filtering
            # For version localization, we still filter by package but consider
            # all versions (not just clustered ones)
            pass  # Already using all package versions
        
        if not package_neighbors:
            # Fallback to temporal-only
            return self._localize_temporal_only(cve_id, package, versions_info, None)
        
        # 3. Rank candidates
        # If temporal is disabled, use only similarity ranking
        if not self.use_temporal:
            # Rank purely by similarity (no time consideration)
            ranked_candidates = self._rank_candidates_by_similarity(
                package_neighbors,
                explanations
            )
        else:
            # Rank by: time (early) + CVE similarity
            ranked_candidates = self._rank_candidates_temporal(
                package_neighbors,
                versions_info,
                explanations
            )

        # 4. Select origin (earliest with high score)
        origin_node = ranked_candidates[0] if ranked_candidates else None     


        if origin_node:
            # Get version info
            origin_info = next((v for v in versions_info if v['node_id'] == origin_node), None)
            discovered_info = versions_info[-1]  # Latest version

            # Version sequence
            version_seq = self._get_version_sequence(
                versions_info,
                origin_info['version'],
                discovered_info['version']
            )

            # Calculate confidence dynamically
            confidence = self._calculate_confidence(
                method='vector_temporal',
                origin_node=origin_node,
                num_candidates=len(package_neighbors),
                version_sequence=version_seq,
                explanations=explanations
            )

            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': f"{package}@{origin_info['version']}",
                'discovered_version': f"{package}@{discovered_info['version']}",
                'confidence': confidence,
                'method': 'vector_temporal',
                'version_sequence': version_seq,
                'ranked_candidates': [f"{package}@{self._get_version_for_node(v, versions_info)}" 
                                     for v in ranked_candidates[:10]],
                'num_candidates': len(package_neighbors)
            }
        else:
            return self._failed_result(cve_id, 'No candidates found')
        
    
    def _localize_temporal_only(
        self,
        cve_id: str,
        package: str,
        versions_info: List[Dict],
        discovered_version: Optional[str]
    ) -> Dict:
        """Localize using only temporal information"""

        # If temporal is disabled, use conservative estimate
        if not self.use_temporal:
            # Conservative: go back 3 versions from discovered (or use earliest)
            if discovered_version and '@' in discovered_version:
                discovered_ver = discovered_version.split('@')[1]
                discovered_info = next((v for v in versions_info if v['version'] == discovered_ver), None)
                
                if discovered_info:
                    disc_idx = versions_info.index(discovered_info)
                    origin_idx = max(0, disc_idx - 3)
                    origin_info = versions_info[origin_idx]
                else:
                    origin_info = versions_info[0]
            else:
                origin_info = versions_info[0]
            
            discovered_info = versions_info[-1]
            
            version_seq = [v['version'] for v in versions_info]
            confidence = self._calculate_confidence(
                method='static_conservative',
                num_candidates=len(versions_info),
                version_sequence=version_seq
            )
            
            return {
                'cve_id': cve_id,
                'package': package,
                'origin_version': f"{package}@{origin_info['version']}",
                'discovered_version': f"{package}@{discovered_info['version']}",
                'confidence': confidence,
                'method': 'static_conservative',
                'version_sequence': version_seq,
                'ranked_candidates': [f"{package}@{v['version']}" for v in versions_info[:10]],
                'num_candidates': len(versions_info)
            }

        # Strategy: Use time window around discovered version
        if discovered_version and '@' in discovered_version:
            discovered_ver = discovered_version.split('@')[1]

            # Find this version
            discovered_info = next((v for v in versions_info if v['version'] == discovered_ver), None)
            
            if discovered_info:
                discovered_ts = discovered_info['timestamp']

                                # Look back 2 years
                time_window = 2 * 365 * 24 * 3600
                origin_ts_threshold = discovered_ts - time_window
                
                # Find earliest version in window
                candidates = [v for v in versions_info if v['timestamp'] >= origin_ts_threshold]
                
                if candidates:
                    origin_info = candidates[0]
                    
                    version_seq = self._get_version_sequence(
                        versions_info,
                        origin_info['version'],
                        discovered_ver
                    )
                    
                    # Calculate confidence
                    confidence = self._calculate_confidence(
                        method='temporal_window',
                        num_candidates=len(candidates),
                        version_sequence=version_seq
                    )
                    
                    return {
                        'cve_id': cve_id,
                        'package': package,
                        'origin_version': f"{package}@{origin_info['version']}",
                        'discovered_version': discovered_version,
                        'confidence': confidence,
                        'method': 'temporal_window',
                        'version_sequence': version_seq,
                        'ranked_candidates': [f"{package}@{v['version']}" for v in candidates[:10]],
                        'num_candidates': len(candidates)
                    }

        # Conservative fallback: Use earliest version
        origin_info = versions_info[0]
        discovered_info = versions_info[-1]
        
        version_seq = [v['version'] for v in versions_info]
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            method='conservative',
            num_candidates=len(versions_info),
            version_sequence=version_seq
        )
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': f"{package}@{origin_info['version']}",
            'discovered_version': f"{package}@{discovered_info['version']}",
            'confidence': confidence,
            'method': 'conservative',
            'version_sequence': version_seq,
            'ranked_candidates': [f"{package}@{v['version']}" for v in versions_info[:10]],
            'num_candidates': len(versions_info)
        }
    
    
    def _rank_candidates_by_similarity(
        self,
        candidates: List,
        explanations: Optional[Dict]
    ) -> List:
        """
        Rank candidates purely by similarity (no temporal consideration)
        Used when use_temporal=False
        """
        if not explanations:
            return candidates
        
        scores = {}
        for node_id in candidates:
            if node_id in explanations:
                info = explanations[node_id]
                # Convert distance to similarity
                dist = float(info.get('best_similarity', 0))
                sim_score = 1.0 / (1.0 + abs(dist) + 1e-8)
                scores[node_id] = sim_score
            else:
                scores[node_id] = 0.0
        
        # Sort by similarity only
        ranked = sorted(candidates, key=lambda n: scores.get(n, 0), reverse=True)
        return ranked
        

    def _rank_candidates_temporal(
        self,
        candidates: List,
        versions_info: List[Dict],
        explanations: Optional[Dict]
    ) -> List:
        """
        rank candidates by temporal score
        
        Score = w1 * time_score + w2 * similarity_score
        where time_score prefers earlier versions

        """
        scores = {}

        # get timestamps
        timestamps = [v['timestamp'] for v in versions_info]
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        ts_range = max(1, max_ts - min_ts)

        for node_id in candidates:
            # Time score (earlier = better)
            node_ts = self.timestamps.get(node_id, max_ts)
            time_score = 1.0 - (node_ts - min_ts) / ts_range
            
            # Similarity score
            sim_score = 0.5  # Default
            if explanations and node_id in explanations:
                info = explanations[node_id]
                # Convert distance to similarity
                dist = float(info.get('best_similarity', 0))
                sim_score = 1.0 / (1.0 + abs(dist) + 1e-8)
            
            # Combined score (time is more important for origin)
            scores[node_id] = 0.7 * time_score + 0.3 * sim_score
        
        # Sort by score
        ranked = sorted(candidates, key=lambda n: scores.get(n, 0), reverse=True)
        return ranked
    
    def _get_version_sequence(self, versions_info, start_ver, end_ver):
        """Get sequence of versions between start and end"""
        sequence = []
        in_range = False
        
        for v_info in versions_info:
            ver = v_info['version']
            
            if ver == start_ver:
                in_range = True
            
            if in_range:
                sequence.append(ver)
            
            if ver == end_ver:
                break
        
        return sequence

    def _calculate_confidence(
        self,
        method: str,
        origin_node= None,
        num_candidates: int = 0,
        version_sequence: Optional[list] = None,
        explanations: Optional[Dict] = None
    ) -> float:
        """
        calculate confidence score dynamically

        Factors:
            1. Method quality (vector > temporal > conservative)
            2. Vector similarity (if available)
            3. Number of candidates (fewer = more certain)
            4. Version sequence completeness
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        # Base confidence by method
        base_confidence = {
            'vector_temporal': 0.70,
            'temporal_window': 0.50,
            'conservative': 0.30
        }.get(method, 0.20)

        confidence_adjustments = 0.0

        # Adjustment 1: Vector similarity (if available)
        if explanations and origin_node and origin_node in explanations:
            info = explanations[origin_node]
            try:
                # Convert distance to similarity
                dist = float(info.get('best_similarity', 0))
                similarity = 1.0 / (1.0 + abs(dist) + 1e-8)
                
                # High similarity boosts confidence
                if similarity > 0.8:
                    confidence_adjustments += 0.15
                elif similarity > 0.6:
                    confidence_adjustments += 0.10
                elif similarity > 0.4:
                    confidence_adjustments += 0.05
            except (TypeError, ValueError):
                pass
        
        # Adjustment 2: Number of candidates (fewer = more certain)
        if num_candidates > 0:
            if num_candidates <= 3:
                confidence_adjustments += 0.10  # Very few candidates
            elif num_candidates <= 10:
                confidence_adjustments += 0.05  # Moderate number
            elif num_candidates > 30:
                confidence_adjustments -= 0.05  # Many candidates = uncertainty
        
        # Adjustment 3: Version sequence completeness
        if version_sequence:
            if len(version_sequence) >= 5:
                confidence_adjustments += 0.05  # Good version coverage
            elif len(version_sequence) == 1:
                confidence_adjustments -= 0.05  # Only one version

        # Calculate final confidence
        final_confidence = base_confidence + confidence_adjustments
        
        # Clamp to valid range
        return max(0.1, min(0.95, final_confidence))

    def _get_version_for_node(self, node_id, versions_info):
        """Get version string for a node_id"""
        info = next((v for v in versions_info if v['node_id'] == node_id), None)
        return info['version'] if info else 'unknown'

    def _infer_package_from_cve(self, cve_id):
        """Try to infer package from CVE nodes in graph"""
        # Look for nodes with this CVE
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            cve_list = node_data.get('cve_list', [])
            
            if any(cve_id in str(cve) for cve in cve_list):
                package, _ = self._parse_node(node_id, node_data)
                if package:
                    return package
        
        return None
    
    def _failed_result(self, cve_id, reason):
        """Return failed result"""
        return {
            'cve_id': cve_id,
            'package': None,
            'origin_version': None,
            'discovered_version': None,
            'confidence': 0.0,
            'method': 'failed',
            'version_sequence': [],
            'ranked_candidates': [],
            'failure_reason': reason
        }

# ============================================================================
# Baseline Methods
# ============================================================================

class NaiveBaselineLocalizer:
    """Baseline: Always return earliest version"""

    def __init__(self, dep_graph):
        self.graph = dep_graph
        self._build_package_index()

    def _build_package_index(self):
        """Build package index"""
        self.package_versions = defaultdict(list)
        
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            release = node_data.get('release','')

            if not release:
                continue
            
            parts = release.split(':')
            if len(parts) >= 3:
                artifact_id = parts[1]
                version = parts[2]
            elif len(parts) == 2:
                artifact_id = parts[0]
                version = parts[1]
            else:
                continue
            timestamp = node_data.get('timestamp', 0)
            self.package_versions[artifact_id].append({
                'version': version,
                'node_id': node_id,
                'timestamp': timestamp
            })
        for package in self.package_versions:
            self.package_versions[package].sort(key=lambda x: x['timestamp'])

    def localize_origin(self, cve_id, package, **kwargs):
        """Always return earliest version"""
        versions = self.package_versions.get(package, [])
        
        if not versions:
            return {'origin_version': None, 'method': 'naive_failed'}
        
        origin = versions[0]
        discovered = versions[-1]
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': f"{package}@{origin['version']}",
            'discovered_version': f"{package}@{discovered['version']}",
            'confidence': 0.3,
            'method': 'naive_earliest',
            'version_sequence': [v['version'] for v in versions]
        }
    
class ConservativeBaselineLocalizer:
    """Baseline: Estimate origin as N versions before discovered"""
    def __init__(self, dep_graph, n_versions_back=3):
        self.graph = dep_graph
        self.n_versions_back = n_versions_back
        self._build_package_index()

    def _build_package_index(self):
        """Build package index"""
        self.package_versions = defaultdict(list)
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            release = node_data.get('release', '')
            if not release:
                continue
            parts = release.split(':')
            if len(parts) >= 3:
                artifact_id = parts[1]
                version = parts[2]
            elif len(parts) == 2:
                artifact_id = parts[0]
                version = parts[1]
            else:
                continue
            timestamp = node_data.get('timestamp', 0)
            self.package_versions[artifact_id].append({
                'version': version,
                'node_id': node_id,
                'timestamp': timestamp
            })
        for package in self.package_versions:
            self.package_versions[package].sort(key=lambda x: x['timestamp'])
    
    def localize_origin(self, cve_id, package, discovered_version=None, **kwargs):
        """Estimate N versions before discovered"""
        versions = self.package_versions.get(package, [])
        
        if not versions:
            return {'origin_version': None, 'method': 'conservative_failed'}
        
        # Find discovered version index
        discovered_ver = discovered_version.split('@')[1] if discovered_version and '@' in discovered_version else None
        
        if discovered_ver:
            disc_idx = next((i for i, v in enumerate(versions) if v['version'] == discovered_ver), len(versions) - 1)
        else:
            disc_idx = len(versions) - 1
        
        # Go back N versions
        origin_idx = max(0, disc_idx - self.n_versions_back)
        
        origin = versions[origin_idx]
        discovered = versions[disc_idx]
        
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': f"{package}@{origin['version']}",
            'discovered_version': f"{package}@{discovered['version']}",
            'confidence': 0.5,
            'method': f'conservative_{self.n_versions_back}back',
            'version_sequence': [v['version'] for v in versions[origin_idx:disc_idx+1]]
        }





    

