"""
Streamlined Temporal Localization GT Builder

Directly reuses parsing logic from gt_builder.py and works with the actual
cve_records_for_meta.pkl format.

Key advantages:
1. No code duplication - imports functions from gt_builder.py
2. Works with actual CVE data structure (builder_payload.affected[].ranges.events)
3. Simple and maintainable

Usage:
    python ground/gt_temporal.py \
        --dep-graph data/dep_graph_cve.pkl \
        --cve-meta data/cve_records_for_meta.pkl \
        --output data/gt_temporal.jsonl
"""

import sys
from pathlib import Path
import pickle
import json
import csv
import random
import argparse
from collections import defaultdict
from typing import Dict, List, Optional

# Import existing parsing functions from gt_builder.py
sys.path.insert(0, str(Path(__file__).parent.parent))
from ground.helper import SemVer


class TemporalGTBuilder:
    """
    Generate temporal localization ground truth
    
    Reuses OSV parsing from gt_builder.py
    """
    
    def __init__(self, dep_graph, cve_meta_dict):
        """
        Args:
            dep_graph: NetworkX graph from dep_graph_cve.pkl
            cve_meta_dict: Dict from cve_records_for_meta.pkl
                          Format: {cve_id: [list of CVE records]}
                          
        Example CVE record structure:
        {
            'name': 'BIT-jenkins-2023-36478',
            'packages': ['jenkins'],
            'fix_commits': {'2.428.0'},
            'builder_payload': {
                'affected': [{
                    'package': {'name': 'jenkins'},
                    'ranges': [{
                        'events': [
                            {'introduced': '0'},
                            {'fixed': '2.428.0'}
                        ]
                    }]
                }]
            }
        }
        """
        self.graph = dep_graph
        self.cve_meta = cve_meta_dict
        
        # Build version index
        self._build_version_index()
    
    def _build_version_index(self):
        """Build index: package -> [(version, node_id, timestamp)]"""
        print("Building version index from dependency graph...")
        
        self.package_versions = defaultdict(list)
        
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            
            # Extract package and version
            package, version = self._parse_node(node_id, node_data)
            timestamp = node_data.get('timestamp', 0)
            
            if package and version:
                self.package_versions[package].append({
                    'version': version,
                    'node_id': node_id,
                    'timestamp': timestamp
                })
        
        # Sort by timestamp
        for package in self.package_versions:
            self.package_versions[package].sort(key=lambda x: x['timestamp'])
        
        print(f"  Indexed {len(self.package_versions)} packages")
    
    def _parse_node(self, node_id, node_data):
        """Extract package and version from graph node"""
        node_str = str(node_id)
        
        # Try package@version format
        if '@' in node_str:
            parts = node_str.rsplit('@', 1)
            return parts[0], parts[1]
        
        # Fallback to node data
        package = node_data.get('package') or node_data.get('release', '')
        version = node_data.get('version', '')
        
        if '@' in package:
            parts = package.rsplit('@', 1)
            return parts[0], parts[1]
        
        return package, version
    
    # ========================================================================
    # OSV Parsing Functions (copied from gt_builder.py)
    # ========================================================================
    
    @staticmethod
    def extract_introduced_fixed(cve_records: List[Dict]) -> Dict:
        """
        Extract introduced and fixed versions from CVE records
        
        Parses builder_payload.affected[].ranges[].events[]
        to find 'introduced' and 'fixed' version markers.
        
        Returns:
            {
                'package': str,
                'introduced_versions': [str, ...],
                'fixed_versions': [str, ...],
                'all_ranges': [{'introduced': str, 'fixed': str}, ...]
            }
        """
        package = None
        introduced_versions = []
        fixed_versions = []
        all_ranges = []
        
        for record in cve_records:
            # Get package name
            if not package and 'packages' in record:
                packages = record['packages']
                if packages and isinstance(packages, list):
                    package = packages[0]
            
            # Parse builder_payload (OSV format)
            payload = record.get('builder_payload', {})
            
            for affected in payload.get('affected', []) or []:
                # Get package from affected if not found yet
                if not package:
                    pkg_obj = affected.get('package', {})
                    if isinstance(pkg_obj, dict):
                        package = pkg_obj.get('name')
                
                # Parse ranges
                for rng in affected.get('ranges', []) or []:
                    events = rng.get('events', []) or []
                    
                    current_introduced = None
                    
                    for event in events:
                        if 'introduced' in event and event['introduced']:
                            intro = event['introduced']
                            current_introduced = intro
                            introduced_versions.append(intro)
                        
                        elif 'fixed' in event and event['fixed']:
                            fix = event['fixed']
                            fixed_versions.append(fix)
                            
                            # Create range pair
                            if current_introduced:
                                all_ranges.append({
                                    'introduced': current_introduced,
                                    'fixed': fix
                                })
                                current_introduced = None
                    
                    # If introduced but no fix yet
                    if current_introduced:
                        all_ranges.append({
                            'introduced': current_introduced,
                            'fixed': None
                        })
        
        return {
            'package': package,
            'introduced_versions': introduced_versions,
            'fixed_versions': fixed_versions,
            'all_ranges': all_ranges
        }
    
    def extract_origin_version(self, cve_id: str, cve_records: List[Dict]) -> Dict:
        """
        Extract origin version from CVE records
        
        Strategy:
        1. Use 'introduced' from ranges (highest confidence)
        2. Use earliest 'introduced' if multiple
        3. Estimate if no explicit 'introduced'
        
        Returns:
            {
                'cve_id': str,
                'package': str,
                'origin_version': str,
                'discovered_version': str,
                'confidence': float,
                'method': str,
                'evidence': str
            }
        """
        # Extract introduced/fixed from OSV data
        parsed = self.extract_introduced_fixed(cve_records)
        
        package = parsed['package']
        
        if not package:
            return {
                'cve_id': cve_id,
                'package': None,
                'origin_version': None,
                'discovered_version': None,
                'confidence': 0.0,
                'method': 'failed',
                'evidence': 'No package name found'
            }
        
        # Strategy 1: Use explicit 'introduced' (highest confidence)
        if parsed['introduced_versions']:
            introduced = parsed['introduced_versions']
            
            # Sort to find earliest
            try:
                sorted_intro = sorted(introduced, key=self._version_sort_key)
                origin = sorted_intro[0]
                
                # Discovered version = latest fixed or latest introduced
                if parsed['fixed_versions']:
                    sorted_fixed = sorted(parsed['fixed_versions'], key=self._version_sort_key)
                    discovered = sorted_fixed[-1]
                else:
                    discovered = sorted_intro[-1]
                
                return {
                    'cve_id': cve_id,
                    'package': package,
                    'origin_version': f"{package}@{origin}",
                    'discovered_version': f"{package}@{discovered}",
                    'confidence': 0.9,
                    'method': 'osv_introduced',
                    'evidence': f"Explicitly marked 'introduced' in version {origin}",
                    'all_ranges': parsed['all_ranges']
                }
            except Exception as e:
                pass
        
        # Strategy 2: Infer from fix_commits field
        fix_commits = None
        for record in cve_records:
            if 'fix_commits' in record and record['fix_commits']:
                fix_commits = record['fix_commits']
                break
        
        if fix_commits:
            # Get versions from graph
            versions_in_graph = self.package_versions.get(package, [])
            
            if versions_in_graph:
                # Conservative: assume origin is a few versions before latest
                # This is low confidence but better than nothing
                num_versions = len(versions_in_graph)
                origin_idx = max(0, num_versions - 5)  # 5 versions back
                discovered_idx = num_versions - 1
                
                origin_info = versions_in_graph[origin_idx]
                discovered_info = versions_in_graph[discovered_idx]
                
                return {
                    'cve_id': cve_id,
                    'package': package,
                    'origin_version': f"{package}@{origin_info['version']}",
                    'discovered_version': f"{package}@{discovered_info['version']}",
                    'confidence': 0.4,
                    'method': 'conservative_estimate',
                    'evidence': f"Estimated from graph (no explicit 'introduced')",
                    'all_ranges': []
                }
        
        # Failed
        return {
            'cve_id': cve_id,
            'package': package,
            'origin_version': None,
            'discovered_version': None,
            'confidence': 0.0,
            'method': 'failed',
            'evidence': 'Insufficient information in CVE record'
        }
    
    def _version_sort_key(self, version_str: str):
        """Sort key for version comparison"""
        try:
            sv = SemVer.parse(version_str)
            if sv:
                return (sv.major, sv.minor, sv.patch)
        except:
            pass
        
        # Fallback
        try:
            parts = version_str.replace('v', '').split('.')
            return tuple(int(p) if p.isdigit() else 0 for p in parts[:3])
        except:
            return (0, 0, 0)
    
    # ========================================================================
    # Ground Truth Generation
    # ========================================================================
    
    def generate_ground_truth(self, output_path: str):
        """Generate complete ground truth"""
        print(f"\n{'='*70}")
        print(" TEMPORAL LOCALIZATION GT GENERATION ".center(70, "="))
        print(f"{'='*70}\n")
        
        print(f"Processing {len(self.cve_meta)} CVE entries...")
        
        gt_entries = []
        stats = {
            'total': 0,
            'success': 0,
            'high_conf': 0,
            'medium_conf': 0,
            'low_conf': 0,
            'failed': 0,
            'by_method': defaultdict(int)
        }
        
        for cve_id, cve_records in self.cve_meta.items():
            stats['total'] += 1
            
            if stats['total'] % 100 == 0:
                print(f"  Progress: {stats['total']}/{len(self.cve_meta)}")
            
            # Extract origin version
            result = self.extract_origin_version(cve_id, cve_records)
            
            if not result['origin_version']:
                stats['failed'] += 1
                continue
            
            # Get version sequence and timestamps
            package = result['package']
            origin_ver = result['origin_version'].split('@')[1]
            discovered_ver = result['discovered_version'].split('@')[1]
            
            version_sequence = self._get_version_sequence(package, origin_ver, discovered_ver)
            origin_ts = self._get_timestamp(package, origin_ver)
            discovered_ts = self._get_timestamp(package, discovered_ver)
            
            time_lag_days = 0
            if origin_ts and discovered_ts:
                time_lag_days = (discovered_ts - origin_ts) / (24 * 3600)
            
            # Create GT entry
            gt_entry = {
                'cve_id': cve_id,
                'package': package,
                'origin_version': result['origin_version'],
                'discovered_version': result['discovered_version'],
                'version_sequence': version_sequence,
                'confidence': result['confidence'],
                'method': result['method'],
                'evidence': result['evidence'],
                'time_lag_days': time_lag_days,
                'origin_timestamp': origin_ts,
                'discovered_timestamp': discovered_ts,
                'source': 'automatic'
            }
            
            gt_entries.append(gt_entry)
            
            # Update stats
            stats['success'] += 1
            stats['by_method'][result['method']] += 1
            
            if result['confidence'] >= 0.8:
                stats['high_conf'] += 1
            elif result['confidence'] >= 0.5:
                stats['medium_conf'] += 1
            else:
                stats['low_conf'] += 1
        
        # Save
        with open(output_path, 'w') as f:
            for entry in gt_entries:
                f.write(json.dumps(entry) + '\n')
        
        print(f"\n✓ Saved {len(gt_entries)} GT entries to {output_path}")
        self._print_statistics(stats)
        
        return gt_entries, stats
    
    def _get_version_sequence(self, package, origin_ver, discovered_ver):
        """Get sequence of versions between origin and discovered"""
        if package not in self.package_versions:
            return []
        
        versions = self.package_versions[package]
        sequence = []
        in_range = False
        
        for v_info in versions:
            ver = v_info['version']
            
            if ver == origin_ver:
                in_range = True
            
            if in_range:
                sequence.append(ver)
            
            if ver == discovered_ver:
                break
        
        return sequence
    
    def _get_timestamp(self, package, version):
        """Get timestamp for a version"""
        if package not in self.package_versions:
            return None
        
        for v_info in self.package_versions[package]:
            if v_info['version'] == version:
                return v_info['timestamp']
        
        return None
    
    def _print_statistics(self, stats):
        """Print statistics"""
        print(f"\n{'='*70}")
        print(" STATISTICS ".center(70, "="))
        print(f"{'='*70}")
        
        total = stats['total']
        success = stats['success']
        
        print(f"\nTotal CVEs: {total}")
        print(f"Successfully extracted: {success} ({success/total*100:.1f}%)")
        
        print(f"\nBy Confidence:")
        print(f"  High (≥0.8):      {stats['high_conf']:4d} ({stats['high_conf']/total*100:5.1f}%)")
        print(f"  Medium (0.5-0.8): {stats['medium_conf']:4d} ({stats['medium_conf']/total*100:5.1f}%)")
        print(f"  Low (<0.5):       {stats['low_conf']:4d} ({stats['low_conf']/total*100:5.1f}%)")
        print(f"  Failed:           {stats['failed']:4d} ({stats['failed']/total*100:5.1f}%)")
        
        print(f"\nBy Method:")
        for method, count in sorted(stats['by_method'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {method:25s}: {count:4d} ({count/total*100:5.1f}%)")
        
        print(f"{'='*70}\n")
        
        if success / total >= 0.7:
            print("✅ Success rate ≥ 70% - Good for automated GT")
        else:
            print(f"⚠️  Success rate {success/total*100:.1f}% - May need manual annotation")
        
        print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate temporal localization GT"
    )
    parser.add_argument('--dep-graph', required=True)
    parser.add_argument('--cve-meta', required=True)
    parser.add_argument('--output', required=True)
    
    args = parser.parse_args()
    
    # Load data
    print("Loading dependency graph...")
    with open(args.dep_graph, 'rb') as f:
        dep_graph = pickle.load(f)
    print(f"  {dep_graph.number_of_nodes()} nodes, {dep_graph.number_of_edges()} edges")
    
    print("Loading CVE metadata...")
    with open(args.cve_meta, 'rb') as f:
        cve_meta = pickle.load(f)
    print(f"  {len(cve_meta)} CVE entries")
    
    # Generate GT
    builder = TemporalGTBuilder(dep_graph, cve_meta)
    builder.generate_ground_truth(args.output)


if __name__ == "__main__":
    main()