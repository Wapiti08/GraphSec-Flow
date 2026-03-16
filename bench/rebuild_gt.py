"""
Rebuild Ground Truth: Resolve GT simple names to graph Maven coordinates
========================================================================

Problem:
  GT says:    package="tomcat",  origin_version="tomcat@1.6"
  Graph has:  release="org.apache.tomcat:tomcat-catalina:9.0.93", node_id="n897241"
  
  These can never match by string comparison.

Solution:
  For each GT entry, find the actual graph node that:
    1. Has this CVE in its cve_list (exact CVE match)
    2. Is the earliest such node by timestamp (= silver reference root)
  
  Then rewrite GT with:
    package    = Maven artifactId (e.g., "tomcat-catalina")  
    origin_version = "tomcat-catalina@9.0.93"
    origin_node_id = "n897241"
    version_sequence = all versions of this artifactId, sorted by timestamp

This ensures GT and predictions use the same namespace.

Usage:
    python bench/rebuild_gt.py \
        --gt data/gt_temporal_fixed.jsonl \
        --dep-graph data/dep_graph_cve.pkl \
        --output data/gt_resolved.jsonl
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pickle
import argparse
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


def build_cve_to_nodes(dep_graph) -> Dict[str, List[dict]]:
    """
    Build index: CVE ID -> list of graph nodes that have this CVE.
    
    Each entry: {
        'node_id': 'n897241',
        'release': 'org.apache.tomcat:tomcat-catalina:9.0.93',
        'group_id': 'org.apache.tomcat',
        'artifact_id': 'tomcat-catalina',
        'version': '9.0.93',
        'timestamp': 1234567890.0,
        'severity': 'HIGH'
    }
    """
    cve_to_nodes = defaultdict(list)
    
    for nid in dep_graph.nodes():
        nd = dep_graph.nodes[nid]
        
        if not nd.get('has_cve', False):
            continue
        
        cve_list = nd.get('cve_list', [])
        release = nd.get('release', '')
        timestamp = nd.get('timestamp', 0)
        
        # Parse Maven coordinate
        group_id, artifact_id, version = '', '', ''
        if release:
            parts = release.split(':')
            if len(parts) >= 3:
                group_id = parts[0]
                artifact_id = parts[1]
                version = parts[2]
            elif len(parts) == 2:
                artifact_id = parts[0]
                version = parts[1]
        
        if not artifact_id or not version:
            continue
        
        for cve_entry in cve_list:
            # cve_entry can be a dict or a string
            if isinstance(cve_entry, dict):
                cve_id = cve_entry.get('name', '')
                severity = cve_entry.get('severity', 'UNKNOWN')
            elif isinstance(cve_entry, str):
                cve_id = cve_entry
                severity = 'UNKNOWN'
            else:
                continue
            
            if not cve_id:
                continue
            
            cve_id = str(cve_id).strip()
            
            # Convert Bitnami format: BIT-tomcat-2023-42795 → CVE-2023-42795
            # Pattern: BIT-{package}-{year}-{number}
            if cve_id.startswith('BIT-'):
                bit_match = re.match(r'BIT-[a-zA-Z0-9._-]+-(\d{4}-\d+)$', cve_id)
                if bit_match:
                    cve_id = f"CVE-{bit_match.group(1)}"
                else:
                    continue
            elif not cve_id.startswith('CVE-'):
                continue
            
            cve_to_nodes[cve_id].append({
                'node_id': nid,
                'release': release,
                'group_id': group_id,
                'artifact_id': artifact_id,
                'version': version,
                'timestamp': float(timestamp),
                'severity': severity,
            })
    
    # Sort each CVE's nodes by timestamp (earliest first)
    for cve_id in cve_to_nodes:
        cve_to_nodes[cve_id].sort(key=lambda x: x['timestamp'])
    
    return cve_to_nodes


def build_artifact_versions(dep_graph) -> Dict[str, List[dict]]:
    """
    Build index: artifactId -> list of (version, node_id, timestamp), sorted by timestamp.
    
    This gives us the version sequence for each artifact.
    """
    artifact_index = defaultdict(list)
    
    for nid in dep_graph.nodes():
        nd = dep_graph.nodes[nid]
        release = nd.get('release', '')
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
        
        timestamp = nd.get('timestamp', 0)
        artifact_index[artifact_id].append({
            'version': version,
            'node_id': nid,
            'timestamp': float(timestamp),
        })
    
    # Sort and deduplicate
    for art in artifact_index:
        artifact_index[art].sort(key=lambda x: x['timestamp'])
    
    return artifact_index


def resolve_gt_entry(
    gt_entry: dict,
    cve_to_nodes: Dict[str, List[dict]],
    artifact_versions: Dict[str, List[dict]],
) -> Optional[dict]:
    """
    Resolve one GT entry from simple names to graph coordinates.
    
    Input GT:
        cve_id: "CVE-2023-1234"
        package: "tomcat"
        origin_version: "tomcat@1.6"
    
    Output (resolved):
        cve_id: "CVE-2023-1234"
        package: "tomcat-catalina"              # actual Maven artifactId
        origin_version: "tomcat-catalina@9.0.1" # actual version from graph
        origin_node_id: "n897241"               # graph node ID
        origin_timestamp: 1234567890.0
        original_package: "tomcat"              # preserve original for reference
        original_origin: "tomcat@1.6"
        version_sequence: ["8.5.0", "8.5.1", ..., "9.0.93"]
        discovered_version: "tomcat-catalina@9.0.93"
        resolution_method: "cve_match"
    """
    cve_id = gt_entry.get('cve_id', '')
    original_package = gt_entry.get('package', '')
    original_origin = gt_entry.get('origin_version', '')
    
    # Find graph nodes with this CVE
    nodes = cve_to_nodes.get(cve_id, [])
    
    if not nodes:
        return None
    
    # The earliest node is the silver reference root
    root_node = nodes[0]
    
    artifact_id = root_node['artifact_id']
    version = root_node['version']
    node_id = root_node['node_id']
    timestamp = root_node['timestamp']
    
    # Build version sequence for this artifact
    art_versions = artifact_versions.get(artifact_id, [])
    seen = set()
    version_sequence = []
    for v in art_versions:
        if v['version'] not in seen:
            seen.add(v['version'])
            version_sequence.append(v['version'])
    
    # Discovered version = latest version of this artifact that has this CVE
    # (or just the latest version of the artifact)
    cve_nodes_same_artifact = [n for n in nodes if n['artifact_id'] == artifact_id]
    if cve_nodes_same_artifact:
        discovered_node = cve_nodes_same_artifact[-1]  # latest
    else:
        discovered_node = nodes[-1]
    
    discovered_artifact = discovered_node['artifact_id']
    discovered_version = discovered_node['version']
    
    return {
        'cve_id': cve_id,
        'package': artifact_id,
        'origin_version': f"{artifact_id}@{version}",
        'origin_node_id': node_id,
        'origin_timestamp': timestamp,
        'original_package': original_package,
        'original_origin': original_origin,
        'version_sequence': version_sequence,
        'discovered_version': f"{discovered_artifact}@{discovered_version}",
        'discovered_node_id': discovered_node['node_id'],
        'severity': root_node.get('severity', 'UNKNOWN'),
        'num_affected_nodes': len(nodes),
        'num_affected_artifacts': len(set(n['artifact_id'] for n in nodes)),
        'resolution_method': 'cve_match',
    }


def main():
    parser = argparse.ArgumentParser(
        description="Rebuild GT with resolved graph node IDs"
    )
    parser.add_argument('--gt', required=True,
                        help="Original GT JSONL file")
    parser.add_argument('--dep-graph', required=True,
                        help="Dependency graph pickle")
    parser.add_argument('--output', required=True,
                        help="Output resolved GT JSONL")
    
    args = parser.parse_args()
    
    # Load graph
    print("Loading dependency graph...")
    with open(args.dep_graph, 'rb') as f:
        dep_graph = pickle.load(f)
    print(f"  Nodes: {dep_graph.number_of_nodes():,}")
    print(f"  Edges: {dep_graph.number_of_edges():,}")
    
    # Build indexes
    print("\nBuilding CVE -> nodes index...")
    cve_to_nodes = build_cve_to_nodes(dep_graph)
    print(f"  Unique CVEs in graph: {len(cve_to_nodes):,}")
    
    print("Building artifact -> versions index...")
    artifact_versions = build_artifact_versions(dep_graph)
    print(f"  Unique artifacts: {len(artifact_versions):,}")
    
    # Load original GT
    print(f"\nLoading original GT from {args.gt}...")
    gt_entries = []
    with open(args.gt, 'r') as f:
        for line in f:
            if line.strip():
                gt_entries.append(json.loads(line.strip()))
    print(f"  Original GT entries: {len(gt_entries)}")
    
    # Resolve each entry
    print("\nResolving GT entries...")
    resolved = []
    failed = []
    
    for i, entry in enumerate(gt_entries):
        result = resolve_gt_entry(entry, cve_to_nodes, artifact_versions)
        
        if result:
            resolved.append(result)
        else:
            failed.append(entry)
        
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(gt_entries)} "
                  f"(resolved: {len(resolved)}, failed: {len(failed)})")
    
    print(f"\n  Resolved: {len(resolved)} ({len(resolved)/len(gt_entries):.1%})")
    print(f"  Failed:   {len(failed)} ({len(failed)/len(gt_entries):.1%})")
    
    # Stats on resolved entries
    if resolved:
        artifacts = set(r['package'] for r in resolved)
        avg_seq_len = sum(len(r['version_sequence']) for r in resolved) / len(resolved)
        avg_affected = sum(r['num_affected_nodes'] for r in resolved) / len(resolved)
        
        print(f"\n  Unique artifacts in resolved GT: {len(artifacts)}")
        print(f"  Avg version sequence length:     {avg_seq_len:.1f}")
        print(f"  Avg affected nodes per CVE:      {avg_affected:.1f}")
        
        # Show some examples
        print(f"\n  Examples:")
        for r in resolved[:5]:
            print(f"    {r['cve_id']}: {r['original_package']}@{r['original_origin'].split('@')[-1] if '@' in r['original_origin'] else '?'}"
                  f" → {r['origin_version']} (node {r['origin_node_id']})")
    
    # Show failed entries
    if failed:
        print(f"\n  Failed CVEs (not found in graph):")
        for f_entry in failed[:10]:
            print(f"    {f_entry.get('cve_id')}: {f_entry.get('package')}")
    
    # Save resolved GT
    print(f"\nSaving resolved GT to {args.output}...")
    with open(args.output, 'w') as f:
        for entry in resolved:
            f.write(json.dumps(entry) + '\n')
    
    # Also save a summary
    summary_path = Path(args.output).with_suffix('.summary.json')
    summary = {
        'original_count': len(gt_entries),
        'resolved_count': len(resolved),
        'failed_count': len(failed),
        'resolution_rate': len(resolved) / len(gt_entries) if gt_entries else 0,
        'unique_artifacts': len(set(r['package'] for r in resolved)),
        'unique_cves': len(set(r['cve_id'] for r in resolved)),
        'failed_cves': [f.get('cve_id') for f in failed],
    }
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Summary saved to {summary_path}")
    
    print("\nDone. Next steps:")
    print(f"  1. Use {args.output} as --gt in run_all_eval_parallel.py")
    print(f"  2. Clear checkpoints: rm results/checkpoints/*.pkl")
    print(f"  3. Re-run evaluation with resolved GT")


if __name__ == "__main__":
    main()