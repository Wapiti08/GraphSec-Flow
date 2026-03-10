"""
Generate sample_projects.json from existing dependency graph

This tool extracts real project snapshots from dep_graph_cve.pkl
by identifying root nodes (packages with few/no dependents) and their dependencies.

Usage:
    python validation/generate_sample_projects.py \
        --dep-graph data/dep_graph_cve.pkl \
        --output data/sample_projects.json \
        --num-samples 100 \
        --min-dependencies 3
"""

import argparse
import pickle
import json
import random
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Set, Optional

class ProjectSampler:
    """Extract project snapshots from dependency graph"""
    
    def __init__(self, dep_graph):
        self.graph = dep_graph
        self._analyze_graph()
    
    def _analyze_graph(self):
        """Analyze graph to find potential root nodes"""
        print("Analyzing dependency graph...")
        
        # Count in-degree (how many packages depend on this)
        self.in_degree = defaultdict(int)
        self.out_degree = defaultdict(int)
        
        for edge in self.graph.edges():
            src, dst = edge
            self.out_degree[src] += 1
            self.in_degree[dst] += 1
        
        # Find potential root nodes (packages with dependencies but few dependents)
        self.potential_roots = []
        
        for node in self.graph.nodes():
            out_deg = self.out_degree[node]
            in_deg = self.in_degree[node]
            
            # Criteria for a "project" node:
            # - Has at least some dependencies (out_degree > 0)
            # - Has few or no dependents (in_degree < 5)
            # This suggests it's an application rather than a library
            
            if out_deg >= 1 and in_deg < 5:
                self.potential_roots.append({
                    'node_id': node,
                    'out_degree': out_deg,
                    'in_degree': in_deg
                })
        
        print(f"Found {len(self.potential_roots)} potential root nodes (projects)")
        
        # Sort by out_degree (prefer nodes with more dependencies)
        self.potential_roots.sort(key=lambda x: x['out_degree'], reverse=True)
    
    def extract_dependencies(self, root_node: str, max_depth: int = 3) -> Dict:
        """
        Extract all direct dependencies of a root node.
        
        Args:
            root_node: Root node ID
            max_depth: How deep to traverse (1 = direct only)
        
        Returns:
            Dict of dependencies with their versions
        """
        dependencies = {}
        
        # BFS to find dependencies
        visited = {root_node}
        queue = deque([(root_node, 0)])
        
        while queue:
            node, depth = queue.popleft()
            
            if depth >= max_depth:
                continue
            
            # Get neighbors (dependencies)
            try:
                neighbors = list(self.graph.neighbors(node))
            except:
                # If graph doesn't have neighbors method, use edges
                neighbors = [dst for src, dst in self.graph.edges() if src == node]
            
            for dep_node in neighbors:
                if dep_node in visited:
                    continue
                
                visited.add(dep_node)
                
                # Parse package and version
                package, version = self._parse_node_id(dep_node)
                
                # Only add direct dependencies (depth == 0)
                if depth == 0:
                    dependencies[package] = {
                        'package': package,
                        'version': version,
                        'resolved_version': version,
                        'node_id': dep_node
                    }
                
                queue.append((dep_node, depth + 1))
        
        return dependencies
    
    def _parse_node_id(self, node_id: str) -> tuple:
        """
        Parse node ID to extract package and version.
        
        Handles formats like:
        - "express@3.0.2"
        - "n123456" (fallback to node data)
        """
        node_id_str = str(node_id)
        
        # Try to parse from node_id string
        if '@' in node_id_str:
            parts = node_id_str.rsplit('@', 1)
            return parts[0], parts[1]
        
        # Fallback: get from node data
        try:
            node_data = self.graph.nodes[node_id]
            package = node_data.get('package', node_id_str)
            version = node_data.get('version', 'unknown')
            
            # If package not in data, try to extract from release field
            if package == node_id_str and 'release' in node_data:
                release = node_data['release']
                if '@' in release:
                    parts = release.rsplit('@', 1)
                    package = parts[0]
                    version = parts[1]
            
            return package, version
        except:
            return node_id_str, 'unknown'
    
    def generate_samples(
        self,
        num_samples: int = 100,
        min_dependencies: int = 3,
        max_dependencies: int = 50
    ) -> List[Dict]:
        """
        Generate project snapshots.
        
        Args:
            num_samples: Number of projects to sample
            min_dependencies: Minimum number of dependencies
            max_dependencies: Maximum number of dependencies
        
        Returns:
            List of project snapshots
        """
        print(f"\nGenerating {num_samples} project samples...")
        
        samples = []
        attempted = 0
        
        for root_info in self.potential_roots:
            if len(samples) >= num_samples:
                break
            
            attempted += 1
            if attempted % 100 == 0:
                print(f"  Attempted: {attempted}, Generated: {len(samples)}")
            
            root_node = root_info['node_id']
            
            # Extract dependencies
            dependencies = self.extract_dependencies(root_node, max_depth=1)
            
            # Filter by dependency count
            if len(dependencies) < min_dependencies or len(dependencies) > max_dependencies:
                continue
            
            # Parse root node info
            package, version = self._parse_node_id(root_node)
            
            # Get timestamp if available
            try:
                node_data = self.graph.nodes[root_node]
                timestamp = node_data.get('timestamp')
                
                if timestamp:
                    # Convert timestamp to date string
                    from datetime import datetime
                    if isinstance(timestamp, (int, float)):
                        # Assume milliseconds
                        date = datetime.fromtimestamp(timestamp / 1000)
                        snapshot_date = date.strftime('%Y-%m-%d')
                    else:
                        snapshot_date = str(timestamp)
                else:
                    snapshot_date = '2023-01-01'
            except:
                snapshot_date = '2023-01-01'
            
            # Create project snapshot
            project = {
                'name': package,
                'version': version,
                'snapshot_date': snapshot_date,
                'dependencies': dependencies,
                'metadata': {
                    'root_node_id': root_node,
                    'num_dependencies': len(dependencies),
                    'in_degree': root_info['in_degree'],
                    'out_degree': root_info['out_degree']
                }
            }
            
            samples.append(project)
        
        print(f"\n✓ Generated {len(samples)} project samples")
        
        return samples


def main():
    parser = argparse.ArgumentParser(
        description="Generate sample projects from dependency graph"
    )
    parser.add_argument(
        "--dep-graph",
        required=True,
        help="Path to dependency graph pickle file"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file path"
    )
    parser.add_argument(
        "--num-samples",
        type=int,
        default=100,
        help="Number of project samples to generate"
    )
    parser.add_argument(
        "--min-dependencies",
        type=int,
        default=3,
        help="Minimum number of dependencies per project"
    )
    parser.add_argument(
        "--max-dependencies",
        type=int,
        default=50,
        help="Maximum number of dependencies per project"
    )
    
    args = parser.parse_args()
    
    # Load graph
    print(f"Loading dependency graph from {args.dep_graph}...")
    with open(args.dep_graph, 'rb') as f:
        dep_graph = pickle.load(f)
    
    print(f"Graph loaded: {dep_graph.number_of_nodes()} nodes, {dep_graph.number_of_edges()} edges")
    
    # Create sampler
    sampler = ProjectSampler(dep_graph)
    
    # Generate samples
    samples = sampler.generate_samples(
        num_samples=args.num_samples,
        min_dependencies=args.min_dependencies,
        max_dependencies=args.max_dependencies
    )
    
    if not samples:
        print("\n⚠️  No samples generated!")
        print("Try adjusting --min-dependencies or --max-dependencies")
        return
    
    # Save to JSON
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(samples, f, indent=2)
    
    print(f"\n✓ Saved to {output_path}")
    
    # Print statistics
    print("\n" + "="*70)
    print("SAMPLE STATISTICS")
    print("="*70)
    
    dep_counts = [len(p['dependencies']) for p in samples]
    print(f"\nDependency counts:")
    print(f"  Min: {min(dep_counts)}")
    print(f"  Max: {max(dep_counts)}")
    print(f"  Avg: {sum(dep_counts)/len(dep_counts):.1f}")
    
    print(f"\nSample projects:")
    for i, project in enumerate(samples[:5]):
        print(f"\n  [{i+1}] {project['name']}@{project['version']}")
        print(f"      Dependencies: {len(project['dependencies'])}")
        print(f"      Date: {project['snapshot_date']}")
        
        # Show first few dependencies
        deps = list(project['dependencies'].keys())[:3]
        print(f"      Sample deps: {', '.join(deps)}")
    
    if len(samples) > 5:
        print(f"\n  ... and {len(samples)-5} more projects")
    
    print("\n" + "="*70)
    print("\n✓ Ready to use in gt_builder_new.py!")
    print(f"\nNext step:")
    print(f"  python gt_builder_new.py \\")
    print(f"    --mode path_query \\")
    print(f"    --dep-graph {args.dep_graph} \\")
    print(f"    --sample-projects {args.output} \\")
    print(f"    ...")


if __name__ == "__main__":
    main()
