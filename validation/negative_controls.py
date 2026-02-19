'''
Negative Control Experiment for GraphSec-Flow
Validate non-circularity by randomizing temporal singals

Usage:
    python3 validation/negative_controls.py
'''

import sys
import pickle
import numpy as np
from pathlib import Path
import json
from copy import deepcopy
import subprocess
import re
import time

np.random.seed(42) 

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

class NegativeControlExperiment:
    """Randomization test to validate temporal signal usage"""

    def __init__(self, 
            graph_path='data/dep_graph_cve.pkl',
            ref_layer_path='data/ref_paths_layer.jsonl',
            node_texts_path='data/nodeid_to_texts.pkl',
            cve_meta_path='data/cve_records_for_meta.pkl',
            per_cve_path='data/per_cve_scores.pkl',
            node_scores_path='data/node_cve_scores.pkl'):
        """
        Initialize with paths matching your benchmark.py requirements
        
        Args:
            graph_path: CVE-enriched dependency graph
            ref_layer_path: Ground truth paths (JSONL format)
            node_texts_path: Node text representations
            cve_meta_path: CVE metadata for evaluation
            per_cve_path: Per-CVE scores (optional)
            node_scores_path: Node-level CVE scores (optional)
        """
        self.graph_path = Path(graph_path)
        self.ref_layer_path = Path(ref_layer_path)
        self.node_texts_path = Path(node_texts_path)
        self.cve_meta_path = Path(cve_meta_path)
        self.per_cve_path = Path(per_cve_path)
        self.node_scores_path = Path(node_scores_path)
        
        self.output_dir = Path('data/validation')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Verify required files exist
        self._verify_files()

    def _verify_files(self):
        """Check if required files exist"""
        required = {
            'graph': self.graph_path,
            'ref_layer': self.ref_layer_path,
            'node_texts': self.node_texts_path,
            'cve_meta': self.cve_meta_path,
        }
        
        missing = []
        for name, path in required.items():
            if not path.exists():
                missing.append(f"{name}: {path}")
        
        if missing:
            print("⚠️  WARNING: Missing required files:")
            for m in missing:
                print(f"   - {m}")
            print("\nPlease update file paths or generate missing files.")
            print("Continuing anyway - benchmark may fail...\n")
    
    def load_graph(self):
        """Load CVE-enriched dependency graph"""
        print(f"Loading graph from {self.graph_path}...")
        with open(self.graph_path, 'rb') as f:
            G = pickle.load(f)
        print(f"  ✓ Loaded: {G.number_of_nodes():,} nodes, {G.number_of_edges():,} edges")
        return G
     
     def randomize_timestamps(self, G):
        """
        Shuffle all node timestamps while preserving graph structure

        This breaks temporal causality - if model performance drops significantly, 
        it proves the model uses genuine temporal signals
        """
        print("\n" + "="*60)
        print("RANDOMIZING TIMESTAMPS")
        print("="*60)

        G_random = deepcopy(G)

        # extract all timestamps
        nodes_with_time = []
        timestamps = []

        for node in G_random.nodes():
            node_data = G_random.nodes[node]
            if 'timestamp' in node_data:
                nodes_with_time.append(node)
                timestamps.append(node_data['timestamp'])
        
        print(f"Found {len(timestamps):,} nodes with timestamps")

        # shuffle timestamps
        shuffled_timestamps = np.random.permutation(timestamps)

        # reassign
        for node, new_timestamp in zip(nodes_with_time, shuffled_timestamps):
            G_random.nodes[node]['timestamp'] = new_timestamp
        
        print("✓ Timestamps randomized")
        print("  - Graph structure preserved")
        print("  - Temporal causality destroyed")
        return G_random
    
    def save_randomized_graph(self, G_random):
        """Save randomized graph for benchmark"""
        output_path = self.output_dir / 'dep_graph_cve_random_timestamps.pkl'
        print(f"\nSaving randomized graph to: {output_path}")
        with open(output_path, 'wb') as f:
            pickle.dump(G_random, f)
        print("✓ Saved")
        return output_path
    
    def run_benchmark(self, graph_path, label="baseline"):
        """
        Run benchmark.py via subprocess and parse output
        
        Args:
            graph_path: Path to graph pickle file
            label: Label for this run (baseline/random)
        
        Returns:
            dict with metrics (MRR, Hit-Root, etc.)
        """
        print("\n" + "="*60)
        print(f"RUNNING BENCHMARK: {label.upper()}")
        print("="*60)
        print(f"Graph: {graph_path}")
        print(f"Ref paths: {self.ref_layer_path}")
        
        # build command
        cmd = [
            sys.executable,  # Use same Python interpreter
            'bench/benchmark.py',
            '--dep-graph', str(graph_path),
            '--ref-layer', str(self.ref_layer_path),
            '--node-texts', str(self.node_texts_path),
            '--cve-meta', str(self.cve_meta_path),
        ]

        # Add optional args if files exist
        if self.per_cve_path.exists():
            cmd.extend(['--per-cve', str(self.per_cve_path)])
        
        if self.node_scores_path.exists():
            cmd.extend(['--node-scores', str(self.node_scores_path)])
        
        print(f"\nCommand: {' '.join(cmd)}")
        print("\nRunning benchmark (this may take 10-30 minutes)...")
        print("=" * 60)

        try:
            # Run benchmark
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd='.',  # Run from project root
                timeout=18000  # 5 hour timeout
            )
            elapsed = time.time() - start_time

            print(f"\n✓ Benchmark completed in {elapsed/60:.1f} minutes")

            if result.returncode != 0:
                print(f"\n⚠️  Benchmark exited with code {result.returncode}")
                print("STDERR:", result.stderr)

            # parse output
            metrics = self._parse_benchmark_output(result.stdout)

            # Save raw output
            output_file = self.output_dir / f'{label}_benchmark_output.txt'
            with open(output_file, 'w') as f:
                f.write("=== STDOUT ===\n")
                f.write(result.stdout)
                f.write("\n\n=== STDERR ===\n")
                f.write(result.stderr)
            
            print(f"✓ Raw output saved to: {output_file}")
            
            return metrics

        except subprocess.TimeoutExpired:
            print("✗ Benchmark timed out after 1 hour")
            return None
        
        except Exception as e:
            print(f"✗ Error running benchmark: {e}")
            import traceback
            traceback.print_exc()
            return None
        
    def _parse_benchmark_output(self, stdout):
        