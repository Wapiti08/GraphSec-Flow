'''
Negative Control Experiment for GraphSec-Flow
Validate non-circularity by randomizing temporal signals

Usage:
    python3 validation/negative_controls.py

Precisely adapted to dep_graph_cve.pkl node structure

Node structure:
{
    'version': str,
    'timestamp': int (milliseconds),
    'cve_count': int,
    'has_cve': bool,
    'cve_list': [{'severity': str, 'name': str, 'cwe_ids': str}, ...],
    'release': str
}
    
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
    
    def analyze_graph_structure(self, G):
        """Analyze and report graph statistics"""
        print("\n" + "="*60)
        print("GRAPH STRUCTURE ANALYSIS")
        print("="*60)
        
        # Count nodes with timestamps
        nodes_with_ts = sum(1 for n in G.nodes() if G.nodes[n].get('timestamp'))
        
        # Count vulnerable nodes (using has_cve flag)
        vulnerable_nodes = sum(1 for n in G.nodes() if G.nodes[n].get('has_cve'))
        
        # Count by cve_count
        nodes_with_cve_count = sum(1 for n in G.nodes() if G.nodes[n].get('cve_count', 0) > 0)
        
        # Total CVEs
        total_cves = sum(G.nodes[n].get('cve_count', 0) for n in G.nodes())
        
        print(f"Total nodes: {G.number_of_nodes():,}")
        print(f"Nodes with timestamps: {nodes_with_ts:,} ({nodes_with_ts/G.number_of_nodes()*100:.2f}%)")
        print(f"Vulnerable nodes (has_cve=True): {vulnerable_nodes:,} ({vulnerable_nodes/G.number_of_nodes()*100:.3f}%)")
        print(f"Nodes with cve_count > 0: {nodes_with_cve_count:,}")
        print(f"Total CVEs in graph: {total_cves:,}")
        
        # Sample a few vulnerable nodes
        vuln_samples = [(n, G.nodes[n]) for n in G.nodes() if G.nodes[n].get('has_cve')][:3]
        if vuln_samples:
            print("\nSample vulnerable nodes:")
            for node_id, attrs in vuln_samples:
                cve_names = [c.get('name', 'Unknown') for c in attrs.get('cve_list', [])]
                print(f"  {node_id}: {attrs.get('release', 'Unknown')}")
                print(f"    CVEs: {', '.join(cve_names[:3])}{'...' if len(cve_names) > 3 else ''}")
    
     
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

        # Count vulnerable nodes (using has_cve flag)
        vulnerable_count = sum(
            1 for n in G_random.nodes()
            if G_random.nodes[n].get('has_cve', False)
        )
        print(f"Vulnerable nodes: {vulnerable_count:,} ({vulnerable_count/len(timestamps)*100:.3f}%)")
        
        # Shuffle timestamps
        np.random.seed(42)  # For reproducibility
        shuffled_timestamps = np.random.permutation(timestamps)
        
        # Reassign
        for node, new_timestamp in zip(nodes_with_time, shuffled_timestamps):
            G_random.nodes[node]['timestamp'] = new_timestamp
        
        print("✓ Timestamps randomized")
        print("  - Graph structure preserved")
        print("  - Temporal causality destroyed")
        print("  - CVE annotations unchanged (only timestamps shuffled)")
        
        # Verify randomization didn't break graph
        assert G_random.number_of_nodes() == G.number_of_nodes()
        assert G_random.number_of_edges() == G.number_of_edges()
        print("  - Graph integrity verified ✓")
        
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
        """
        Parse benchmark output to extract metrics
        
        Example output:
        {
            'Community': {'MRR': 0.00027, ...},
            'Static-DC': {'MRR': 0.00078, ...},
            ...
            'Full Model': {'MRR': 0.00078, ...}
        }
        """
        print("\nParsing benchmark output...")

        metrics = {}
        
        try:
            # Find lines that look like metrics
            lines = stdout.split('\n')
            
            # Strategy 1: Look for the final dict print
            for i, line in enumerate(lines):
                if 'Full Model' in line or 'all_metrics' in line.lower():
                    # Try to extract the dict from subsequent lines
                    dict_text = '\n'.join(lines[i:])
                    
                    # Use regex to find key metrics
                    mrr_match = re.search(r"'MRR':\s*([0-9.e-]+)", dict_text)
                    hit_match = re.search(r"'Hit-Root':\s*([0-9.e-]+)", dict_text)
                    pathf1_match = re.search(r"'Path-F1':\s*([0-9.e-]+)", dict_text)
                    leadtime_match = re.search(r"'LeadTime[^']*':\s*([0-9.e-]+)", dict_text)
                    
                    if mrr_match:
                        metrics['mrr'] = float(mrr_match.group(1))
                    if hit_match:
                        metrics['hit_root'] = float(hit_match.group(1))
                    if pathf1_match:
                        metrics['path_f1'] = float(pathf1_match.group(1))
                    if leadtime_match:
                        metrics['lead_time'] = float(leadtime_match.group(1))
                    
                    break
            
            # Strategy 2: Extract from specific model outputs
            # Look for "Full Model" results
            for line in lines:
                if 'Full Model' in line:
                    # Next few lines should have metrics
                    idx = lines.index(line)
                    context = '\n'.join(lines[idx:idx+10])
                    
                    if 'MRR' in context and 'mrr' not in metrics:
                        mrr_match = re.search(r"'MRR':\s*([0-9.e-]+)", context)
                        if mrr_match:
                            metrics['mrr'] = float(mrr_match.group(1))
            
            # If we got nothing, try to parse the whole thing as a dict
            if not metrics:
                print("  Attempting to parse entire output as dict...")
                # This is a fallback - might be fragile
                try:
                    # Find the last occurrence of a dict-like structure
                    import ast
                    for i in range(len(lines)-1, -1, -1):
                        if '{' in lines[i]:
                            dict_str = '\n'.join(lines[i:])
                            # Try to extract the dict
                            if 'Full Model' in dict_str:
                                # This is hacky but might work
                                pass
                except:
                    pass
            
            print(f"  Extracted metrics: {list(metrics.keys())}")
            if not metrics:
                print("  ⚠️  Warning: Could not extract metrics from output")
                print("  Will use manual input if needed")
            
        except Exception as e:
            print(f"  Error parsing output: {e}")
        
        return metrics
    
    def generate_report(self, baseline_metrics, random_metrics):
        """Generate comparison report for paper"""
        print("\n" + "="*70)
        print(" NEGATIVE CONTROL RESULTS ".center(70, "="))
        print("="*70)
        
        if not baseline_metrics or not random_metrics:
            print("\n⚠️  Missing metrics - cannot generate full report")
            
            if not baseline_metrics:
                print("\nPlease manually enter baseline metrics:")
                baseline_metrics = self._manual_input_metrics()
            
            if not random_metrics:
                print("\nPlease manually enter randomized metrics:")
                random_metrics = self._manual_input_metrics()
        
        # Calculate and display results
        print("\n" + "="*70)
        print("COMPARISON TABLE")
        print("="*70)
        
        metrics_to_compare = ['mrr', 'hit_root', 'path_f1', 'lead_time']
        
        print(f"\n{'Metric':<20} | {'Baseline':<15} | {'Random':<15} | {'% Drop':<12}")
        print("-" * 75)
        
        drops = []
        for metric in metrics_to_compare:
            baseline_val = baseline_metrics.get(metric, 0)
            random_val = random_metrics.get(metric, 0)
            
            if baseline_val > 0:
                drop_pct = ((baseline_val - random_val) / baseline_val * 100)
                drops.append(drop_pct)
            else:
                drop_pct = 0
            
            print(f"{metric.upper():<20} | {baseline_val:<15.6f} | "
                  f"{random_val:<15.6f} | {drop_pct:<12.1f}%")
        
        # Summary
        avg_drop = np.mean(drops) if drops else 0
        
        print("\n" + "="*70)
        print(f"Average performance drop: {avg_drop:.1f}%")
        print("="*70)
        
        if avg_drop > 70:
            print("\n✓ VALIDATION PASSED")
            print("  Substantial performance drop (>70%) confirms the model")
            print("  exploits genuine temporal signals, not statistical artifacts.")
            print("\n  This proves NON-CIRCULAR validation.")
        elif avg_drop > 40:
            print("\n⚠ PARTIAL VALIDATION")
            print("  Moderate drop suggests temporal dependence, but could be stronger.")
        else:
            print("\n⚠ WARNING: Drop less than expected")
            print("  Review model's temporal dependencies")
        
        # Save results
        results = {
            'baseline': baseline_metrics,
            'random_timestamps': random_metrics,
            'average_drop_percent': avg_drop,
            'drops_by_metric': {
                m: ((baseline_metrics.get(m, 0) - random_metrics.get(m, 0)) 
                    / baseline_metrics.get(m, 1) * 100)
                if baseline_metrics.get(m, 0) > 0 else 0
                for m in metrics_to_compare
            },
            'validation_passed': avg_drop > 70
        }
        
        output_path = self.output_dir / 'negative_control_results.json'
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ Results saved to: {output_path}")
        
        # Generate LaTeX table
        # self._generate_latex_table(baseline_metrics, random_metrics, avg_drop)
        
        return results
    
    def _manual_input_metrics(self):
        """Fallback: manually input metrics"""
        print("\nEnter metrics manually:")
        metrics = {}
        
        try:
            metrics['mrr'] = float(input("  MRR: "))
            metrics['hit_root'] = float(input("  Hit-Root: "))
            metrics['path_f1'] = float(input("  Path-F1 (optional, press Enter to skip): ") or "0")
            metrics['lead_time'] = float(input("  LeadTime (optional, press Enter to skip): ") or "0")
        except (ValueError, KeyboardInterrupt):
            print("\n  Using default values...")
            metrics = {'mrr': 0, 'hit_root': 0, 'path_f1': 0, 'lead_time': 0}
        
        return metrics
    
    def run_full_experiment(self):
        """Run complete negative control experiment"""
        print("="*70)
        print(" GraphSec-Flow Negative Control Experiment ".center(70))
        print("="*70)
        print("\nThis will:")
        print("  1. Load original graph")
        print("  2. Run baseline benchmark (~15-30 min)")
        print("  3. Create randomized graph")
        print("  4. Run randomized benchmark (~15-30 min)")
        print("  5. Compare results")
        print("\nTotal estimated time: 30-60 minutes")
        print("="*70)
        
        # input("\nPress Enter to continue or Ctrl+C to abort...")
        
        # Step 1: Load original graph
        G_original = self.load_graph()
        
        # Step 2: Run baseline benchmark
        baseline_metrics = self.run_benchmark(
            self.graph_path,
            label="baseline"
        )
        
        # Step 3: Create randomized graph
        G_random = self.randomize_timestamps(G_original)
        random_graph_path = self.save_randomized_graph(G_random)
        
        # Step 4: Run randomized benchmark
        random_metrics = self.run_benchmark(
            random_graph_path,
            label="random_timestamps"
        )
        
        # Step 5: Generate report
        results = self.generate_report(baseline_metrics, random_metrics)
        
        print("\n" + "="*70)
        print(" Experiment Complete! ".center(70))
        print("="*70)
        print("\nGenerated files:")
        print(f"  • {self.output_dir}/negative_control_results.json")
        print(f"  • {self.output_dir}/negative_control_table.tex")
        print(f"  • {self.output_dir}/baseline_benchmark_output.txt")
        print(f"  • {self.output_dir}/random_timestamps_benchmark_output.txt")
        print("="*70)
        
        return results


def main():
    """Main entry point"""
    
    # Initialize experiment with your actual file paths
    exp = NegativeControlExperiment(
        graph_path='data/dep_graph_cve.pkl',
        ref_layer_path='data/ref_paths_layer.jsonl',  # Or ref_paths_layer_full_6.jsonl
        node_texts_path='data/nodeid_to_texts.pkl',
        cve_meta_path='data/cve_records_for_meta.pkl',
        per_cve_path='data/per_cve_scores.pkl',
        node_scores_path='data/node_cve_scores.pkl'
    )
    
    results = exp.run_full_experiment()
    
    return results


if __name__ == '__main__':
    main()
