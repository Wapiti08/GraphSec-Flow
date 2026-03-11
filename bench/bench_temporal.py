"""
Benchmark Framework for Temporal Root Cause Localization

Evaluates localization algorithms on ground truth data.

Usage:
    python bench/bench_temporal.py \
        --gt data/gt_temporal.jsonl \
        --dep-graph data/dep_graph_cve.pkl \
        --cve-meta data/cve_records_for_meta.pkl \
        --node-texts data/nodeid_to_texts.pkl \
        --node-scores data/node_cve_scores.pkl \
        --output results/temporal_results.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pickle
import argparse
from collections import defaultdict
from typing import Dict, List, Optional
import time

# import localization algorithms
from src.temp_localize import (
    TemporalLocalizer,
    NaiveBaselineLocalizer,
    ConservativeBaselineLocalizer
)

from bench.baseline_localizers import (
    PageRankLocalizer,
    BetweennessLocalizer,
    TemporalPageRankLocalizer,
    CommunityOnlyLocalizer
)

from cve.cvevector import CVEVector
from ground.helper import SemVer


class TemporalLocalizationBenchmark:
    """
    Benchmark framework for temporal localization
    
    Evaluates:
    - Version distance accuracy
    - Time estimation error
    - Confidence calibration
    - Performance (latency)
    """
    
    def __init__(
        self,
        ground_truth_path: str,
        dep_graph,
        cve_meta,
        node_texts,
        node_cve_scores,
        timestamps
    ):
        """
        Args:
            ground_truth_path: Path to GT JSONL file
            dep_graph: NetworkX graph
            cve_meta: CVE metadata dict
            node_texts: Node texts for vector search
            node_cve_scores: Node CVE scores
            timestamps: Node timestamps
        """
        self.gt_path = ground_truth_path
        self.graph = dep_graph
        self.cve_meta = cve_meta
        self.node_texts = node_texts
        self.node_cve_scores = node_cve_scores
        self.timestamps = timestamps
        
        # Load ground truth
        self.ground_truth = self._load_ground_truth()
        
        # Initialize algorithms
        self.embedder = CVEVector()
        self.algorithms = {}

        # ====================================================================
        # SIMPLE HEURISTIC BASELINES
        # ====================================================================
        self.algorithms['Naive (Earliest)'] = NaiveBaselineLocalizer(dep_graph)
        self.algorithms['Conservative (3-back)'] = ConservativeBaselineLocalizer(
                    dep_graph, n_versions_back=3
                )
        
        # ====================================================================
        # GRAPH CENTRALITY BASELINES
        # ====================================================================
        self.algorithms['PageRank-based'] = PageRankLocalizer(dep_graph)
        self.algorithms['Betweenness-based'] = BetweennessLocalizer(dep_graph)
        self.algorithms['Temporal PageRank'] = TemporalPageRankLocalizer(dep_graph)

        # ====================================================================
        # COMMUNITY-BASED BASELINE
        # ====================================================================
        self.algorithms['Community-only (Louvain)'] = CommunityOnlyLocalizer(dep_graph)

        # ====================================================================
        # FULL MODEL (PROPOSED)
        # ====================================================================
        self.algorithms['TemporalLocalizer (Full)'] = TemporalLocalizer(
            dep_graph=dep_graph,
            cve_embedder=self.embedder,
            node_cve_scores=node_cve_scores,
            timestamps=timestamps,
            node_texts=node_texts,
            use_vector_search=True,
            use_temporal=True,
            use_community=True
        )

        # ====================================================================
        # ABLATION VARIANTS (optional, controlled by run_ablations flag)
        # ====================================================================
        self.ablation_algorithms = {
            'w/o Vector Search': TemporalLocalizer(
                dep_graph=dep_graph,
                cve_embedder=self.embedder,
                node_cve_scores=node_cve_scores,
                timestamps=timestamps,
                node_texts=node_texts,
                use_vector_search=False,  # ❌ Disabled
                use_temporal=True,
                use_community=True
            ),
            'w/o Temporal': TemporalLocalizer(
                dep_graph=dep_graph,
                cve_embedder=self.embedder,
                node_cve_scores=node_cve_scores,
                timestamps=timestamps,
                node_texts=node_texts,
                use_vector_search=True,
                use_temporal=False,  # ❌ Disabled
                use_community=True
            ),
            'w/o Community': TemporalLocalizer(
                dep_graph=dep_graph,
                cve_embedder=self.embedder,
                node_cve_scores=node_cve_scores,
                timestamps=timestamps,
                node_texts=node_texts,
                use_vector_search=True,
                use_temporal=True,
                use_community=False  # ❌ Disabled
            )
        }

    def _load_ground_truth(self) -> List[Dict]:
        """Load ground truth from JSONL"""
        gt = []
        with open(self.gt_path, 'r') as f:
            for line in f:
                gt.append(json.loads(line))
        return gt
    
    # ========================================================================
    # Evaluation Metrics
    # ========================================================================
    def evaluate_all(
        self, 
        max_samples: Optional[int] = None,
        run_ablations: bool = False
    ) -> Dict:
        """
        Evaluate all algorithms
        
        Args:
            max_samples: Limit number of samples to evaluate (for testing)
            run_ablations: Whether to run ablation study (slower)
        
        Returns:
            {
                algorithm_name: {
                    'results': [...],
                    'metrics': {...}
                }
            }
        """
        print(f"\n{'='*70}")
        print(" TEMPORAL LOCALIZATION BENCHMARK ".center(70, "="))
        print(f"{'='*70}\n")
        
        print(f"Ground Truth: {len(self.ground_truth)} entries")
        
        # Sample if needed
        gt_to_eval = self.ground_truth[:max_samples] if max_samples else self.ground_truth
        
        print(f"Evaluating on: {len(gt_to_eval)} entries")
        
        if run_ablations:
            print(f"Ablation study: ENABLED")
        else:
            print(f"Ablation study: DISABLED (use --ablations to enable)")
        print()
        
        all_results = {}
        
        # Evaluate main algorithms
        for algo_name, algo in self.algorithms.items():
            print(f"{'='*70}")
            print(f" {algo_name} ".center(70, "="))
            print(f"{'='*70}\n")
            
            results = self._evaluate_algorithm(algo, gt_to_eval, algo_name)
            all_results[algo_name] = results
            
            # Print summary
            self._print_algorithm_summary(algo_name, results)
        
        # Evaluate ablation variants (if enabled)
        if run_ablations:
            print(f"\n{'='*70}")
            print(" ABLATION STUDY ".center(70, "="))
            print(f"{'='*70}\n")
            
            for ablation_name, ablation_algo in self.ablation_algorithms.items():
                print(f"{'='*70}")
                print(f" {ablation_name} ".center(70, "="))
                print(f"{'='*70}\n")
                
                results = self._evaluate_algorithm(ablation_algo, gt_to_eval, ablation_name)
                all_results[ablation_name] = results
                
                # Print summary
                self._print_algorithm_summary(ablation_name, results)
        
        # Comparison table
        print(f"\n{'='*70}")
        print(" ALGORITHM COMPARISON ".center(70, "="))
        print(f"{'='*70}\n")
        self._print_comparison_table(all_results)
        
        return all_results
    
    def _evaluate_algorithm(
        self,
        algorithm,
        ground_truth: List[Dict],
        algo_name: str
    ) -> Dict:
        """Evaluate a single algorithm"""
        
        results = []
        predictions = []
        
        for i, gt_entry in enumerate(ground_truth):
            if (i + 1) % 50 == 0:
                print(f"  Progress: {i+1}/{len(ground_truth)}")
            
            # Get CVE description
            cve_id = gt_entry['cve_id']
            package = gt_entry['package']
            
            # Get CVE description from metadata
            cve_description = self._get_cve_description(cve_id)
            
            # Run localization
            try:
                if hasattr(algorithm, 'localize_origin'):
                    # Determine which parameters to pass based on algorithm type
                    if 'TemporalLocalizer' in algo_name or 'w/o' in algo_name:
                        # Full model and ablations need CVE description
                        pred = algorithm.localize_origin(
                            cve_id=cve_id,
                            cve_description=cve_description,
                            discovered_version=gt_entry.get('discovered_version'),
                            k=15
                        )
                    else:
                        # Baselines only need package
                        pred = algorithm.localize_origin(
                            cve_id=cve_id,
                            package=package,
                            discovered_version=gt_entry.get('discovered_version')
                        )
                else:
                    pred = {'origin_version': None, 'method': 'error'}
            except Exception as e:
                print(f"  Error on {cve_id}: {e}")
                pred = {'origin_version': None, 'method': 'error', 'error': str(e)}
            
            # Compute metrics
            metrics = self._compute_single_metrics(gt_entry, pred)
            
            result = {
                'cve_id': cve_id,
                'package': package,
                'gt_origin': gt_entry['origin_version'],
                'pred_origin': pred.get('origin_version'),
                'gt_discovered': gt_entry.get('discovered_version'),
                'metrics': metrics,
                'prediction': pred
            }
            
            results.append(result)
            predictions.append(pred)
        
        # Aggregate metrics
        aggregated_metrics = self._aggregate_metrics(results)
        
        return {
            'results': results,
            'predictions': predictions,
            'metrics': aggregated_metrics
        }
    
    def _compute_single_metrics(self, gt_entry: Dict, pred: Dict) -> Dict:
        """Compute metrics for a single prediction"""
        
        metrics = {
            'exact_match': 0,
            'within_1_version': 0,
            'within_3_versions': 0,
            'version_distance': None,
            'time_error_days': None,
            'success': 0
        }
        
        gt_origin = gt_entry.get('origin_version')
        pred_origin = pred.get('origin_version')
        
        if not pred_origin or not gt_origin:
            return metrics
        
        metrics['success'] = 1
        
        # Version distance
        version_distance = self._compute_version_distance(
            gt_origin,
            pred_origin,
            gt_entry.get('version_sequence', [])
        )
        
        metrics['version_distance'] = version_distance
        
        if version_distance is not None:
            if version_distance == 0:
                metrics['exact_match'] = 1
            if version_distance <= 1:
                metrics['within_1_version'] = 1
            if version_distance <= 3:
                metrics['within_3_versions'] = 1
        
        # Time error
        gt_ts = gt_entry.get('origin_timestamp')
        pred_ts = self._get_timestamp_for_version(pred_origin)
        
        if gt_ts and pred_ts:
            time_error_days = abs(gt_ts - pred_ts) / (24 * 3600)
            metrics['time_error_days'] = time_error_days
        
        return metrics
    
    def _compute_version_distance(
        self,
        gt_version: str,
        pred_version: str,
        version_sequence: List[str]
    ) -> Optional[int]:
        """
        Compute distance between versions in sequence
        
        Returns:
            Number of versions between gt and pred, or None if not in sequence
        """
        if not version_sequence:
            # Fallback: simple equality
            return 0 if gt_version == pred_version else 999
        
        # Extract version strings
        gt_ver = gt_version.split('@')[1] if '@' in gt_version else gt_version
        pred_ver = pred_version.split('@')[1] if '@' in pred_version else pred_version
        
        try:
            gt_idx = version_sequence.index(gt_ver)
            pred_idx = version_sequence.index(pred_ver)
            return abs(gt_idx - pred_idx)
        except ValueError:
            # Version not in sequence
            return 999
    
    def _get_timestamp_for_version(self, version_str: str) -> Optional[float]:
        """Get timestamp for a version"""
        if not version_str or '@' not in version_str:
            return None
        
        # Find node with this version
        for node_id in self.graph.nodes():
            if str(node_id) == version_str:
                return self.timestamps.get(node_id)
        
        return None
    
    def _get_cve_description(self, cve_id: str) -> str:
        """Get CVE description from metadata"""
        if cve_id not in self.cve_meta:
            return ""
        
        records = self.cve_meta[cve_id]
        
        for record in records:
            payload = record.get('builder_payload', {})
            
            # Try different description fields
            for field in ['details', 'summary', 'description']:
                if field in payload and payload[field]:
                    return payload[field]
        
        return ""
    
    def _aggregate_metrics(self, results: List[Dict]) -> Dict:
        """Aggregate metrics across all results"""
        
        metrics = {
            'total': len(results),
            'success': 0,
            'exact_match': 0,
            'within_1_version': 0,
            'within_3_versions': 0,
            'version_distances': [],
            'time_errors': [],
            'latencies': []
        }
        
        for result in results:
            m = result['metrics']
            pred = result['prediction']
            
            if m['success']:
                metrics['success'] += 1
            
            if m['exact_match']:
                metrics['exact_match'] += 1
            
            if m['within_1_version']:
                metrics['within_1_version'] += 1
            
            if m['within_3_versions']:
                metrics['within_3_versions'] += 1
            
            if m['version_distance'] is not None:
                metrics['version_distances'].append(m['version_distance'])
            
            if m['time_error_days'] is not None:
                metrics['time_errors'].append(m['time_error_days'])
            
            if 'time_ms' in pred:
                metrics['latencies'].append(pred['time_ms'])
        
        # Compute rates
        total = metrics['total']
        metrics['success_rate'] = metrics['success'] / total if total > 0 else 0
        metrics['exact_match_rate'] = metrics['exact_match'] / total if total > 0 else 0
        metrics['within_1_rate'] = metrics['within_1_version'] / total if total > 0 else 0
        metrics['within_3_rate'] = metrics['within_3_versions'] / total if total > 0 else 0
        
        # Compute statistics
        if metrics['version_distances']:
            vd = metrics['version_distances']
            metrics['mean_version_distance'] = sum(vd) / len(vd)
            metrics['median_version_distance'] = sorted(vd)[len(vd) // 2]
        
        if metrics['time_errors']:
            te = metrics['time_errors']
            metrics['mean_time_error_days'] = sum(te) / len(te)
            metrics['median_time_error_days'] = sorted(te)[len(te) // 2]
        
        if metrics['latencies']:
            lat = metrics['latencies']
            metrics['mean_latency_ms'] = sum(lat) / len(lat)
            metrics['median_latency_ms'] = sorted(lat)[len(lat) // 2]
            metrics['p95_latency_ms'] = sorted(lat)[int(len(lat) * 0.95)]
        
        return metrics
    
    # ========================================================================
    # Reporting
    # ========================================================================
    
    def _print_algorithm_summary(self, algo_name: str, results: Dict):
        """Print summary for an algorithm"""
        
        metrics = results['metrics']
        
        print(f"Results for {algo_name}:")
        print(f"  Total: {metrics['total']}")
        print(f"  Success: {metrics['success']} ({metrics['success_rate']:.1%})")
        print()
        
        print(f"Version Localization:")
        print(f"  Exact Match:      {metrics['exact_match']:4d} ({metrics['exact_match_rate']:.1%})")
        print(f"  Within 1 Version: {metrics['within_1_version']:4d} ({metrics['within_1_rate']:.1%})")
        print(f"  Within 3 Versions:{metrics['within_3_versions']:4d} ({metrics['within_3_rate']:.1%})")
        print()
        
        if 'mean_version_distance' in metrics:
            print(f"Version Distance Error:")
            print(f"  Mean:   {metrics['mean_version_distance']:.2f} versions")
            print(f"  Median: {metrics['median_version_distance']:.0f} versions")
            print()
        
        if 'mean_time_error_days' in metrics:
            print(f"Time Estimation Error:")
            print(f"  Mean:   {metrics['mean_time_error_days']:.1f} days")
            print(f"  Median: {metrics['median_time_error_days']:.1f} days")
            print()
        
        if 'mean_latency_ms' in metrics:
            print(f"Performance:")
            print(f"  Mean Latency:   {metrics['mean_latency_ms']:.1f} ms")
            print(f"  Median Latency: {metrics['median_latency_ms']:.1f} ms")
            print(f"  P95 Latency:    {metrics.get('p95_latency_ms', 0):.1f} ms")
            print()
    
    def _print_comparison_table(self, all_results: Dict):
        """Print comparison table across algorithms"""
        
        # Header
        print(f"{'Algorithm':<25} {'Exact':>8} {'±1 Ver':>8} {'±3 Ver':>8} {'Mean Dist':>10} {'Latency':>10}")
        print(f"{'-'*25} {'-'*8} {'-'*8} {'-'*8} {'-'*10} {'-'*10}")
        
        # Rows
        for algo_name, results in all_results.items():
            m = results['metrics']
            
            exact = f"{m['exact_match_rate']:.1%}"
            within1 = f"{m['within_1_rate']:.1%}"
            within3 = f"{m['within_3_rate']:.1%}"
            mean_dist = f"{m.get('mean_version_distance', 0):.2f}"
            latency = f"{m.get('mean_latency_ms', 0):.1f} ms" if 'mean_latency_ms' in m else "N/A"
            
            print(f"{algo_name:<25} {exact:>8} {within1:>8} {within3:>8} {mean_dist:>10} {latency:>10}")
        
        print()
    
    def save_results(self, results: Dict, output_path: str):
        """Save results to JSON"""
        
        # Convert to serializable format
        serializable = {}
        
        for algo_name, algo_results in results.items():
            serializable[algo_name] = {
                'metrics': algo_results['metrics'],
                'num_results': len(algo_results['results'])
            }
        
        with open(output_path, 'w') as f:
            json.dump(serializable, f, indent=2)
        
        print(f"\n✓ Results saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark temporal localization algorithms"
    )
    parser.add_argument('--gt', required=True, help="Ground truth JSONL file")
    parser.add_argument('--dep-graph', required=True, help="Dependency graph pickle")
    parser.add_argument('--cve-meta', required=True, help="CVE metadata pickle")
    parser.add_argument('--node-texts', required=True, help="Node texts pickle")
    parser.add_argument('--node-scores', required=True, help="Node CVE scores pickle")
    parser.add_argument('--output', required=True, help="Output JSON file")
    parser.add_argument('--max-samples', type=int, help="Max samples to evaluate (for testing)")
    parser.add_argument('--ablations', action='store_true', 
                       help="Run ablation study (w/o Vector, w/o Temporal, w/o Community)")
    
    args = parser.parse_args()
    
    # Load data
    print("Loading data...")
    
    with open(args.dep_graph, 'rb') as f:
        dep_graph = pickle.load(f)
    print(f"  Graph: {dep_graph.number_of_nodes()} nodes")
    
    with open(args.cve_meta, 'rb') as f:
        cve_meta = pickle.load(f)
    print(f"  CVE metadata: {len(cve_meta)} entries")
    
    with open(args.node_texts, 'rb') as f:
        node_texts = pickle.load(f)
    print(f"  Node texts: {len(node_texts)} entries")
    
    with open(args.node_scores, 'rb') as f:
        node_cve_scores = pickle.load(f)
    print(f"  Node scores: {len(node_cve_scores)} entries")
    
    # Extract timestamps from graph
    timestamps = {n: dep_graph.nodes[n].get('timestamp', 0) for n in dep_graph.nodes()}
    
    # Run benchmark
    benchmark = TemporalLocalizationBenchmark(
        ground_truth_path=args.gt,
        dep_graph=dep_graph,
        cve_meta=cve_meta,
        node_texts=node_texts,
        node_cve_scores=node_cve_scores,
        timestamps=timestamps
    )
    
    results = benchmark.evaluate_all(
        max_samples=args.max_samples,
        run_ablations=args.ablations
    )
    
    # Save results
    benchmark.save_results(results, args.output)


if __name__ == "__main__":
    main()
