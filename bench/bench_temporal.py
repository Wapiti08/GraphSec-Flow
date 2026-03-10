"""
Benchmark Framework for Temporal Root Cause Localization

Evaluates localization algorithms on ground truth data.

Usage:
    python benchmark_temporal.py \
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
    
    