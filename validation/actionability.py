"""
Actionability Analysis for GraphSec-Flow
Demonstrates practical utility despite low absolute metrics

Usage:
    python validation/actionability.py

"""

import sys
import pickle
import numpy as np
import json
from pathlib import Path
from collections import defaultdict

sys.path.append(str(Path(__file__).parent.parent))

class ActionabilityAnalyzer:
    """ Analyze triage efficiency and practical utility
    
    """

    def __init__(self,
                 graph_path='data/dep_graph_cve.pkl',
                 predictions_path='data/validation/predictions.json'):
        
        self.graph_path = Path(graph_path)
        self.predictions_path = Path(predictions_path)
        self.output_dir = Path('data/validation')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print("Loading data...")
        self.G, self.vulnerable_nodes = self.load_graph()
        self.predictions = self.load_predictions()
        
        print(f"  ✓ Graph: {self.G.number_of_nodes():,} nodes")
        print(f"  ✓ Vulnerable nodes: {len(self.vulnerable_nodes):,}")
        print(f"  ✓ Predictions: {len(self.predictions)} CVEs")

    def load_graph(self):
        """Load dependency graph and identify vulnerable nodes"""
        print(f"Loading graph from {self.graph_path}...")
        with open(self.graph_path, 'rb') as f:
            G = pickle.load(f)
        
        # Identify vulnerable nodes using has_cve flag
        vulnerable_nodes = set()
        for node in G.nodes():
            node_data = G.nodes[node]
            if node_data.get('has_cve', False):
                vulnerable_nodes.add(node)
        
        return G, vulnerable_nodes
    
    def load_predictions(self):
        """Load predictions from JSON"""
        print(f"Loading predictions from {self.predictions_path}...")
        
        if not self.predictions_path.exists():
            raise FileNotFoundError(
                f"Predictions file not found: {self.predictions_path}\n"
                f"Please run: python validation/batch_predict.py first"
            )
        
        with open(self.predictions_path, 'r') as f:
            predictions = json.load(f)
        
        return predictions

    def calculate_topk_metrics(self, k_values=[100, 500, 1000, 5000]):
        '''
        calculate recall@k and precision@k for different k values

        returns:
            dict with metrics for each K
        '''
        print("\nCalculating Top-K metrics...")

        total_nodes = self.G.number_of_nodes()
        total_vulnerable = len(self.vulnerable_nodes)
        
        results = {}

        for k in k_values:
            print(f"  Calculating for K={k}...")

            # collect top-k predictions across all CVEs
            topk_predictions = set()
            for cve_id, ranked_nodes in self.predictions.items():
                topk_predictions.update(ranked_nodes[:k])

            # calculate metrics
            true_positives = len(topk_predictions & self.vulnerable_nodes)
            false_positives = len(topk_predictions - self.vulnerable_nodes)

            recall = true_positives / total_vulnerable if total_vulnerable > 0 else 0
            precision = true_positives / len(topk_predictions) if topk_predictions else 0

            # effort reduction
            inspected = len(topk_predictions)
            effort_reduction = (1 - inspected / total_nodes) * 100 if total_nodes > 0 else 0
            
            results[k] = {
                'recall': recall,
                'precision': precision,
                'true_positives': true_positives,
                'total_inspected': inspected,
                'effort_reduction': effort_reduction,
                'coverage': inspected / total_nodes if total_nodes > 0 else 0,
            }
            
            print(f"    Recall@{k}: {recall:.4f}")
            print(f"    Precision@{k}: {precision:.4f}")
            print(f"    Effort reduction: {effort_reduction:.3f}%")

        return results
    
    def generate_report(self, results):
        """Generate summary report"""
        print("\n" + "="*70)
        print(" ACTIONABILITY ANALYSIS RESULTS ".center(70, "="))
        print("="*70)

        total_nodes = self.G.number_of_nodes()
        total_vulnerable = len(self.vulnerable_nodes)

        print(f"\nGraph Statistics:")
        print(f"  Total nodes: {total_nodes:,}")
        print(f"  Vulnerable nodes: {total_vulnerable:,} ({total_vulnerable/total_nodes*100:.3f}%)")
        print(f"  CVEs analyzed: {len(self.predictions)}")
        
        print(f"\nTop-K Performance:")
        print(f"{'K':<10} | {'Recall':<10} | {'Precision':<12} | {'Coverage':<10} | {'Effort Reduction':<18}")
        print("-" * 75)
        
        for k in sorted(results.keys()):
            metrics = results[k]
            print(f"{k:<10} | {metrics['recall']:<10.4f} | {metrics['precision']:<12.6f} | "
                  f"{metrics['coverage']*100:<9.3f}% | {metrics['effort_reduction']:<17.3f}%")
        
        # Key insights
        print("\n" + "="*70)
        print("KEY INSIGHTS")
        print("="*70)

        # find best K for practical triage
        