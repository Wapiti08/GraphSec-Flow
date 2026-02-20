"""
Batch Prediction Script for GraphSec-Flow
Generates ranked predictions for all CVEs for actionability analysis

Usage:
    python validation/batch_predict.py --max-cves 100

Output:
    data/validation/predictions.json - {cve_id: [ranked_node_ids]}
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pickle
import json
from typing import Dict, List
import argparse
from tqdm import tqdm

from src.root_ana import RootCauseAnalyzer
from search.vamana import VamanaOnCVE, VamanaSearch
from cve.cvevector import CVEVector
from cent.temp_cent import TempCentricity
from cve.cveinfo import osv_cve_api
from cve.cvescore import _normalize_cve_id, load_cve_seve_json, node_cve_score_agg
from utils.util import _first_nonempty

class BatchPredictor:
    ''' Batch prediction for all CVEs
    
    '''
    def __init__(self, 
                 graph_path='data/dep_graph_cve.pkl',
                 node_texts_path='data/nodeid_to_texts.pkl',
                 cve_meta_path='data/cve_records_for_meta.pkl',
                 node_scores_path='data/node_cve_scores.pkl',
                 per_cve_path='data/per_cve_scores.pkl'):
        
        self.graph_path = Path(graph_path)
        self.node_texts_path = Path(node_texts_path)
        self.cve_meta_path = Path(cve_meta_path)
        self.node_scores_path = Path(node_scores_path)
        self.per_cve_path = Path(per_cve_path)
        
        self.output_dir = Path('data/validation')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print("Loading graph and data...")
        self._load_data()
        print("Initializing analyzer...")
        self._init_analyzer()


    def _load_data(self):
        """Load all required data"""
        # Load graph
        with open(self.graph_path, 'rb') as f:
            self.depgraph = pickle.load(f)
        print(f"  ✓ Graph: {self.depgraph.number_of_nodes():,} nodes")
        
        # Load node texts
        with open(self.node_texts_path, 'rb') as f:
            self.nodeid_to_texts = pickle.load(f)
        print(f"  ✓ Node texts: {len(self.nodeid_to_texts):,} nodes")
        
        # Load CVE metadata
        if self.cve_meta_path.exists():
            with open(self.cve_meta_path, 'rb') as f:
                self.cve_records = pickle.load(f)
            print(f"  ✓ CVE metadata loaded")
        else:
            self.cve_records = None
        
        # Load scores
        if self.node_scores_path.exists():
            with open(self.node_scores_path, 'rb') as f:
                self.node_cve_scores = pickle.load(f)
            print(f"  ✓ Node CVE scores: {len(self.node_cve_scores):,} nodes")
        else:
            self.node_cve_scores = {n: 0.0 for n in self.depgraph.nodes()}
        
        if self.per_cve_path.exists():
            with open(self.per_cve_path, 'rb') as f:
                self.per_cve_scores = pickle.load(f)
            print(f"  ✓ Per-CVE scores: {len(self.per_cve_scores):,} CVEs")
        else:
            self.per_cve_scores = {}
        
        # Timestamps
        nodes = list(self.depgraph.nodes())
        self.timestamps = {n: float(self.depgraph.nodes[n]["timestamp"]) 
                          for n in nodes 
                          if "timestamp" in self.depgraph.nodes[n]}
        print(f"  ✓ Timestamps: {len(self.timestamps):,} nodes")


    def _init_analyzer(self):
        """Initialize RootCauseAnalyzer"""
        # Centrality
        self.centrality = TempCentricity(self.depgraph, search_scope='auto')
        
        # Embedder
        self.embedder = CVEVector()
        
        # Vamana
        ann = VamanaSearch()
        self.vamana = VamanaOnCVE(
            self.depgraph, 
            self.nodeid_to_texts, 
            self.embedder, 
            ann
        )
        
        if self.cve_records:
            self.vamana.build(cve_records=self.cve_records)
        else:
            self.vamana.build(cve_records=None)
        
        # Analyzer
        self.analyzer = RootCauseAnalyzer(
            vamana=self.vamana,
            node_cve_scores=self.node_cve_scores,
            timestamps=self.timestamps,
            centrality=self.centrality,
        )
        
        print("  ✓ Analyzer initialized")


    def collect_cves(self, max_cves=None):
        """Collect all CVEs from graph"""
        print("\nCollecting CVEs from graph...")
        
        cve_set = set()
        for node in self.depgraph.nodes():
            node_data = self.depgraph.nodes[node]
            if not node_data.get('has_cve', False):
                continue
            
            cve_list = node_data.get('cve_list', [])
            for cve_entry in cve_list:
                cve_id = cve_entry.get('name', '')
                if cve_id and cve_id.startswith('CVE-'):
                    cve_set.add(cve_id)
        
        cves = sorted(list(cve_set))
        
        if max_cves:
            cves = cves[:max_cves]
        
        print(f"  Found {len(cves)} unique CVEs")
        return cves
    
    
    def predict_one_cve(self, cve_id, k = 15):
        """
        Generate predictions for one CVE
        
        Returns:
            List[str] - ranked node IDs, or empty list if failed
        """
        try:
            # get cve data
            cve_data = osv_cve_api(cve_id)
            if not cve_data or "data" not in cve_data:
                return []
            
            # create query vector
            text = _first_nonempty(cve_data['data'], ['details', 'summary', 'description'])
            if not text:
                return []
            
            query_vec = self.embedder.encode(text)

            # Auto time window
            all_ts = sorted(self.timestamps.values())
            t_s = all_ts[len(all_ts) // 4]
            t_e = all_ts[3 * len(all_ts) // 4]
            
            # cve score lookup
            def cve_score_lookup(cid):
                return self.per_cve_scores.get(cid, 0.0)
            
            # run analyzer
            result = self.analyzer.analyze(
                query_vector=query_vec,
                k=k,
                t_s=t_s,
                t_e=t_e,
                explain=True,
                cve_score_lookup=cve_score_lookup,
                return_diagnostics=True,
            )

            # unpact results
            if len(result) == 4:
                root_comm, root_node, diagnostics, ranked_candidates = result
            else:
                # Old version without ranked_candidates
                root_comm, root_node, diagnostics = result
                ranked_candidates = [root_node] if root_node else []
            
            return ranked_candidates if ranked_candidates else []
            
        except Exception as e:
            print(f"  ✗ Error predicting {cve_id}: {e}")
            return []
    
    def run_batch_prediction(self, max_cves=None, k=15):
        '''
        Run prediction for all CVEs
        
        Args:
            max_cves: Maximum number of CVEs to process (for testing)
            k: Number of neighbors for Vamana search
        
        Returns:
            Dict[str, List[str]] - {cve_id: [ranked_node_ids]}
        '''
        cves = self.collect_cves(max_cves=max_cves)

        print(f"\nRunning batch prediction for {len(cves)} CVEs...")
        print(f"k={k}, output will be in {self.output_dir}")

        predictions = {}
        failed = []

        for cve_id in tqdm(cves, desc="Predicting"):
            ranked_nodes = self.predict_one_cve(cve_id, k=k)

            if ranked_nodes:
                predictions[cve_id] = ranked_nodes
            else:
                failed.append(cve_id)
        
        print(f"\n✓ Predictions generated:")
        print(f"  Successful: {len(predictions)}/{len(cves)}")
        print(f"  Failed: {len(failed)}")

        if failed and len(failed) <= 10:
            print(f"  Failed CVEs: {', '.join(failed)}")

        return predictions
    
    def save_predictions(self, predictions, filename='predictions.json'):
        """ save predictions to JSON
        
        """
        output_path = self.output_dir / filename

        print(f"\nSaving predictions to {output_path}...")

        with open(output_path, 'w') as f:
            json.dump(predictions, f, indent=2)

        # save summary
        summary = {
            'total_cves': len(predictions),
            'total_predictions': sum(len(nodes) for nodes in predictions.values()),
            'avg_predictions_per_cve': sum(len(nodes) for nodes in predictions.values()) / len(predictions) if predictions else 0,
        }

        summary_path = self.output_dir / 'predictions_summary.json'
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"✓ Saved:")
        print(f"  • {output_path}")
        print(f"  • {summary_path}")
        print(f"\nSummary:")
        for key, value in summary.items():
            print(f"  {key}: {value}")
        
        return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Batch prediction for GraphSec-Flow validation"
    )
    parser.add_argument(
        '--max-cves', 
        type=int, 
        default=None,
        help='Maximum number of CVEs to process (default: all)'
    )
    parser.add_argument(
        '--k', 
        type=int, 
        default=15,
        help='Number of neighbors for Vamana search (default: 15)'
    )
    parser.add_argument(
        '--graph-path',
        type=str,
        default='data/dep_graph_cve.pkl',
        help='Path to dependency graph'
    )

    args = parser.parse_args()
    
    print("="*70)
    print(" GraphSec-Flow Batch Prediction ".center(70))
    print("="*70)
    print(f"\nConfiguration:")
    print(f"  Max CVEs: {args.max_cves or 'all'}")
    print(f"  k: {args.k}")
    print(f"  Graph: {args.graph_path}")
    print("="*70)
    
    # Initialize predictor
    predictor = BatchPredictor(graph_path=args.graph_path)
    
    # Run predictions
    predictions = predictor.run_batch_prediction(
        max_cves=args.max_cves,
        k=args.k
    )
    
    # Save results
    output_path = predictor.save_predictions(predictions)
    
    print("\n" + "="*70)
    print(" Batch Prediction Complete! ".center(70))
    print("="*70)
    print(f"\nNext step:")
    print(f"  → Run actionability analysis:")
    print(f"     python validation/actionability.py")
    print("="*70)


if __name__ == '__main__':
    main()
