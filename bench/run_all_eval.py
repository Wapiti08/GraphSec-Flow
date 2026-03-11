"""
Complete Evaluation Pipeline for ASE Submission

Runs all experiments:
1. Main comparison (7 methods)
2. Ablation study (3 variants)
3. Multi-dimensional metrics
4. Visualizations (3 figures)
5. Case studies

Usage:
    python bench/run_all_eval.py \
        --gt data/gt_temporal.jsonl \
        --dep-graph data/dep_graph_cve.pkl \
        --cve-meta data/cve_records_for_meta.pkl \
        --node-texts data/nodeid_to_texts.pkl \
        --node-scores data/node_cve_scores.pkl \
        --output-dir results/

Output:
    results/
        ├── main_results.json
        ├── multidim_metrics.json
        ├── figures/
        │   ├── performance_by_severity.pdf
        │   ├── performance_by_time_lag.pdf
        │   └── confidence_calibration.pdf
        ├── tables/
        │   └── main_results.tex
        └── case_studies/
            ├── case_studies.md
            └── case_studies.tex
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pickle
import argparse
from datetime import datetime

# Import all modules
from bench.bench_temporal import TemporalLocalizationBenchmark
from eval.multidim_metrics import MultiDimEvaluator, print_multidim_metrics
from bench.visualization import generate_all_figures
from bench.case_studies import CaseStudyAnalyzer, generate_case_study_latex


class CompleteEvaluationPipeline:
    """
    Run complete evaluation pipeline for ASE submission
    """
    
    def __init__(
        self,
        gt_path: str,
        dep_graph_path: str,
        cve_meta_path: str,
        node_texts_path: str,
        node_scores_path: str,
        output_dir: str
    ):
        self.gt_path = gt_path
        self.dep_graph_path = dep_graph_path
        self.cve_meta_path = cve_meta_path
        self.node_texts_path = node_texts_path
        self.node_scores_path = node_scores_path
        self.output_dir = Path(output_dir)
        
        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'figures').mkdir(exist_ok=True)
        (self.output_dir / 'tables').mkdir(exist_ok=True)
        (self.output_dir / 'case_studies').mkdir(exist_ok=True)
        
        print("\n" + "="*80)
        print(" COMPLETE EVALUATION PIPELINE FOR ASE SUBMISSION ".center(80, "="))
        print("="*80 + "\n")
        print(f"Output directory: {self.output_dir}")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    def run_all(self, max_samples: int = None):
        """
        Run complete evaluation pipeline
        
        Args:
            max_samples: Limit samples for testing (None = all)
        """
        # Step 1: Load data
        print("\n" + "="*80)
        print(" STEP 1/6: LOADING DATA ".center(80, "="))
        print("="*80 + "\n")
        
        dep_graph, cve_meta, node_texts, node_cve_scores, timestamps = self._load_data()
        
        # Step 2: Run main benchmark
        print("\n" + "="*80)
        print(" STEP 2/6: MAIN BENCHMARK (7 methods + 3 ablations) ".center(80, "="))
        print("="*80 + "\n")
        
        main_results = self._run_main_benchmark(
            dep_graph, cve_meta, node_texts, node_cve_scores, timestamps, max_samples
        )
        
        # Step 3: Multi-dimensional metrics
        print("\n" + "="*80)
        print(" STEP 3/6: MULTI-DIMENSIONAL METRICS ".center(80, "="))
        print("="*80 + "\n")
        
        multidim_results = self._compute_multidim_metrics(
            main_results, timestamps
        )
        
        # Step 4: Generate visualizations
        print("\n" + "="*80)
        print(" STEP 4/6: GENERATING VISUALIZATIONS ".center(80, "="))
        print("="*80 + "\n")
        
        self._generate_visualizations(main_results)
        
        # Step 5: Generate LaTeX tables
        print("\n" + "="*80)
        print(" STEP 5/6: GENERATING LATEX TABLES ".center(80, "="))
        print("="*80 + "\n")
        
        # Step 6: Case studies
        print("\n" + "="*80)
        print(" STEP 6/6: CASE STUDIES ".center(80, "="))
        print("="*80 + "\n")
        
        self._generate_case_studies(main_results, dep_graph, cve_meta)
        
        # Summary
        self._print_summary()
    
    def _load_data(self):
        """Load all data files"""
        print("Loading data files...")
        
        with open(self.dep_graph_path, 'rb') as f:
            dep_graph = pickle.load(f)
        print(f"  ✓ Dependency graph: {dep_graph.number_of_nodes()} nodes")
        
        with open(self.cve_meta_path, 'rb') as f:
            cve_meta = pickle.load(f)
        print(f"  ✓ CVE metadata: {len(cve_meta)} entries")
        
        with open(self.node_texts_path, 'rb') as f:
            node_texts = pickle.load(f)
        print(f"  ✓ Node texts: {len(node_texts)} entries")
        
        with open(self.node_scores_path, 'rb') as f:
            node_cve_scores = pickle.load(f)
        print(f"  ✓ Node CVE scores: {len(node_cve_scores)} entries")
        
        timestamps = {n: dep_graph.nodes[n].get('timestamp', 0) for n in dep_graph.nodes()}
        print(f"  ✓ Timestamps extracted")
        
        return dep_graph, cve_meta, node_texts, node_cve_scores, timestamps
    
    def _run_main_benchmark(
        self, 
        dep_graph, 
        cve_meta, 
        node_texts, 
        node_cve_scores, 
        timestamps, 
        max_samples
    ):
        """Run main benchmark with all methods"""
        
        benchmark = TemporalLocalizationBenchmark(
            ground_truth_path=self.gt_path,
            dep_graph=dep_graph,
            cve_meta=cve_meta,
            node_texts=node_texts,
            node_cve_scores=node_cve_scores,
            timestamps=timestamps
        )
        
        # Run with ablations
        results = benchmark.evaluate_all(
            max_samples=max_samples,
            run_ablations=True
        )
        
        # Save results
        output_path = self.output_dir / 'main_results.json'
        benchmark.save_results(results, str(output_path))
        
        return results
    
    def _compute_multidim_metrics(self, main_results, timestamps):
        """Compute multi-dimensional metrics"""
        
        multidim_results = {}
        
        for method_name, method_results in main_results.items():
            print(f"\nComputing multi-dim metrics for: {method_name}")
            
            # Get ground truth and predictions
            results_list = method_results['results']
            
            gt_list = [{
                'cve_id': r['cve_id'],
                'origin_version': r['gt_origin'],
                'discovered_version': r['gt_discovered'],
                'time_lag_days': 0,  # Will be computed
                'version_sequence': []
            } for r in results_list]
            
            pred_list = [r['prediction'] for r in results_list]
            
            # Compute metrics
            evaluator = MultiDimEvaluator(gt_list, pred_list, timestamps)
            metrics = evaluator.compute_all_metrics()
            
            multidim_results[method_name] = metrics
            
            # Print
            print_multidim_metrics(metrics, method_name)
        
        # Save
        output_path = self.output_dir / 'multidim_metrics.json'
        with open(output_path, 'w') as f:
            # Convert numpy types to native Python types for JSON
            import numpy as np
            def convert(obj):
                if isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                elif isinstance(obj, np.ndarray):
                    return obj.tolist()
                elif isinstance(obj, dict):
                    return {k: convert(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert(item) for item in obj]
                return obj
            
            json.dump(convert(multidim_results), f, indent=2)
        
        print(f"\n✓ Multi-dim metrics saved: {output_path}")
        
        return multidim_results
    
    def _generate_visualizations(self, main_results):
        """Generate all figures"""
        
        figures_dir = self.output_dir / 'figures'
        generate_all_figures(main_results, str(figures_dir))
    
    
    def _generate_case_studies(self, main_results, dep_graph, cve_meta):
        """Generate case studies"""
        
        # Get results for full model
        full_model_results = main_results['TemporalLocalizer (Full)']['results']
        
        # Extract GT and predictions
        gt_list = [{
            'cve_id': r['cve_id'],
            'package': r['package'],
            'origin_version': r['gt_origin'],
            'discovered_version': r['gt_discovered'],
            'version_sequence': []
        } for r in full_model_results]
        
        pred_list = [r['prediction'] for r in full_model_results]
        
        # Analyze cases
        analyzer = CaseStudyAnalyzer(gt_list, pred_list, dep_graph, cve_meta)
        cases = analyzer.select_representative_cases()
        
        # Generate reports
        case_dir = self.output_dir / 'case_studies'
        
        # Markdown report
        analyzer.generate_case_study_report(
            cases, 
            str(case_dir / 'case_studies.md')
        )
        
        # LaTeX version
        generate_case_study_latex(
            cases,
            str(case_dir / 'case_studies.tex')
        )
    
    def _print_summary(self):
        """Print summary of outputs"""
        
        print("\n" + "="*80)
        print(" EVALUATION COMPLETE ".center(80, "="))
        print("="*80 + "\n")
        
        print("Generated files:")
        print(f"  📊 Main results:     {self.output_dir / 'main_results.json'}")
        print(f"  📊 Multi-dim metrics: {self.output_dir / 'multidim_metrics.json'}")
        print(f"  📈 Figures (3):       {self.output_dir / 'figures/'}")
        print(f"  📄 LaTeX tables:      {self.output_dir / 'tables/'}")
        print(f"  📝 Case studies:      {self.output_dir / 'case_studies/'}")
        print()
        print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(
        description="Run complete evaluation pipeline for ASE submission"
    )
    parser.add_argument('--gt', required=True, help="Ground truth JSONL file")
    parser.add_argument('--dep-graph', required=True, help="Dependency graph pickle")
    parser.add_argument('--cve-meta', required=True, help="CVE metadata pickle")
    parser.add_argument('--node-texts', required=True, help="Node texts pickle")
    parser.add_argument('--node-scores', required=True, help="Node CVE scores pickle")
    parser.add_argument('--output-dir', required=True, help="Output directory")
    parser.add_argument('--max-samples', type=int, help="Limit samples for testing")
    
    args = parser.parse_args()
    
    # Run pipeline
    pipeline = CompleteEvaluationPipeline(
        gt_path=args.gt,
        dep_graph_path=args.dep_graph,
        cve_meta_path=args.cve_meta,
        node_texts_path=args.node_texts,
        node_scores_path=args.node_scores,
        output_dir=args.output_dir
    )
    
    pipeline.run_all(max_samples=args.max_samples)


if __name__ == "__main__":
    main()