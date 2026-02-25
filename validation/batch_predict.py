"""
Batch Prediction Script for GraphSec-Flow
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pickle
import json
from typing import Dict, List, Optional
import argparse
from tqdm import tqdm

from src.root_ana import RootCauseAnalyzer
from search.vamana import VamanaOnCVE, VamanaSearch
from cve.cvevector import CVEVector
from cent.temp_cent import TempCentricity
from cve.cveinfo import osv_cve_api
from utils.util import _first_nonempty


class BatchPredictor:
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
        with open(self.graph_path, 'rb') as f:
            self.depgraph = pickle.load(f)
        print(f"  ✓ Graph: {self.depgraph.number_of_nodes():,} nodes")

        with open(self.node_texts_path, 'rb') as f:
            self.nodeid_to_texts = pickle.load(f)
        print(f"  ✓ Node texts: {len(self.nodeid_to_texts):,} nodes")

        if self.cve_meta_path.exists():
            with open(self.cve_meta_path, 'rb') as f:
                self.cve_records = pickle.load(f)
        else:
            self.cve_records = None

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
        self.timestamps = {
            n: float(self.depgraph.nodes[n]["timestamp"])
            for n in self.depgraph.nodes()
            if "timestamp" in self.depgraph.nodes[n]
        }
        self._all_ts_sorted = sorted(self.timestamps.values())
        print(f"  ✓ Timestamps: {len(self.timestamps):,} nodes")

        # ----------------------------------------------------------------
        # One-time full-graph scan to build all reverse indices.
        # Avoids scanning 14M nodes per CVE in _get_cve_text/_time_window.
        # ----------------------------------------------------------------
        # cve_id -> text (from cve_records_for_meta builder_payload)
        self._cve_to_text: Dict[str, str] = {}
        # cve_id -> first node_id that carries it (for nodeid_to_texts fallback)
        self._cve_to_node: Dict[str, str] = {}
        # cve_id -> min timestamp of nodes carrying it
        self._cve_to_ts: Dict[str, float] = {}

        # Index from cve_records_for_meta (builder_payload has details + aliases)
        if self.cve_records and isinstance(self.cve_records, dict):
            for node_id, rec_list in self.cve_records.items():
                if not isinstance(rec_list, list):
                    continue
                for rec in rec_list:
                    if not isinstance(rec, dict):
                        continue
                    payload = rec.get('builder_payload', {}) or {}
                    text = (payload.get('details') or payload.get('summary')
                            or rec.get('details') or rec.get('summary') or '')
                    aliases = payload.get('aliases', []) or []
                    cve_ids_here = [a for a in aliases
                                    if isinstance(a, str) and a.startswith('CVE-')]
                    name = rec.get('name', '')
                    if name and name.startswith('CVE-'):
                        cve_ids_here.append(name)
                    for cid in cve_ids_here:
                        if text and cid not in self._cve_to_text:
                            self._cve_to_text[cid] = text

        print(f"  ✓ CVE→text index (from meta): {len(self._cve_to_text):,} CVEs")

        # Index from graph nodes (cve_list + nodeid_to_texts + timestamps)
        for node in self.depgraph.nodes():
            node_data = self.depgraph.nodes[node]
            ts = self.timestamps.get(node)
            for entry in node_data.get('cve_list', []) or []:
                cid = entry.get('name', '') if isinstance(entry, dict) else str(entry)
                if not cid or not cid.startswith('CVE-'):
                    continue
                # node fallback for text
                if cid not in self._cve_to_node:
                    self._cve_to_node[cid] = node
                # min timestamp for time window
                if ts is not None:
                    if cid not in self._cve_to_ts or ts < self._cve_to_ts[cid]:
                        self._cve_to_ts[cid] = ts

        print(f"  ✓ CVE→node index (graph scan): {len(self._cve_to_node):,} CVEs")
        print(f"  ✓ CVE→ts index: {len(self._cve_to_ts):,} CVEs")

        total_with_text = len(self._cve_to_text) + sum(
            1 for cid, node in self._cve_to_node.items()
            if cid not in self._cve_to_text and self.nodeid_to_texts.get(node)
        )
        print(f"  ✓ Total CVEs with text available: ~{total_with_text:,}")

    def _init_analyzer(self):
        self.centrality = TempCentricity(self.depgraph, search_scope='auto')
        self.embedder = CVEVector()
        ann = VamanaSearch()
        self.vamana = VamanaOnCVE(self.depgraph, self.nodeid_to_texts, self.embedder, ann)
        self.vamana.build(cve_records=self.cve_records)
        self.analyzer = RootCauseAnalyzer(
            vamana=self.vamana,
            node_cve_scores=self.node_cve_scores,
            timestamps=self.timestamps,
            centrality=self.centrality,
        )
        print("  ✓ Analyzer initialized")

    def collect_cves(self, max_cves=None):
        print("\nCollecting CVEs from graph...")
        # Use pre-built index instead of scanning 14M nodes
        cves = sorted(self._cve_to_node.keys())
        if max_cves:
            cves = cves[:max_cves]
        print(f"  Found {len(cves)} unique CVEs")
        return cves

    def _get_cve_text(self, cve_id: str) -> Optional[str]:
        # 1) From cve_records_for_meta builder_payload (O(1))
        text = self._cve_to_text.get(cve_id)
        if text:
            return text

        # 2) From nodeid_to_texts via pre-built node index (O(1))
        node = self._cve_to_node.get(cve_id)
        if node is not None:
            for t in self.nodeid_to_texts.get(node, []):
                if t:
                    return t

        # 3) OSV API fallback (only for CVEs not in any local data)
        try:
            cve_data = osv_cve_api(cve_id)
            if cve_data and "data" in cve_data:
                text = _first_nonempty(cve_data['data'], ['details', 'summary', 'description'])
                if text:
                    return text
        except Exception:
            pass

        return None

    def _time_window(self, cve_id: str):
        all_ts = self._all_ts_sorted
        fallback = (all_ts[len(all_ts) // 4], all_ts[3 * len(all_ts) // 4])

        # O(1) lookup via pre-built index
        cve_ts = self._cve_to_ts.get(cve_id)
        if cve_ts is None:
            return fallback

        window = 2 * 365 * 24 * 3600 * 1000.0
        t_s = max(all_ts[0], cve_ts - window)
        t_e = min(all_ts[-1], cve_ts + window)
        return t_s, t_e

    def predict_one_cve(self, cve_id: str, k: int = 15) -> List[str]:
        """Returns ranked node IDs list (empty if failed)."""
        try:
            text = self._get_cve_text(cve_id)
            if not text:
                return []

            query_vec = self.embedder.encode(text)
            t_s, t_e = self._time_window(cve_id)

            def cve_score_lookup(cid):
                return self.per_cve_scores.get(cid, 0.0)

            result = self.analyzer.analyze(
                query_vector=query_vec,
                k=k,
                t_s=t_s,
                t_e=t_e,
                explain=True,
                cve_score_lookup=cve_score_lookup,
                return_diagnostics=True,
            )

            if result is None or len(result) < 4:
                return []

            root_comm, root_node, diagnostics, ranked_node_ids = result

            if ranked_node_ids:
                return ranked_node_ids

            # fallback from diagnostics
            exps = (diagnostics.get('search_explanations', {})
                    if isinstance(diagnostics, dict) else {})
            if exps:
                return sorted(exps.keys(),
                               key=lambda n: exps[n].get('best_similarity', 0.0),
                               reverse=True)
            return [root_node] if root_node else []

        except Exception as e:
            import traceback
            traceback.print_exc()
            return []

    def run_batch_prediction(self, max_cves=None, k=15):
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
        if failed:
            print(f"  Failed CVEs (first 10): {failed[:10]}")
        return predictions

    def save_predictions(self, predictions, filename='predictions.json'):
        output_path = self.output_dir / filename
        print(f"\nSaving predictions to {output_path}...")
        with open(output_path, 'w') as f:
            json.dump(predictions, f, indent=2)

        total = sum(len(v) for v in predictions.values())
        summary = {
            'total_cves': len(predictions),
            'total_predictions': total,
            'avg_predictions_per_cve': total / len(predictions) if predictions else 0,
        }
        summary_path = self.output_dir / 'predictions_summary.json'
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"✓ Saved:")
        print(f"  • {output_path}")
        print(f"  • {summary_path}")
        print(f"\nSummary:")
        for key, val in summary.items():
            print(f"  {key}: {val}")
        return output_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-cves', type=int, default=None)
    parser.add_argument('--k', type=int, default=15)
    parser.add_argument('--graph-path', type=str, default='data/dep_graph_cve.pkl')
    args = parser.parse_args()

    print("=" * 70)
    print(" GraphSec-Flow Batch Prediction ".center(70))
    print("=" * 70)
    print(f"\nConfiguration:")
    print(f"  Max CVEs: {args.max_cves or 'all'}")
    print(f"  k: {args.k}")
    print(f"  Graph: {args.graph_path}")
    print("=" * 70)

    predictor = BatchPredictor(graph_path=args.graph_path)
    predictions = predictor.run_batch_prediction(max_cves=args.max_cves, k=args.k)
    predictor.save_predictions(predictions)

    print("\n" + "=" * 70)
    print(" Batch Prediction Complete! ".center(70))
    print("=" * 70)
    print(f"\nNext step:")
    print(f"  → Run actionability analysis:")
    print(f"     python validation/actionability.py")
    print("=" * 70)


if __name__ == '__main__':
    main()