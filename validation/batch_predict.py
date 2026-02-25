"""
Batch Prediction Script for GraphSec-Flow - DEBUG VERSION
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
            if isinstance(self.cve_records, list):
                self.cve_lookup = {}
                for rec in self.cve_records:
                    cid = rec.get('id') or rec.get('cve_id') or rec.get('name', '')
                    if cid:
                        self.cve_lookup[cid] = rec
            elif isinstance(self.cve_records, dict):
                # cve_records is {node_id -> [record, ...]}
                # Build reverse lookup: cve_id -> record
                self.cve_lookup = {}
                for node_id, rec_list in self.cve_records.items():
                    if not isinstance(rec_list, list):
                        continue
                    for rec in rec_list:
                        if not isinstance(rec, dict):
                            continue
                        cid = rec.get('name') or rec.get('cve_id') or rec.get('id', '')
                        if cid and cid.startswith('CVE-') and cid not in self.cve_lookup:
                            self.cve_lookup[cid] = rec
            else:
                self.cve_lookup = {}
            print(f"  ✓ CVE metadata loaded ({len(self.cve_lookup):,} entries in local lookup)")
        else:
            self.cve_records = None
            self.cve_lookup = {}

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

        nodes = list(self.depgraph.nodes())
        self.timestamps = {
            n: float(self.depgraph.nodes[n]["timestamp"])
            for n in nodes
            if "timestamp" in self.depgraph.nodes[n]
        }
        self._all_ts_sorted = sorted(self.timestamps.values())
        print(f"  ✓ Timestamps: {len(self.timestamps):,} nodes")

        # Build reverse index: cve_id -> (node_id, text)
        # cve_records_for_meta structure: {node_id -> [{name, builder_payload:{details, aliases:[CVE-xxx]}}]}
        self._cve_to_text: dict = {}  # cve_id -> text string
        if self.cve_records and isinstance(self.cve_records, dict):
            for node_id, rec_list in self.cve_records.items():
                if not isinstance(rec_list, list):
                    continue
                for rec in rec_list:
                    if not isinstance(rec, dict):
                        continue
                    payload = rec.get('builder_payload', {}) or {}
                    # get text from builder_payload
                    text = (payload.get('details') or payload.get('summary')
                            or rec.get('details') or rec.get('summary') or '')
                    if not text:
                        continue
                    # map all aliases (CVE IDs) to this text
                    aliases = payload.get('aliases', []) or []
                    for alias in aliases:
                        if isinstance(alias, str) and alias.startswith('CVE-'):
                            if alias not in self._cve_to_text:
                                self._cve_to_text[alias] = text
                    # also try name field directly if it looks like CVE
                    name = rec.get('name', '')
                    if name and name.startswith('CVE-') and name not in self._cve_to_text:
                        self._cve_to_text[name] = text
        print(f"  ✓ CVE→text index: {len(self._cve_to_text):,} CVEs with text")

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
        cve_set = set()
        for node in self.depgraph.nodes():
            node_data = self.depgraph.nodes[node]
            if not node_data.get('has_cve', False):
                continue
            for cve_entry in node_data.get('cve_list', []):
                cve_id = cve_entry.get('name', '')
                if cve_id and cve_id.startswith('CVE-'):
                    cve_set.add(cve_id)
        cves = sorted(list(cve_set))
        if max_cves:
            cves = cves[:max_cves]
        print(f"  Found {len(cves)} unique CVEs")
        return cves

    def _get_cve_text(self, cve_id: str) -> Optional[str]:
        # 1) Pre-built index from cve_records_for_meta builder_payload (O(1))
        text = self._cve_to_text.get(cve_id)
        if text:
            # print(f"[BATCH-DEBUG] text from cve_to_text index, len={len(text)}")
            return text

        # 2) nodeid_to_texts via graph cve_list scan
        for node in self.depgraph.nodes():
            for entry in self.depgraph.nodes[node].get('cve_list', []) or []:
                cid = entry.get('name', '') if isinstance(entry, dict) else str(entry)
                if cid == cve_id:
                    texts = self.nodeid_to_texts.get(node, [])
                    for t in texts:
                        if t:
                            # print(f"[BATCH-DEBUG] text from nodeid_to_texts[{node}], len={len(t)}")
                            return t

        # 3) OSV API fallback
        try:
            cve_data = osv_cve_api(cve_id)
            if cve_data and "data" in cve_data:
                text = _first_nonempty(cve_data['data'], ['details', 'summary', 'description'])
                if text:
                    # print(f"[BATCH-DEBUG] text from OSV API")
                    return text
        except Exception:
            pass

        # print(f"[BATCH-DEBUG] no text found anywhere for {cve_id}")
        return None

    def _time_window(self, cve_id: str):
        all_ts = self._all_ts_sorted
        fallback = (all_ts[len(all_ts) // 4], all_ts[3 * len(all_ts) // 4])
        cve_timestamps = []
        for node in self.depgraph.nodes():
            for entry in self.depgraph.nodes[node].get('cve_list', []):
                if entry.get('name') == cve_id:
                    ts = self.timestamps.get(node)
                    if ts:
                        cve_timestamps.append(ts)
        if not cve_timestamps:
            return fallback
        cve_ts = min(cve_timestamps)
        window = 2 * 365 * 24 * 3600 * 1000.0
        t_s = max(all_ts[0], cve_ts - window)
        t_e = min(all_ts[-1], cve_ts + window)
        return t_s, t_e

    def predict_one_cve(self, cve_id: str, k: int = 15) -> List[str]:
        """Returns ranked node IDs list (empty if failed)."""
        # print(f"\n[BATCH-DEBUG] === predicting {cve_id} ===")
        try:
            text = self._get_cve_text(cve_id)
            if not text:
                # print(f"[BATCH-DEBUG] FAIL: no text for {cve_id}")
                return []
            # print(f"[BATCH-DEBUG] text found, length={len(text)}")

            query_vec = self.embedder.encode(text)
            t_s, t_e = self._time_window(cve_id)
            # print(f"[BATCH-DEBUG] time_window: {t_s} ~ {t_e}")

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

            # print(f"[BATCH-DEBUG] analyze() returned type={type(result)}, len={len(result) if result else 0}")

            if result is None or len(result) < 4:
                # print(f"[BATCH-DEBUG] FAIL: result has <4 elements: {result}")
                return []

            root_comm, root_node, diagnostics, ranked_node_ids = result
            # print(f"[BATCH-DEBUG] root_comm={root_comm}, root_node={root_node}")
            # print(f"[BATCH-DEBUG] ranked_node_ids type={type(ranked_node_ids)}, len={len(ranked_node_ids) if ranked_node_ids else 0}")
            if ranked_node_ids:
                # print(f"[BATCH-DEBUG] first 3: {ranked_node_ids[:3]}")

            if ranked_node_ids:
                return ranked_node_ids

            # fallback from diagnostics
            exps = diagnostics.get('search_explanations', {}) if isinstance(diagnostics, dict) else {}
            if exps:
                # print(f"[BATCH-DEBUG] fallback: using search_explanations, {len(exps)} nodes")
                return sorted(exps.keys(),
                               key=lambda n: exps[n].get('best_similarity', 0.0),
                               reverse=True)
            return [root_node] if root_node else []

        except Exception as e:
            import traceback
            # print(f"[BATCH-DEBUG] EXCEPTION for {cve_id}: {type(e).__name__}: {e}")
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
            print(f"  Failed CVEs: {failed[:10]}")
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