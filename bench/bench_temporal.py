"""
bench_temporal_patched.py — Patched benchmark with fixes for:

1. Version distance uses graph-derived version_sequence (not empty [])
2. Fuzzy version matching (handles package name format mismatches) 
3. Prediction format normalization (node_id → package@version)
4. Timestamp-based distance fallback when version not in sequence
5. Proper SemVer distance computation

Drop-in replacement: same CLI interface as bench_temporal.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pickle
import argparse
import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


# ============================================================================
# Version distance computation (the core fix)
# ============================================================================

def normalize_version_string(v: str) -> Tuple[str, str]:
    """
    Normalize a version string to (package, version).
    Handles: 'tomcat@7.0.0', 'tomcat-catalina@9.0.1', node_ids, etc.
    """
    if not v:
        return '', ''

    v = str(v)

    if '@' in v:
        pkg, ver = v.rsplit('@', 1)
        return pkg.lower(), ver

    # Might be a bare version number
    if re.match(r'^\d+[\.\d]*', v):
        return '', v

    return '', v


def semver_tuple(version_str: str) -> Optional[tuple]:
    """Parse version string into comparable tuple. Returns None if unparseable."""
    m = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?', version_str)
    if not m:
        return None
    parts = []
    for g in m.groups():
        if g is not None:
            parts.append(int(g))
        else:
            parts.append(0)
    return tuple(parts)


def compute_version_distance_fixed(
    gt_version: str,
    pred_version: str,
    version_sequence: List[str],
    graph=None,
    package_index=None,
    package: str = None,
) -> Optional[int]:
    """
    Compute distance between two versions.
    
    Strategy (in order):
    1. If both versions are in version_sequence: index distance
    2. If version_sequence is empty but package_index available: build sequence
    3. SemVer-based approximate distance
    4. Fallback: exact match = 0, else 999
    """
    _, gt_ver = normalize_version_string(gt_version)
    _, pred_ver = normalize_version_string(pred_version)

    if not gt_ver or not pred_ver:
        return None

    # Exact match (case-insensitive)
    if gt_ver.lower() == pred_ver.lower():
        return 0

    # Strategy 1: Use provided version_sequence
    if version_sequence and len(version_sequence) > 0:
        try:
            gt_idx = version_sequence.index(gt_ver)
            pred_idx = version_sequence.index(pred_ver)
            return abs(gt_idx - pred_idx)
        except ValueError:
            # One or both versions not in sequence — try fuzzy
            gt_idx = _fuzzy_find_in_sequence(gt_ver, version_sequence)
            pred_idx = _fuzzy_find_in_sequence(pred_ver, version_sequence)
            if gt_idx is not None and pred_idx is not None:
                return abs(gt_idx - pred_idx)

    # Strategy 2: Build sequence from package_index
    if package_index and package:
        entries = package_index.get(package, [])
        if not entries:
            # Fuzzy package lookup
            for key in package_index:
                if package.lower() in key.lower():
                    entries = package_index[key]
                    break

        if entries:
            seq = []
            seen = set()
            for e in entries:
                v = e['version']
                if v not in seen:
                    seen.add(v)
                    seq.append(v)

            gt_idx = _fuzzy_find_in_sequence(gt_ver, seq)
            pred_idx = _fuzzy_find_in_sequence(pred_ver, seq)
            if gt_idx is not None and pred_idx is not None:
                return abs(gt_idx - pred_idx)

    # Strategy 3: SemVer distance
    gt_sv = semver_tuple(gt_ver)
    pred_sv = semver_tuple(pred_ver)
    if gt_sv is not None and pred_sv is not None:
        # Rough distance: major diff * 100 + minor diff * 10 + patch diff
        # This gives ordinal-ish distance
        major_diff = abs(gt_sv[0] - pred_sv[0])
        minor_diff = abs(gt_sv[1] - pred_sv[1])
        patch_diff = abs(gt_sv[2] - pred_sv[2])

        # For "within N versions" metrics, treat as: 
        # same major+minor = patch distance
        # same major, diff minor = minor distance  
        # diff major = large distance
        if major_diff == 0 and minor_diff == 0:
            return patch_diff
        elif major_diff == 0:
            return minor_diff + patch_diff
        else:
            return major_diff * 10 + minor_diff + patch_diff

    # Fallback
    return 999


def _fuzzy_find_in_sequence(version: str, sequence: List[str]) -> Optional[int]:
    """Try to find a version in a sequence, allowing fuzzy matching."""
    # Exact
    if version in sequence:
        return sequence.index(version)

    # Try stripping trailing .0s: 7.0.0 -> 7.0 -> 7
    v = version
    while v.endswith('.0'):
        v = v[:-2]
        if v in sequence:
            return sequence.index(v)

    # Try adding .0s: 7 -> 7.0 -> 7.0.0
    v = version
    for _ in range(3):
        v = v + '.0'
        if v in sequence:
            return sequence.index(v)

    return None


# ============================================================================
# Prediction format normalizer
# ============================================================================

def normalize_prediction(pred: dict, graph=None, package_index=None) -> dict:
    """
    Ensure prediction has origin_version in package@version format.
    Handles cases where localizers return node_ids or bare version numbers.
    """
    origin = pred.get('origin_version')
    if not origin:
        return pred

    origin = str(origin)

    # Already in package@version format
    if '@' in origin:
        return pred

    # Might be a node_id — look up in graph
    if graph and origin in graph.nodes:
        nd = graph.nodes[origin]
        release = nd.get('release', '')
        if release:
            parts = release.split(':')
            if len(parts) >= 3:
                simple_pkg = parts[1].split('-')[0] if '-' in parts[1] else parts[1]
                version = parts[2]
                pred['origin_version'] = f"{simple_pkg}@{version}"
                pred['_original_node_id'] = origin
                return pred

    return pred


# ============================================================================
# Patched single-metric computation  
# ============================================================================

def compute_single_metrics(
    gt_entry: dict,
    pred: dict,
    graph=None,
    package_index=None,
    timestamps=None,
) -> dict:
    """Compute metrics for a single prediction (patched version)."""

    metrics = {
        'exact_match': 0,
        'within_1_version': 0,
        'within_3_versions': 0,
        'version_distance': None,
        'time_error_days': None,
        'success': 0,
    }

    gt_origin = gt_entry.get('origin_version')
    pred_origin = pred.get('origin_version')

    if not pred_origin or not gt_origin:
        return metrics

    metrics['success'] = 1

    # Compute version distance
    version_distance = compute_version_distance_fixed(
        gt_origin,
        pred_origin,
        gt_entry.get('version_sequence', []),
        graph=graph,
        package_index=package_index,
        package=gt_entry.get('package', ''),
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
    if gt_ts and timestamps:
        # Try to find timestamp for predicted version
        pred_str = str(pred_origin)
        pred_ts = None

        if '@' in pred_str:
            pred_pkg, pred_ver = pred_str.rsplit('@', 1)
            if package_index:
                entries = package_index.get(pred_pkg, [])
                for e in entries:
                    if e['version'] == pred_ver:
                        pred_ts = e['timestamp']
                        break

        if pred_ts and gt_ts:
            time_error_days = abs(float(gt_ts) - float(pred_ts)) / (24 * 3600)
            metrics['time_error_days'] = time_error_days

    return metrics


# ============================================================================
# Aggregate metrics
# ============================================================================

def aggregate_metrics(results: List[dict]) -> dict:
    """Aggregate metrics across all results."""

    metrics = {
        'total': len(results),
        'success': 0,
        'exact_match': 0,
        'within_1_version': 0,
        'within_3_versions': 0,
        'version_distances': [],
        'time_errors': [],
        'latencies': [],
    }

    for result in results:
        m = result['metrics']

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

        pred = result.get('prediction', {})
        if 'time_ms' in pred:
            metrics['latencies'].append(pred['time_ms'])

    total = metrics['total']
    metrics['success_rate'] = metrics['success'] / total if total > 0 else 0
    metrics['exact_match_rate'] = metrics['exact_match'] / total if total > 0 else 0
    metrics['within_1_rate'] = metrics['within_1_version'] / total if total > 0 else 0
    metrics['within_3_rate'] = metrics['within_3_versions'] / total if total > 0 else 0

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


# ============================================================================
# Patched evaluation loop
# ============================================================================

def evaluate_algorithm(
    algorithm,
    ground_truth: List[dict],
    algo_name: str,
    graph=None,
    package_index=None,
    timestamps=None,
    cve_meta=None,
    embedder=None,
) -> dict:
    """Evaluate a single algorithm with all fixes applied."""

    results = []

    for i, gt_entry in enumerate(ground_truth):
        if (i + 1) % 50 == 0:
            print(f"  Progress: {i+1}/{len(ground_truth)}")

        cve_id = gt_entry['cve_id']
        package = gt_entry['package']

        # Get CVE description
        cve_description = ''
        if cve_meta and cve_id in cve_meta:
            records = cve_meta[cve_id]
            for record in (records if isinstance(records, list) else [records]):
                payload = record.get('builder_payload', {})
                for field in ['details', 'summary', 'description']:
                    if field in payload and payload[field]:
                        cve_description = payload[field]
                        break
                if cve_description:
                    break

        # Run localization
        try:
            if hasattr(algorithm, 'localize_origin'):
                if 'TemporalLocalizer' in algo_name or 'w/o' in algo_name:
                    pred = algorithm.localize_origin(
                        cve_id=cve_id,
                        cve_description=cve_description,
                        discovered_version=gt_entry.get('discovered_version'),
                        k=15
                    )
                else:
                    pred = algorithm.localize_origin(
                        cve_id=cve_id,
                        package=package,
                        discovered_version=gt_entry.get('discovered_version')
                    )
            else:
                pred = {'origin_version': None, 'method': 'error'}

        except Exception as e:
            pred = {'origin_version': None, 'method': 'error', 'error': str(e)}

        # ---- KEY FIX: Normalize prediction format ----
        pred = normalize_prediction(pred, graph=graph, package_index=package_index)

        if i < 3:
            print(f"  [DEBUG] #{i+1}: CVE={cve_id}, pkg={package}")
            print(f"    GT:   {gt_entry.get('origin_version')}")
            print(f"    Pred: {pred.get('origin_version')}")
            print(f"    Seq:  {gt_entry.get('version_sequence', [])[:5]}...")

        # ---- KEY FIX: Use patched metrics ----
        metrics = compute_single_metrics(
            gt_entry, pred,
            graph=graph,
            package_index=package_index,
            timestamps=timestamps,
        )

        result = {
            'cve_id': cve_id,
            'package': package,
            'gt_origin': gt_entry['origin_version'],
            'pred_origin': pred.get('origin_version'),
            'gt_discovered': gt_entry.get('discovered_version'),
            'metrics': metrics,
            'prediction': pred,
        }
        results.append(result)

    aggregated = aggregate_metrics(results)

    return {
        'results': results,
        'predictions': [r['prediction'] for r in results],
        'metrics': aggregated,
    }


# ============================================================================
# Main (drop-in replacement CLI)
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Patched benchmark for temporal localization"
    )
    parser.add_argument('--gt', required=True, help="Ground truth JSONL (use fixed version)")
    parser.add_argument('--dep-graph', required=True, help="Dependency graph pickle")
    parser.add_argument('--cve-meta', required=True, help="CVE metadata pickle")
    parser.add_argument('--node-texts', required=True, help="Node texts pickle")
    parser.add_argument('--node-scores', required=True, help="Node CVE scores pickle")
    parser.add_argument('--output', required=True, help="Output JSON file")
    parser.add_argument('--max-samples', type=int, help="Max samples to evaluate")
    parser.add_argument('--ablations', action='store_true', help="Run ablation study")

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

    timestamps = {n: dep_graph.nodes[n].get('timestamp', 0) for n in dep_graph.nodes()}

    # Build package index (KEY ADDITION)
    from ground.fix_gt_and_bench import build_package_index
    package_index = build_package_index(dep_graph)
    print(f"  Package index: {len(package_index)} packages")

    # Load GT
    print(f"\nLoading ground truth from {args.gt}...")
    gt = []
    with open(args.gt, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                gt.append(json.loads(line))
    print(f"  {len(gt)} entries")

    # Verify GT has version sequences
    has_seq = sum(1 for e in gt if e.get('version_sequence'))
    print(f"  Entries with version_sequence: {has_seq}/{len(gt)}")
    if has_seq == 0:
        print("  ⚠️  WARNING: No version sequences found!")
        print("  Run fix_gt_and_bench.py first to populate them.")
        print("  Continuing with SemVer fallback distance...")

    gt_to_eval = gt[:args.max_samples] if args.max_samples else gt
    print(f"  Evaluating on: {len(gt_to_eval)} entries")

    # Initialize algorithms
    from bench.baseline_localizers import (
        PageRankLocalizer, BetweennessLocalizer,
        TemporalPageRankLocalizer, CommunityOnlyLocalizer
    )
    from src.temp_localize import (
        TemporalLocalizer, NaiveBaselineLocalizer, ConservativeBaselineLocalizer
    )
    from cve.cvevector import CVEVector

    embedder = CVEVector()

    algorithms = {
        'Naive (Earliest)': NaiveBaselineLocalizer(dep_graph),
        'Conservative (3-back)': ConservativeBaselineLocalizer(dep_graph, n_versions_back=3),
        'PageRank-based': PageRankLocalizer(dep_graph),
        'Betweenness-based': BetweennessLocalizer(dep_graph),
        'Temporal PageRank': TemporalPageRankLocalizer(dep_graph),
        'Community-only (Louvain)': CommunityOnlyLocalizer(dep_graph),
        'TemporalLocalizer (Full)': TemporalLocalizer(
            dep_graph=dep_graph, cve_embedder=embedder,
            node_cve_scores=node_cve_scores, timestamps=timestamps,
            node_texts=node_texts,
            use_vector_search=True, use_temporal=True, use_community=True
        ),
    }

    ablation_algorithms = {}
    if args.ablations:
        ablation_algorithms = {
            'w/o Vector Search': TemporalLocalizer(
                dep_graph=dep_graph, cve_embedder=embedder,
                node_cve_scores=node_cve_scores, timestamps=timestamps,
                node_texts=node_texts,
                use_vector_search=False, use_temporal=True, use_community=True
            ),
            'w/o Temporal': TemporalLocalizer(
                dep_graph=dep_graph, cve_embedder=embedder,
                node_cve_scores=node_cve_scores, timestamps=timestamps,
                node_texts=node_texts,
                use_vector_search=True, use_temporal=False, use_community=True
            ),
            'w/o Community': TemporalLocalizer(
                dep_graph=dep_graph, cve_embedder=embedder,
                node_cve_scores=node_cve_scores, timestamps=timestamps,
                node_texts=node_texts,
                use_vector_search=True, use_temporal=True, use_community=False
            ),
        }

    all_algorithms = {**algorithms, **ablation_algorithms}

    # Run evaluation
    all_results = {}
    for algo_name, algo in all_algorithms.items():
        print(f"\n{'='*60}")
        print(f" {algo_name} ".center(60, '='))
        print(f"{'='*60}")

        results = evaluate_algorithm(
            algo, gt_to_eval, algo_name,
            graph=dep_graph,
            package_index=package_index,
            timestamps=timestamps,
            cve_meta=cve_meta,
            embedder=embedder,
        )
        all_results[algo_name] = results

        m = results['metrics']
        print(f"  Success:      {m['success']:4d}/{m['total']} ({m['success_rate']:.1%})")
        print(f"  Exact match:  {m['exact_match']:4d}/{m['total']} ({m['exact_match_rate']:.1%})")
        print(f"  Within 1 ver: {m['within_1_version']:4d}/{m['total']} ({m['within_1_rate']:.1%})")
        print(f"  Within 3 ver: {m['within_3_versions']:4d}/{m['total']} ({m['within_3_rate']:.1%})")
        if 'mean_version_distance' in m:
            print(f"  Mean dist:    {m['mean_version_distance']:.2f}")

    # Comparison table
    print(f"\n{'='*70}")
    print(f"{'Algorithm':<25} {'Success':>8} {'Exact':>8} {'±1 Ver':>8} {'±3 Ver':>8} {'Mean Dist':>10}")
    print(f"{'-'*25} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*10}")
    for name, res in all_results.items():
        m = res['metrics']
        print(f"{name:<25} {m['success_rate']:.1%}{'':<3} {m['exact_match_rate']:.1%}{'':<3} "
              f"{m['within_1_rate']:.1%}{'':<3} {m['within_3_rate']:.1%}{'':<3} "
              f"{m.get('mean_version_distance', 0):.2f}")

    # Save
    serializable = {}
    for name, res in all_results.items():
        serializable[name] = {
            'metrics': res['metrics'],
            'num_results': len(res['results']),
        }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(serializable, f, indent=2)
    print(f"\n✓ Results saved to {args.output}")


if __name__ == '__main__':
    main()