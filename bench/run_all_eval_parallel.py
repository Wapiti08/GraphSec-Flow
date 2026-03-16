"""
Memory-Efficient Parallel Evaluation Pipeline for GraphSec-Flow
================================================================

Constraints:
  - 64 CPUs
  - 500 GB RAM hard limit
  - No nested process pools

Architecture:
  - ONE pool at a time (never nested)
  - Light algorithms: Pool(64), workers are stateless, rebuild per call (~ms)
  - Heavy algorithms: Pool(N_HEAVY_WORKERS), workers use initializer to build
    Vamana index ONCE, then process many samples through that single index
  - All read-only data shared via Linux fork() COW

Usage:
    python bench/run_all_eval_parallel.py \
        --gt data/gt_temporal_fixed.jsonl \
        --dep-graph data/dep_graph_cve.pkl \
        --cve-meta data/cve_records_for_meta.pkl \
        --node-texts data/nodeid_to_texts.pkl \
        --node-scores data/node_cve_scores.pkl \
        --output-dir results/ \
        --cpus 64 \
        --mem-limit-gb 500
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pickle
import argparse
import os
import time
import multiprocessing as mp
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from functools import partial

# ============================================================================
# Reuse core metric functions from the original pipeline
# ============================================================================

from run_all_eval import (
    normalize_version_string,
    semver_tuple,
    _fuzzy_find_in_sequence,
    compute_version_distance_fixed,
    normalize_prediction,
    build_package_index,
    compute_single_metrics,
    aggregate_metrics,
)


# ============================================================================
# Global state for worker processes (set via Pool initializer)
# ============================================================================

# These globals are populated by _init_light_worker / _init_heavy_worker.
# After fork(), read-only parent data (graph, timestamps, etc.) is shared
# via COW. Only the algorithm object is built fresh per worker.

_worker_algorithm = None      # Algorithm instance (built in initializer)
_worker_graph_data = None     # Reference to shared graph data dict
_worker_package_index = None  # Reference to shared package index
_worker_timestamps = None     # Reference to shared timestamps
_worker_cve_desc_cache = None # Reference to shared CVE desc cache
_worker_algo_name = None      # Algorithm name string


def _init_light_worker(algo_name, algo_config, graph_data,
                       package_index, timestamps, cve_desc_cache):
    """
    Initializer for lightweight algorithm workers.

    Called ONCE when each Pool worker process starts. Builds the algorithm
    object and stores references to shared data in process-global variables.

    For lightweight algorithms (Naive, PageRank, etc.), the algorithm
    object is tiny (~KB) and builds in milliseconds.

    Memory cost per worker: ~0.5 GB (mostly COW page table overhead).
    """
    global _worker_algorithm, _worker_graph_data, _worker_package_index
    global _worker_timestamps, _worker_cve_desc_cache, _worker_algo_name

    _worker_algo_name = algo_name
    _worker_graph_data = graph_data
    _worker_package_index = package_index
    _worker_timestamps = timestamps
    _worker_cve_desc_cache = cve_desc_cache

    _worker_algorithm = _rebuild_algorithm(algo_config, graph_data)


def _init_heavy_worker(algo_name, algo_config, graph_data,
                       package_index, timestamps, cve_desc_cache):
    """
    Initializer for heavy algorithm workers.

    Same as _init_light_worker, but TemporalLocalizer construction is
    expensive: it builds the Vamana ANN index and loads CVEVector embeddings.

    This runs ONCE per worker process. After initialization, the worker
    processes many samples using the same algorithm instance — amortizing
    the ~5-8 GB / ~seconds construction cost across all assigned samples.

    Memory cost per worker: ~6 GB (CVEVector ~1-2 GB + Vamana index ~2-4 GB
                                    + COW overhead ~0.5 GB).
    """
    global _worker_algorithm, _worker_graph_data, _worker_package_index
    global _worker_timestamps, _worker_cve_desc_cache, _worker_algo_name

    _worker_algo_name = algo_name
    _worker_graph_data = graph_data
    _worker_package_index = package_index
    _worker_timestamps = timestamps
    _worker_cve_desc_cache = cve_desc_cache

    pid = os.getpid()
    print(f"    [Worker {pid}] Building {algo_name}...", flush=True)
    t0 = time.perf_counter()
    _worker_algorithm = _rebuild_algorithm(algo_config, graph_data)
    elapsed = time.perf_counter() - t0
    print(f"    [Worker {pid}] Ready in {elapsed:.1f}s", flush=True)


# ============================================================================
# Algorithm reconstruction (runs inside worker processes)
# ============================================================================

def _rebuild_algorithm(algo_config: dict, graph_data: dict):
    """
    Reconstruct an algorithm object from a config dict.

    Called inside worker processes. The config dict is tiny and pickle-friendly.
    The graph_data dict references objects shared via fork() COW.
    """
    algo_type = algo_config['type']

    if algo_type == 'naive':
        from src.temp_localize import NaiveBaselineLocalizer
        return NaiveBaselineLocalizer(graph_data['graph'])

    elif algo_type == 'conservative':
        from src.temp_localize import ConservativeBaselineLocalizer
        return ConservativeBaselineLocalizer(
            graph_data['graph'],
            n_versions_back=algo_config.get('n_back', 3)
        )

    elif algo_type == 'pagerank':
        from bench.baseline_localizers import PageRankLocalizer
        return PageRankLocalizer(graph_data['graph'])

    elif algo_type == 'betweenness':
        from bench.baseline_localizers import BetweennessLocalizer
        return BetweennessLocalizer(graph_data['graph'])

    elif algo_type == 'temporal_pagerank':
        from bench.baseline_localizers import TemporalPageRankLocalizer
        return TemporalPageRankLocalizer(graph_data['graph'])

    elif algo_type == 'community_only':
        from bench.baseline_localizers import CommunityOnlyLocalizer
        return CommunityOnlyLocalizer(graph_data['graph'])

    elif algo_type == 'temporal_localizer':
        from src.temp_localize import TemporalLocalizer
        from cve.cvevector import CVEVector
        # Force CPU: GPU only has ~12 GB, each SecureBERT copy takes ~684 MiB.
        # With 64 workers that would need ~43 GB GPU memory.
        # CPU inference is fine here — embedding is not the bottleneck.
        embedder = CVEVector(device='cpu')
        return TemporalLocalizer(
            dep_graph=graph_data['graph'],
            cve_embedder=embedder,
            node_cve_scores=graph_data['node_cve_scores'],
            timestamps=graph_data['timestamps'],
            node_texts=graph_data['node_texts'],
            **algo_config.get('kwargs', {})
        )

    raise ValueError(f"Unknown algorithm type: {algo_type}")


# ============================================================================
# Worker task functions (use global state set by initializer)
# ============================================================================

def _worker_eval_sample(task):
    """
    Evaluate one GT sample using the pre-initialized worker algorithm.

    This function is called by Pool.imap_unordered. It uses the global
    _worker_algorithm that was built once in the initializer — no
    per-sample reconstruction overhead.

    Args:
        task: tuple of (index, gt_entry)

    Returns:
        dict with evaluation results for this sample
    """
    i, gt_entry = task

    cve_id = gt_entry['cve_id']
    package = gt_entry['package']
    cve_description = _worker_cve_desc_cache.get(cve_id, '')

    algo = _worker_algorithm
    algo_name = _worker_algo_name

    # Run localization
    try:
        if hasattr(algo, 'localize_origin'):
            if 'TemporalLocalizer' in algo_name or 'w/o' in algo_name:
                pred = algo.localize_origin(
                    cve_id=cve_id,
                    cve_description=cve_description,
                    discovered_version=gt_entry.get('discovered_version'),
                    k=15
                )
            else:
                pred = algo.localize_origin(
                    cve_id=cve_id,
                    package=package,
                    discovered_version=gt_entry.get('discovered_version')
                )
        else:
            pred = {'origin_version': None, 'method': 'error'}
    except Exception as e:
        pred = {'origin_version': None, 'method': 'error', 'error': str(e)}

    # Lightweight normalization (no full graph needed)
    pred = _normalize_pred_lightweight(pred, _worker_graph_data.get('node_releases', {}))

    # Compute metrics
    metrics = compute_single_metrics(
        gt_entry, pred,
        graph=None,
        package_index=_worker_package_index,
        timestamps=_worker_timestamps,
    )

    return {
        'index': i,
        'cve_id': cve_id,
        'package': package,
        'gt_origin': gt_entry['origin_version'],
        'pred_origin': pred.get('origin_version'),
        'gt_discovered': gt_entry.get('discovered_version'),
        'gt_version_sequence': gt_entry.get('version_sequence', []),
        'metrics': metrics,
        'prediction': pred,
    }


def _normalize_pred_lightweight(pred: dict, node_releases: dict) -> dict:
    """
    Normalize prediction without requiring the full graph.
    Converts node_id to package@version using a pre-extracted dict.
    """
    origin = pred.get('origin_version')
    if not origin:
        return pred
    origin = str(origin)
    if '@' in origin:
        return pred

    release = node_releases.get(origin, '')
    if release:
        parts = release.split(':')
        if len(parts) >= 3:
            simple_pkg = parts[1].split('-')[0] if '-' in parts[1] else parts[1]
            version = parts[2]
            pred['origin_version'] = f"{simple_pkg}@{version}"
            pred['_original_node_id'] = origin
    return pred


# ============================================================================
# Single-algorithm evaluation using Pool + initializer
# ============================================================================

def evaluate_one_algorithm(
    algo_name: str,
    algo_config: dict,
    ground_truth: List[dict],
    graph_data: dict,
    package_index: dict,
    timestamps: dict,
    cve_desc_cache: dict,
    n_workers: int,
) -> dict:
    """
    Evaluate one algorithm against all GT entries using a worker pool.

    Creates a Pool with the appropriate initializer:
      - Light algorithms: 64 workers, cheap init (~ms each)
      - Heavy algorithms: fewer workers, expensive init (~seconds each)

    Each worker builds the algorithm ONCE in its initializer, then processes
    many samples via imap_unordered. The pool is destroyed after evaluation,
    freeing all worker memory before the next algorithm starts.

    Args:
        algo_name: display name for logging
        algo_config: config dict (type + kwargs)
        ground_truth: list of GT entries
        graph_data: shared data dict (COW via fork)
        package_index: package -> version entries
        timestamps: node -> timestamp
        cve_desc_cache: cve_id -> description
        n_workers: number of pool workers

    Returns:
        dict with 'results', 'predictions', 'metrics' keys
    """
    n_samples = len(ground_truth)
    is_heavy = algo_config['type'] == 'temporal_localizer'
    init_fn = _init_heavy_worker if is_heavy else _init_light_worker

    print(f"\n  {algo_name}")
    print(f"    Samples: {n_samples}, Workers: {n_workers}, "
          f"Type: {'heavy' if is_heavy else 'light'}")

    t0 = time.perf_counter()

    # Prepare task list: (index, gt_entry)
    tasks = list(enumerate(ground_truth))

    # Use imap_unordered for best throughput with progress tracking.
    # chunksize controls how many tasks are sent to a worker at once.
    # Larger chunksize = less IPC overhead, but less balanced load.
    chunksize = max(1, n_samples // (n_workers * 4))

    results = []

    # The pool is created and destroyed within this function.
    # After pool.join(), all worker processes are terminated and their
    # memory (including Vamana indexes) is freed by the OS.
    with mp.Pool(
        processes=n_workers,
        initializer=init_fn,
        initargs=(algo_name, algo_config, graph_data,
                  package_index, timestamps, cve_desc_cache),
    ) as pool:
        done = 0
        for result in pool.imap_unordered(_worker_eval_sample, tasks,
                                          chunksize=chunksize):
            results.append(result)
            done += 1
            if done % 200 == 0 or done == n_samples:
                elapsed_so_far = time.perf_counter() - t0
                rate = done / elapsed_so_far if elapsed_so_far > 0 else 0
                eta = (n_samples - done) / rate if rate > 0 else 0
                print(f"    Progress: {done}/{n_samples} "
                      f"({rate:.1f} samples/s, ETA {eta:.0f}s)", flush=True)

    # pool.__exit__ calls terminate + join → workers freed

    # Restore original order
    results.sort(key=lambda r: r['index'])

    elapsed = time.perf_counter() - t0
    print(f"    Finished in {elapsed:.1f}s "
          f"({n_samples / elapsed:.1f} samples/s)")

    return {
        'results': results,
        'predictions': [r.get('prediction', {}) for r in results],
        'metrics': aggregate_metrics(results),
    }


# ============================================================================
# Data preparation
# ============================================================================

def prepare_shared_graph_data(dep_graph, node_cve_scores, timestamps, node_texts):
    """
    Package data for fork() COW sharing.

    The dep_graph, node_cve_scores, timestamps, and node_texts are all
    read-only during evaluation. On Linux fork(), child processes share
    the parent's memory pages until they write — which never happens
    for these structures. Net memory cost: ~0 per worker.

    We also pre-extract node_releases so normalization doesn't need
    the full graph object.
    """
    node_releases = {}
    for nid in dep_graph.nodes():
        nd = dep_graph.nodes[nid]
        release = nd.get('release', '')
        if release:
            node_releases[nid] = release

    return {
        'graph': dep_graph,
        'node_cve_scores': node_cve_scores,
        'timestamps': timestamps,
        'node_texts': node_texts,
        'node_releases': node_releases,
    }


def build_cve_desc_cache(cve_meta) -> dict:
    """
    Build CVE ID -> description lookup once in parent process.
    Shared with workers via fork() COW (read-only, never copied).
    """
    cache = {}
    if not isinstance(cve_meta, dict):
        return cache

    for _nid, recs in cve_meta.items():
        if not isinstance(recs, list):
            recs = [recs]
        for rec in recs:
            if not isinstance(rec, dict):
                continue
            bp = rec.get('builder_payload', {})
            if not isinstance(bp, dict):
                continue
            for alias in bp.get('aliases', []):
                if isinstance(alias, str) and alias.startswith('CVE-'):
                    desc = (bp.get('details') or bp.get('summary')
                            or bp.get('description') or '')
                    if desc and alias not in cache:
                        cache[alias] = desc

    return cache


def estimate_memory_usage(dep_graph, n_light_workers, n_heavy_workers):
    """
    Estimate peak memory usage and print a budget summary.

    Returns estimated peak in GB.
    """
    import sys as _sys

    # Rough graph size estimate (nodes × ~2KB average)
    n_nodes = dep_graph.number_of_nodes()
    graph_gb = n_nodes * 2048 / (1024 ** 3)

    parent_gb = graph_gb + 2.0  # graph + metadata + scores + index

    # COW overhead: ~0.5 GB per worker for page tables, stack, etc.
    light_per_worker_gb = 0.5
    # Heavy workers: CVEVector (~1-2 GB) + Vamana index (~2-4 GB) + COW
    heavy_per_worker_gb = 6.0

    peak_light = parent_gb + n_light_workers * light_per_worker_gb
    peak_heavy = parent_gb + n_heavy_workers * heavy_per_worker_gb
    peak = max(peak_light, peak_heavy)

    print(f"\n  Memory budget estimate:")
    print(f"    Parent process:        ~{parent_gb:.1f} GB")
    print(f"    Graph nodes:           {n_nodes:,}")
    print(f"    Light phase ({n_light_workers} workers): ~{peak_light:.0f} GB peak")
    print(f"    Heavy phase ({n_heavy_workers} workers): ~{peak_heavy:.0f} GB peak")
    print(f"    Estimated peak:        ~{peak:.0f} GB")

    return peak


# ============================================================================
# Main pipeline
# ============================================================================

class ParallelEvaluationPipeline:
    """
    Memory-efficient parallel evaluation pipeline.

    Key differences from the previous version:
    1. ONE pool at a time — never nested ProcessPoolExecutors
    2. Pool initializer builds algorithm ONCE per worker (not per sample)
    3. Pool is destroyed between algorithms → memory freed between phases
    4. Explicit memory budget with configurable worker counts
    """

    def __init__(self, gt_path, dep_graph_path, cve_meta_path,
                 node_texts_path, node_scores_path, output_dir,
                 n_cpus=64, mem_limit_gb=500):
        self.gt_path = gt_path
        self.dep_graph_path = dep_graph_path
        self.cve_meta_path = cve_meta_path
        self.node_texts_path = node_texts_path
        self.node_scores_path = node_scores_path
        self.output_dir = Path(output_dir)
        self.n_cpus = n_cpus
        self.mem_limit_gb = mem_limit_gb

        # Worker allocation:
        # Light algorithms are cheap → use all CPUs
        # Heavy algorithms need ~6 GB each → limit count
        self.n_light_workers = n_cpus
        self.n_heavy_workers = min(
            n_cpus,
            max(4, int((mem_limit_gb - 30) / 6))  # 30 GB reserved for parent
        )

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_dir = self.output_dir / 'checkpoints'
        self.checkpoint_dir.mkdir(exist_ok=True)

        print(f"\n{'=' * 70}")
        print(" MEMORY-EFFICIENT PARALLEL EVALUATION ".center(70, '='))
        print(f"{'=' * 70}")
        print(f"  CPUs:              {n_cpus}")
        print(f"  Memory limit:      {mem_limit_gb} GB")
        print(f"  Light workers:     {self.n_light_workers}")
        print(f"  Heavy workers:     {self.n_heavy_workers}")
        print(f"  Output:            {self.output_dir}")
        print(f"  Start:             {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 70}")

    # ── Checkpoint helpers ──────────────────────────────────────────────

    @staticmethod
    def _algo_to_filename(algo_name: str) -> str:
        """Convert algorithm name to a safe filename.
        'TemporalLocalizer (Full)' -> 'temporallocalizer_full'
        'w/o Vector Search'        -> 'wo_vector_search'
        """
        s = algo_name.lower()
        s = s.replace('/', '_').replace('\\', '_')
        s = s.replace('(', '').replace(')', '')
        s = s.replace(' ', '_')
        # collapse multiple underscores
        while '__' in s:
            s = s.replace('__', '_')
        return s.strip('_')

    def _checkpoint_path(self, algo_name: str) -> Path:
        return self.checkpoint_dir / f"{self._algo_to_filename(algo_name)}.pkl"

    def _save_checkpoint(self, algo_name: str, result: dict):
        """Save one algorithm's result to disk immediately after completion."""
        path = self._checkpoint_path(algo_name)
        # Write to a temp file first, then rename — atomic on Linux.
        # Prevents corrupted checkpoints if killed mid-write.
        tmp_path = path.with_suffix('.tmp')
        with open(tmp_path, 'wb') as f:
            pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
        tmp_path.rename(path)
        print(f"    Checkpoint saved: {path.name}")

    def _load_checkpoint(self, algo_name: str) -> Optional[dict]:
        """Load a previously saved checkpoint. Returns None if not found."""
        path = self._checkpoint_path(algo_name)
        if not path.exists():
            return None
        try:
            with open(path, 'rb') as f:
                result = pickle.load(f)
            # Basic sanity check
            if 'metrics' in result and 'results' in result:
                return result
            print(f"    WARNING: Corrupt checkpoint {path.name}, re-running")
            return None
        except Exception as e:
            print(f"    WARNING: Failed to load {path.name}: {e}, re-running")
            return None

    def _list_checkpoints(self) -> List[str]:
        """List algorithm names that have valid checkpoints."""
        cached = []
        for p in self.checkpoint_dir.glob('*.pkl'):
            try:
                with open(p, 'rb') as f:
                    result = pickle.load(f)
                if 'metrics' in result and 'results' in result:
                    cached.append(p.stem)
            except Exception:
                pass
        return cached

    # ── Data loading ────────────────────────────────────────────────────

    def _load_data(self):
        """Load all data files into parent process memory."""
        print("\nLoading data files...")

        with open(self.dep_graph_path, 'rb') as f:
            dep_graph = pickle.load(f)
        print(f"  Dependency graph: {dep_graph.number_of_nodes():,} nodes, "
              f"{dep_graph.number_of_edges():,} edges")

        with open(self.cve_meta_path, 'rb') as f:
            cve_meta = pickle.load(f)
        print(f"  CVE metadata:     {len(cve_meta):,} entries")

        with open(self.node_texts_path, 'rb') as f:
            node_texts = pickle.load(f)
        print(f"  Node texts:       {len(node_texts):,} entries")

        with open(self.node_scores_path, 'rb') as f:
            node_cve_scores = pickle.load(f)
        print(f"  Node CVE scores:  {len(node_cve_scores):,} entries")

        timestamps = {n: dep_graph.nodes[n].get('timestamp', 0)
                      for n in dep_graph.nodes()}

        package_index = build_package_index(dep_graph)
        print(f"  Package index:    {len(package_index):,} packages")

        return dep_graph, cve_meta, node_texts, node_cve_scores, timestamps, package_index

    def _load_ground_truth(self) -> List[dict]:
        """Load GT from JSONL."""
        gt = []
        with open(self.gt_path, 'r') as f:
            for line in f:
                if line.strip():
                    gt.append(json.loads(line.strip()))

        has_seq = sum(1 for e in gt if e.get('version_sequence'))
        print(f"  Ground truth:     {len(gt)} entries "
              f"({has_seq} with version_sequence)")
        return gt

    def run_all(self, max_samples=None, force=False):
        t_total = time.perf_counter()

        # Clear checkpoints if --force
        if force:
            for p in self.checkpoint_dir.glob('*.pkl'):
                p.unlink()
            print("  Cleared all checkpoints (--force)")

        # Show existing checkpoints
        existing = list(self.checkpoint_dir.glob('*.pkl'))
        if existing and not force:
            print(f"\n  Found {len(existing)} cached results in {self.checkpoint_dir}/")
            for p in sorted(existing):
                print(f"    ✓ {p.stem}")
            print(f"  These will be loaded instead of re-computed.")
            print(f"  Use --force to re-run everything from scratch.\n")

        # ── Step 1: Load data into parent process ──
        print(f"\n{'=' * 70}")
        print(" STEP 1: LOAD DATA ".center(70, '='))
        print(f"{'=' * 70}")

        (dep_graph, cve_meta, node_texts,
         node_cve_scores, timestamps, package_index) = self._load_data()

        graph_data = prepare_shared_graph_data(
            dep_graph, node_cve_scores, timestamps, node_texts)
        cve_desc_cache = build_cve_desc_cache(cve_meta)
        print(f"  CVE desc cache:   {len(cve_desc_cache):,} entries")

        # Memory estimate
        estimate_memory_usage(
            dep_graph, self.n_light_workers, self.n_heavy_workers)

        gt = self._load_ground_truth()
        gt_eval = gt[:max_samples] if max_samples else gt
        print(f"  Evaluating:       {len(gt_eval)} samples")

        # ── Step 2: Define algorithms ──
        # Configs are tiny dicts — no large objects, fully pickle-safe
        light_algorithms = {
            'Naive (Earliest)':         {'type': 'naive'},
            'Conservative (3-back)':    {'type': 'conservative', 'n_back': 3},
            'PageRank-based':           {'type': 'pagerank'},
            'Betweenness-based':        {'type': 'betweenness'},
            'Temporal PageRank':        {'type': 'temporal_pagerank'},
            'Community-only (Louvain)': {'type': 'community_only'},
        }

        heavy_algorithms = {
            'TemporalLocalizer (Full)': {
                'type': 'temporal_localizer',
                'kwargs': {'use_vector_search': True,
                           'use_temporal': True, 'use_community': True},
            },
            'w/o Vector Search': {
                'type': 'temporal_localizer',
                'kwargs': {'use_vector_search': False,
                           'use_temporal': True, 'use_community': True},
            },
            'w/o Temporal': {
                'type': 'temporal_localizer',
                'kwargs': {'use_vector_search': True,
                           'use_temporal': False, 'use_community': True},
            },
            'w/o Community': {
                'type': 'temporal_localizer',
                'kwargs': {'use_vector_search': True,
                           'use_temporal': True, 'use_community': False},
            },
        }

        all_results = {}

        # ── Step 3: Phase 1 — Light algorithms ──
        # Each algorithm gets its own pool (created → used → destroyed).
        # Pool destruction frees all worker memory before the next pool.
        print(f"\n{'=' * 70}")
        print(" STEP 2: LIGHT ALGORITHMS (one pool per algorithm) ".center(70, '='))
        print(f"{'=' * 70}")

        for algo_name, algo_config in light_algorithms.items():
            cached = self._load_checkpoint(algo_name)
            if cached is not None:
                print(f"\n  {algo_name} — CACHED (skipping)")
                all_results[algo_name] = cached
                self._print_brief_metrics(algo_name, cached['metrics'])
                continue

            result = evaluate_one_algorithm(
                algo_name, algo_config, gt_eval,
                graph_data, package_index, timestamps, cve_desc_cache,
                n_workers=self.n_light_workers,
            )
            all_results[algo_name] = result
            self._save_checkpoint(algo_name, result)
            self._print_brief_metrics(algo_name, result['metrics'])

        # ── Step 4: Phase 2 — Heavy algorithms ──
        # Each gets its own pool with fewer workers. Pool is destroyed
        # after each algorithm, so Vamana indexes from algorithm A are
        # fully freed before algorithm B starts.
        print(f"\n{'=' * 70}")
        print(" STEP 3: HEAVY ALGORITHMS (one pool per algorithm) ".center(70, '='))
        print(f"{'=' * 70}")

        for algo_name, algo_config in heavy_algorithms.items():
            cached = self._load_checkpoint(algo_name)
            if cached is not None:
                print(f"\n  {algo_name} — CACHED (skipping)")
                all_results[algo_name] = cached
                self._print_brief_metrics(algo_name, cached['metrics'])
                continue

            result = evaluate_one_algorithm(
                algo_name, algo_config, gt_eval,
                graph_data, package_index, timestamps, cve_desc_cache,
                n_workers=self.n_heavy_workers,
            )
            all_results[algo_name] = result
            self._save_checkpoint(algo_name, result)
            self._print_brief_metrics(algo_name, result['metrics'])

        # ── Step 5: Results ──
        print(f"\n{'=' * 70}")
        print(" RESULTS ".center(70, '='))
        print(f"{'=' * 70}")
        self._print_comparison_table(all_results)
        self._save_results(all_results)

        elapsed = time.perf_counter() - t_total
        print(f"\n  Total wall time: {elapsed:.1f}s ({elapsed / 60:.1f} min)")
        print(f"  End: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def _print_brief_metrics(self, name, m):
        print(f"    → Exact: {m['exact_match_rate']:.1%}, "
              f"±1: {m['within_1_rate']:.1%}, "
              f"±3: {m['within_3_rate']:.1%}")

    def _print_comparison_table(self, all_results):
        header = (f"  {'Algorithm':<28} {'Success':>8} {'Exact':>8} "
                  f"{'+-1':>6} {'+-3':>6} {'MeanDist':>9}")
        print(header)
        print(f"  {'-' * 67}")
        for name, res in all_results.items():
            m = res['metrics']
            print(f"  {name:<28} {m['success_rate']:>7.1%} "
                  f"{m['exact_match_rate']:>7.1%} "
                  f"{m['within_1_rate']:>5.1%} "
                  f"{m['within_3_rate']:>5.1%} "
                  f"{m.get('mean_version_distance', 0):>8.2f}")

    def _save_results(self, all_results):
        # Summary
        summary = {}
        for name, res in all_results.items():
            summary[name] = {
                'metrics': res['metrics'],
                'num_results': len(res.get('results', [])),
            }
        path = self.output_dir / 'main_results.json'
        with open(path, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"\n  Summary:  {path}")

        # Detailed per-sample
        detail = {}
        for name, res in all_results.items():
            detail[name] = [
                {
                    'cve_id': r.get('cve_id'),
                    'package': r.get('package'),
                    'gt_origin': r.get('gt_origin'),
                    'pred_origin': r.get('pred_origin'),
                    'metrics': r.get('metrics'),
                }
                for r in res.get('results', [])
            ]
        path = self.output_dir / 'detailed_results.json'
        with open(path, 'w') as f:
            json.dump(detail, f, indent=2)
        print(f"  Detailed: {path}")


# ============================================================================
# Entry point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Memory-efficient parallel evaluation for GraphSec-Flow"
    )
    parser.add_argument('--gt', required=True,
                        help="Ground truth JSONL file")
    parser.add_argument('--dep-graph', required=True,
                        help="Dependency graph pickle")
    parser.add_argument('--cve-meta', required=True,
                        help="CVE metadata pickle")
    parser.add_argument('--node-texts', required=True,
                        help="Node texts pickle")
    parser.add_argument('--node-scores', required=True,
                        help="Node CVE scores pickle")
    parser.add_argument('--output-dir', required=True,
                        help="Output directory")
    parser.add_argument('--cpus', type=int, default=64,
                        help="Number of CPUs to use (default: 64)")
    parser.add_argument('--mem-limit-gb', type=int, default=500,
                        help="Memory limit in GB (default: 500)")
    parser.add_argument('--max-samples', type=int, default=None,
                        help="Limit GT samples (for testing)")
    parser.add_argument('--force', action='store_true',
                        help="Ignore checkpoints, re-run all algorithms")

    args = parser.parse_args()

    # CRITICAL: fork() enables copy-on-write memory sharing on Linux.
    # All read-only data (graph, timestamps, scores, texts, cve_desc_cache)
    # is shared at zero cost. Only algorithm objects built in workers
    # consume new memory.
    mp.set_start_method('fork', force=True)

    pipeline = ParallelEvaluationPipeline(
        gt_path=args.gt,
        dep_graph_path=args.dep_graph,
        cve_meta_path=args.cve_meta,
        node_texts_path=args.node_texts,
        node_scores_path=args.node_scores,
        output_dir=args.output_dir,
        n_cpus=args.cpus,
        mem_limit_gb=args.mem_limit_gb,
    )
    pipeline.run_all(max_samples=args.max_samples, force=args.force)


if __name__ == "__main__":
    main()