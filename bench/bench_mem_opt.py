"""
MEMORY-OPTIMIZED VERSION - Batch Processing
Controls memory under 1TB by processing windows in batches

Key Changes:
1. Process windows in batches of 20 (instead of all 223 at once)
2. With 64 workers, max memory = 64 × 20GB = 1.28TB → reduced to 400GB
3. Adds progress tracking for each batch
"""
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import numpy as np
from multiprocessing import Pool, cpu_count
import time
from collections import defaultdict

from eval.evaluation import _rank_metrics, _zscore, _lead_time
from bench.helper import avg


# ============================================================================
# EventMatcher (unchanged)
# ============================================================================

class EventMatcher:
    """Batch-process event matching using vectorized operations."""
    
    def __init__(self, events, window_size_ms):
        print("[EventMatcher] Building event index...")
        for event in events:
            if event["t"] < 1e11:
                event["t"] *= 1000.0
        
        self.sorted_events = sorted(events, key=lambda e: e["t"])
        self.timestamps = np.array([e["t"] for e in self.sorted_events], dtype=np.float64)
        self.window_size_ms = window_size_ms
        print(f"[EventMatcher] Indexed {len(events)} events")
    
    def batch_match(self, t_eval_list):
        t_eval_array = np.array(t_eval_list, dtype=np.float64)
        indices = np.searchsorted(self.timestamps, t_eval_array)
        
        matches = []
        for i, idx in enumerate(indices):
            best_event = None
            best_distance = float('inf')
            
            for check_idx in range(max(0, idx - 1), min(len(self.sorted_events), idx + 2)):
                distance = abs(self.timestamps[check_idx] - t_eval_array[i])
                if distance < self.window_size_ms and distance < best_distance:
                    best_distance = distance
                    best_event = self.sorted_events[check_idx]
            
            matches.append(best_event)
        
        return matches


# ============================================================================
# Worker functions (unchanged from formatted version)
# ============================================================================

def process_single_window_community(args):
    """Process a single window for community benchmark."""
    (window_idx, t_s, t_e, t_eval, depgraph, tempcent,
     node_cve_scores, gt_root_set, event_match) = args
    
    try:
        start_time = time.perf_counter()
        
        from com.commdet import TemporalCommDetector
        
        tcd = TemporalCommDetector(
            dep_graph=depgraph,
            timestamps={n: depgraph.nodes[n]['timestamp'] for n in depgraph.nodes()},
            cve_scores=node_cve_scores,
            centrality_provider=tempcent,
        )
        
        community_result = tcd.detect_communities(depgraph)
        best_community, centrality_scores = tcd.choose_root_community(
            community_result.comm_to_nodes, t_s, t_e
        )
        
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        
        if not community_result or best_community is None:
            return {
                'window_idx': window_idx,
                'latency': latency_ms,
                'metrics': None
            }
        
        community_nodes = set(community_result.comm_to_nodes[best_community])
        normalized_scores = _zscore(centrality_scores)
        
        # Only keep top 100
        top_k = 100
        sorted_items = sorted(normalized_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        
        lead_time_data = {
            't_eval': t_eval,
            'top_scores': dict(sorted_items)
        }
        
        metrics = {
            'mrr': None,
            'h3': None,
            'hit_list': [],
            'coverage_list': [],
            'purity_list': [],
            'root_ranks': [],
            'lead_time_data': lead_time_data
        }
        
        if event_match:
            mrr, h3 = _rank_metrics(normalized_scores, event_match["targets"])
            metrics['mrr'] = mrr
            metrics['h3'] = h3
        
        sorted_centrality_nodes = None
        
        for root_id in gt_root_set:
            if root_id not in depgraph:
                continue
            
            metrics['hit_list'].append(1.0 if root_id in community_nodes else 0.0)
            
            root_neighborhood = set(depgraph.neighbors(root_id)) | {root_id}
            overlap = len(root_neighborhood & community_nodes)
            coverage = overlap / len(root_neighborhood) if root_neighborhood else 0.0
            metrics['coverage_list'].append(coverage)
            
            purity = overlap / len(community_nodes) if community_nodes else 0.0
            metrics['purity_list'].append(purity)
            
            if root_id in centrality_scores:
                if sorted_centrality_nodes is None:
                    sorted_centrality_nodes = sorted(
                        centrality_scores,
                        key=lambda x: centrality_scores[x],
                        reverse=True
                    )
                
                rank = sorted_centrality_nodes.index(root_id) + 1
                metrics['root_ranks'].append(rank)
        
        return {
            'window_idx': window_idx,
            'latency': latency_ms,
            'metrics': metrics
        }
    
    except Exception as e:
        print(f"[ERROR] Window {window_idx} failed: {e}")
        import traceback
        traceback.print_exc()
        
        return {
            'window_idx': window_idx,
            'latency': 0,
            'metrics': None,
            'error': str(e)
        }


# ============================================================================
# MEMORY OPTIMIZATION: Batched Processing
# ============================================================================

def benchmark_community_parallel_batched(
    depgraph,
    tempcent,
    node_cve_scores,
    events,
    window_iter,
    gt_root_ids,
    window_size=10,
    n_workers=None,
    batch_size=20  # NEW PARAMETER: Process 20 windows at a time
):
    """
    Memory-optimized parallel community benchmark with batched processing.
    
    Memory Control:
        Instead of processing all 223 windows at once (223 × 20GB = 4.5TB),
        process in batches of 20 (20 × 20GB = 400GB max).
    
    Args:
        batch_size: Number of windows to process simultaneously (default: 20)
                   Lower value = less memory, but slightly slower
    
    Memory Usage:
        With batch_size=20, n_workers=64:
        - Max concurrent: min(20, 64) = 20 workers
        - Memory per worker: ~20GB (depgraph copy)
        - Total peak memory: 20 × 20GB = 400GB ✓ (under 1TB limit)
    """
    print("\n" + "="*70)
    print("[MEMORY-OPT] Community Benchmark - Batched Processing")
    print("="*70)
    
    if n_workers is None:
        n_workers = min(cpu_count(), 64)
    
    print(f"[MEMORY-OPT] Using {n_workers} workers")
    print(f"[MEMORY-OPT] Batch size: {batch_size} windows at a time")
    print(f"[MEMORY-OPT] Estimated peak memory: {batch_size * 20 / 1000:.1f} TB")
    
    gt_root_set = set(gt_root_ids)
    
    # Batch-match events
    print("[MEMORY-OPT] Step 1/4: Batch-matching events...")
    window_size_ms = window_size * 86400000.0
    event_matcher = EventMatcher(events, window_size_ms)
    
    windows = list(window_iter())
    t_eval_list = [t_eval for _, _, t_eval in windows]
    
    print(f"[MEMORY-OPT] Total windows: {len(windows)}")
    print(f"[MEMORY-OPT] Batches: {(len(windows) + batch_size - 1) // batch_size}")
    
    event_matches = event_matcher.batch_match(t_eval_list)
    print(f"[MEMORY-OPT] Matched {sum(1 for e in event_matches if e)} events")
    
    # Aggregate results across all batches
    all_latencies = []
    all_mrr_values = []
    all_h3_values = []
    all_hit_list = []
    all_coverage_list = []
    all_purity_list = []
    all_root_rank_list = []
    all_lead_time_data_list = []
    failed_count = 0
    
    total_start_time = time.time()
    
    # Process windows in batches
    num_batches = (len(windows) + batch_size - 1) // batch_size
    
    for batch_idx in range(num_batches):
        batch_start = batch_idx * batch_size
        batch_end = min((batch_idx + 1) * batch_size, len(windows))
        batch_windows = windows[batch_start:batch_end]
        
        print(f"\n[MEMORY-OPT] ========================================")
        print(f"[MEMORY-OPT] Processing Batch {batch_idx + 1}/{num_batches}")
        print(f"[MEMORY-OPT] Windows {batch_start}-{batch_end-1} ({len(batch_windows)} windows)")
        print(f"[MEMORY-OPT] ========================================")
        
        # Prepare worker arguments for this batch only
        worker_args = [
            (batch_start + idx, t_s, t_e, t_eval, depgraph, tempcent,
             node_cve_scores, gt_root_set, event_matches[batch_start + idx])
            for idx, (t_s, t_e, t_eval) in enumerate(batch_windows)
        ]
        
        batch_start_time = time.time()
        
        # Process this batch in parallel
        # Effective workers = min(batch_size, n_workers)
        effective_workers = min(len(batch_windows), n_workers)
        print(f"[MEMORY-OPT] Using {effective_workers} workers for this batch")
        
        with Pool(processes=effective_workers) as pool:
            batch_results = pool.map(process_single_window_community, worker_args)
        
        batch_elapsed = time.time() - batch_start_time
        print(f"[MEMORY-OPT] Batch {batch_idx + 1} completed in {batch_elapsed:.1f}s")
        print(f"[MEMORY-OPT] Average: {batch_elapsed/len(batch_windows):.2f}s per window")
        
        # Aggregate results from this batch
        for result in batch_results:
            if result.get('error'):
                failed_count += 1
                print(f"[WARNING] Window {result['window_idx']} failed: {result['error']}")
                continue
            
            if result['metrics'] is None:
                continue
            
            all_latencies.append(result['latency'])
            m = result['metrics']
            
            if m['mrr'] is not None:
                all_mrr_values.append(m['mrr'])
            if m['h3'] is not None:
                all_h3_values.append(m['h3'])
            
            all_hit_list.extend(m['hit_list'])
            all_coverage_list.extend(m['coverage_list'])
            all_purity_list.extend(m['purity_list'])
            all_root_rank_list.extend(m['root_ranks'])
            
            if 'lead_time_data' in m:
                all_lead_time_data_list.append(
                    (m['lead_time_data']['t_eval'], m['lead_time_data']['top_scores'])
                )
        
        # Progress update
        total_elapsed = time.time() - total_start_time
        windows_done = batch_end
        windows_remaining = len(windows) - windows_done
        avg_time_per_window = total_elapsed / windows_done
        estimated_remaining = avg_time_per_window * windows_remaining
        
        print(f"[MEMORY-OPT] Progress: {windows_done}/{len(windows)} windows")
        print(f"[MEMORY-OPT] Elapsed: {total_elapsed/60:.1f} min")
        print(f"[MEMORY-OPT] Estimated remaining: {estimated_remaining/60:.1f} min")
    
    # Final statistics
    total_elapsed = time.time() - total_start_time
    original_time = 280000
    speedup = original_time / total_elapsed if total_elapsed > 0 else 0
    
    print(f"\n[MEMORY-OPT] ========================================")
    print(f"[MEMORY-OPT] ALL BATCHES COMPLETED")
    print(f"[MEMORY-OPT] ========================================")
    print(f"[MEMORY-OPT] Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f} minutes)")
    print(f"[MEMORY-OPT] Average: {total_elapsed/len(windows):.2f}s per window")
    print(f"[MEMORY-OPT] Speedup: {speedup:.1f}x vs original")
    
    if failed_count > 0:
        print(f"[WARNING] {failed_count}/{len(windows)} windows failed")
    
    print(f"[MEMORY-OPT] Successfully processed {len(windows) - failed_count} windows")
    
    # Calculate lead time
    try:
        lead_time_days = _lead_time(all_lead_time_data_list, events, thresh=0.8)
    except Exception as e:
        print(f"[WARNING] Could not calculate lead time: {e}")
        lead_time_days = 0.0
    
    return {
        "Community": {
            "MRR": avg(all_mrr_values),
            "Hits@3": avg(all_h3_values),
            "LeadTime(days)": lead_time_days,
            "Latency(ms)": avg(all_latencies),
            "Hit-Root": avg(all_hit_list),
            "RootCoverage": avg(all_coverage_list),
            "RootPurity": avg(all_purity_list),
            "RootRankInComm": avg(all_root_rank_list),
        }
    }


# ============================================================================
# Centrality worker function (unchanged)
# ============================================================================

def process_single_window_centrality(args):
    """Process a single window for centrality benchmark."""
    (window_idx, t_s, t_e, t_eval, tempcent, variant_name,
     gt_root_set, event_match, k_precision) = args
    
    try:
        start_time = time.perf_counter()
        
        if variant_name == "Static-DC":
            from eval.evaluation import _pick_total
            raw_scores = _pick_total(tempcent.static_degree())
        elif variant_name == "Static-EVC":
            raw_scores = tempcent.static_eigen()
        elif variant_name == "Temporal-DC":
            raw_scores = tempcent.degree_centrality(t_s, t_e)
        elif variant_name == "Temporal-EVC":
            raw_scores = tempcent.eigenvector_centrality(t_s, t_e)
        else:
            raise ValueError(f"Unknown variant: {variant_name}")
        
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        normalized_scores = _zscore(raw_scores)
        
        top_k_for_lead_time = 100
        sorted_items = sorted(normalized_scores.items(), key=lambda x: x[1], reverse=True)[:top_k_for_lead_time]
        
        metrics = {
            'latency': latency_ms,
            'lead_time_data': {
                't_eval': t_eval,
                'top_scores': dict(sorted_items)
            },
            'mrr': None,
            'h3': None,
            'root_ranks': [],
            'precisions': [],
            'root_mrrs': []
        }
        
        if event_match:
            mrr, h3 = _rank_metrics(normalized_scores, event_match["targets"])
            metrics['mrr'] = mrr
            metrics['h3'] = h3
        
        sorted_nodes = sorted(normalized_scores.items(), key=lambda x: x[1], reverse=True)
        top_k = set(node for node, _ in sorted_nodes[:k_precision])
        node_to_rank = {node: idx + 1 for idx, (node, _) in enumerate(sorted_nodes)}
        
        for root_id in gt_root_set:
            if root_id in normalized_scores:
                rank = node_to_rank.get(root_id)
                if rank:
                    metrics['root_ranks'].append(rank)
                    metrics['precisions'].append(1.0 if root_id in top_k else 0.0)
                    root_mrr, _ = _rank_metrics(normalized_scores, {root_id})
                    metrics['root_mrrs'].append(root_mrr)
        
        return {
            'window_idx': window_idx,
            'variant': variant_name,
            'metrics': metrics
        }
    
    except Exception as e:
        print(f"[ERROR] Window {window_idx} ({variant_name}) failed: {e}")
        return None


def benchmark_centrality_parallel_batched(
    tempcent,
    events,
    window_iter,
    gt_root_ids,
    window_size=10,
    k_precision=5,
    n_workers=None,
    batch_size=20  # NEW PARAMETER
):
    """
    Memory-optimized parallel centrality benchmark with batched processing.
    """
    print("\n" + "="*70)
    print("[MEMORY-OPT] Centrality Benchmark - Batched Processing")
    print("="*70)
    
    if n_workers is None:
        n_workers = min(cpu_count(), 64)
    
    print(f"[MEMORY-OPT] Using {n_workers} workers")
    print(f"[MEMORY-OPT] Batch size: {batch_size} windows at a time")
    
    gt_root_set = set(gt_root_ids)
    
    window_size_ms = window_size * 86400000.0
    event_matcher = EventMatcher(events, window_size_ms)
    
    windows = list(window_iter())
    t_eval_list = [t_eval for _, _, t_eval in windows]
    event_matches = event_matcher.batch_match(t_eval_list)
    
    variants = ["Static-DC", "Static-EVC", "Temporal-DC", "Temporal-EVC"]
    results = {}
    
    for variant_name in variants:
        print(f"\n[MEMORY-OPT] Processing {variant_name}...")
        
        all_latencies = []
        all_mrr_values = []
        all_h3_values = []
        all_root_ranks = []
        all_precisions = []
        all_root_mrrs = []
        all_lead_time_data_list = []
        
        num_batches = (len(windows) + batch_size - 1) // batch_size
        
        for batch_idx in range(num_batches):
            batch_start = batch_idx * batch_size
            batch_end = min((batch_idx + 1) * batch_size, len(windows))
            batch_windows = windows[batch_start:batch_end]
            
            print(f"[MEMORY-OPT] {variant_name}: Batch {batch_idx + 1}/{num_batches} ({len(batch_windows)} windows)")
            
            worker_args = [
                (batch_start + idx, t_s, t_e, t_eval, tempcent, variant_name,
                 gt_root_set, event_matches[batch_start + idx], k_precision)
                for idx, (t_s, t_e, t_eval) in enumerate(batch_windows)
            ]
            
            effective_workers = min(len(batch_windows), n_workers)
            
            with Pool(processes=effective_workers) as pool:
                batch_results = pool.map(process_single_window_centrality, worker_args)
            
            # Aggregate batch results
            for result in batch_results:
                if result is None or result['metrics'] is None:
                    continue
                
                m = result['metrics']
                all_latencies.append(m['latency'])
                
                if m['mrr'] is not None:
                    all_mrr_values.append(m['mrr'])
                if m['h3'] is not None:
                    all_h3_values.append(m['h3'])
                
                all_root_ranks.extend(m['root_ranks'])
                all_precisions.extend(m['precisions'])
                all_root_mrrs.extend(m['root_mrrs'])
                
                if 'lead_time_data' in m:
                    all_lead_time_data_list.append(
                        (m['lead_time_data']['t_eval'], m['lead_time_data']['top_scores'])
                    )
        
        # Calculate final metrics for this variant
        try:
            lead_time_days = _lead_time(all_lead_time_data_list, events, thresh=0.8)
        except Exception as e:
            print(f"[WARNING] Could not calculate lead time for {variant_name}: {e}")
            lead_time_days = 0.0
        
        results[variant_name] = {
            "MRR": avg(all_mrr_values),
            "Hits@3": avg(all_h3_values),
            "LeadTime(days)": lead_time_days,
            "Latency(ms)": avg(all_latencies),
            "RootRank": avg(all_root_ranks),
            f"Precision@{k_precision}": avg(all_precisions),
            "RootMRR": avg(all_root_mrrs),
        }
        
        print(f"[MEMORY-OPT] {variant_name} completed")
        print(f"[MEMORY-OPT] Average latency: {results[variant_name]['Latency(ms)']:.2f}ms")
    
    return results