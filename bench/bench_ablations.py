"""
benchmark_ablations.py

Separate module for ablation variants - keeps benchmark.py clean!

This module:
1. Reuses EventMatcher from benchmark_memory_optimized.py
2. Reuses batched processing pattern (20 windows/batch)
3. Reuses multiprocessing infrastructure (64 workers)
4. Keeps memory < 1TB
5. Returns same metric format as main benchmarks

Usage:
    from bench.benchmark_ablations import benchmark_all_ablations
    
    ablations = benchmark_all_ablations(
        depgraph, tempcent, node_cve_scores, nodeid_to_texts,
        events, window_iter, gt_root_ids, gt_paths_by_root,
        n_workers=64, batch_size=20
    )
    
    # Result:
    # {
    #   "w/o Vector Search": {MRR: ..., Hit-Root: ..., ...},
    #   "w/o Temporal": {MRR: ..., Hit-Root: ..., ...},
    #   ...
    # }

"""

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import time
import numpy as np
from multiprocessing import Pool, cpu_count
from collections import defaultdict
from datetime import datetime
from bench.bench_mem_opt import EventMatcher
# Import evaluation utilities
from eval.evaluation import _zscore, _rank_metrics, _lead_time
from bench.helper import avg, _safe_node_timestamps, build_root_to_nodepaths, path_f1_partial_match, _edge_coverage

# Import core components
from com.commdet import TemporalCommDetector
from src.path_track import PathConfig, RootCausePathAnalyzer
from search.vamana import VamanaSearch, CVEVector, VamanaOnCVE

# ============================================================================
# WORKER FUNCTION: Process single window with feature flags
# ============================================================================

def process_ablation_window(args):
    """
    Worker function for ablation variants.
    
    This is the core processing unit that gets parallelized.
    Similar to process_single_window_community but with ablation flags.
    
    Args:
        args: Tuple containing:
            - window_idx: Index of this window
            - t_s, t_e, t_eval: Time window boundaries
            - depgraph: Dependency graph (shared, read-only)
            - tempcent: Centrality provider (shared, read-only)
            - node_cve_scores: CVE scores dict (shared, read-only)
            - nodeid_to_texts: Text data for Vamana (shared, read-only)
            - gt_root_set: Ground truth roots (shared, read-only)
            - event_match: Pre-matched event for this window
            - use_vector_search: Flag to enable/disable Vamana
            - use_temporal: Flag to enable/disable temporal subgraphs
            - use_cve_scores: Flag to enable/disable CVE scoring
            - use_community: Flag to enable/disable community detection
    
    Returns:
        dict: {
            'window_idx': int,
            'latency': float (ms),
            'metrics': {
                'mrr': float,
                'h3': float,
                'hit_list': list,
                'coverage_list': list,
                'purity_list': list,
                'root_ranks': list,
                'path_count': int,
                'lead_time_data': dict,
            }
        }
    """
    (window_idx, t_s, t_e, t_eval, depgraph, tempcent,
     node_cve_scores, nodeid_to_texts, gt_root_set, event_match,
     use_vector_search, use_temporal, use_cve_scores, use_community) = args
    
    try:
        start_time = time.perf_counter()

        # ================================================================
        # STEP 1: Community Detection (conditional based on flag)
        # ================================================================

        if use_community:
            # Standard community detection
            timestamps = {n: depgraph.nodes[n]['timestamp'] for n in depgraph.nodes()}
            
            # Use CVE scores only if flag is set
            cve_scores = node_cve_scores if use_cve_scores else {n: 0.0 for n in depgraph.nodes()}
            
            tcd = TemporalCommDetector(
                dep_graph=depgraph,
                timestamps=timestamps,
                cve_scores=cve_scores,
                centrality_provider=tempcent,
            )
            
            community_result = tcd.detect_communities(depgraph)
            best_community, centrality_scores = tcd.choose_root_community(
                community_result.comm_to_nodes, t_s, t_e
            )
            
            if best_community is None:
                return {
                    'window_idx': window_idx,
                    'latency': (time.perf_counter() - start_time) * 1000.0,
                    'metrics': None
                }
            
            comm_nodes = set(community_result.comm_to_nodes[best_community])

        else:
            # w/o Community: Use ALL nodes with CVEs
            comm_nodes = set(
                n for n, d in depgraph.nodes(data=True)
                if d.get('has_cve') or d.get('cve_count', 0) > 0
            )
            
            if not comm_nodes:
                return {
                    'window_idx': window_idx,
                    'latency': (time.perf_counter() - start_time) * 1000.0,
                    'metrics': None
                }
            
            # Compute centrality based on temporal flag
            if use_temporal:
                centrality_scores = tempcent.eigenvector_centrality(t_s, t_e)
                if isinstance(centrality_scores, tuple):
                    centrality_scores = centrality_scores[0]
            else:
                centrality_scores = tempcent.static_eigen()
            
    
        # ================================================================
        # STEP 2: Root Selection (always use max centrality)
        # ================================================================
                
        predicted_root = max(comm_nodes, key=lambda n: centrality_scores.get(n, 0.0))


        # ================================================================
        # STEP 3: Path Analysis (conditional based on vector search flag)
        # ================================================================

        paths_by_target = {}

        if use_vector_search:
            # standard vamana-based path analysis
            try:
                embedder = CVEVector()
                ann = VamanaSearch()
                vamana = VamanaOnCVE(depgraph, nodeid_to_texts, embedder, ann)
                
                timestamps = {n: depgraph.nodes[n]['timestamp'] for n in depgraph.nodes()}
                
                analyzer = RootCausePathAnalyzer(
                    depgraph=depgraph,
                    vamana=vamana,
                    node_cve_scores=node_cve_scores if use_cve_scores else {n: 0.0 for n in depgraph.nodes()},
                    timestamps=timestamps,
                    centrality=tempcent,
                    search_scope='auto',
                )

                pcfg = PathConfig(
                    t_start=t_s if use_temporal else 0,
                    t_end=t_e if use_temporal else float('inf'),
                    strict_increase=False,
                    alpha=1.0, beta=0.0, gamma=0.0,
                    k_paths=5,
                    targets=None,
                    similarity_scores=None,
                )

                _, _, _, paths_by_target, _ = analyzer.analyze_with_paths(
                    k_neighbors=15,
                    t_start=pcfg.t_start,
                    t_end=pcfg.t_end,
                    path_cfg=pcfg,
                    explain=False,
                    source=predicted_root,
                )
            
            except Exception as e:
                # If Vamana fails, fall back to empty paths
                print(f"[WARNING] Window {window_idx}: Vamana failed ({e}), using empty paths")
                paths_by_target = {}

        else:
            # w/o Vector Search: Use random neighbors + simple BFS
            import networkx as nx
            import random

            # select random neighbors instead of vamana similarity
            all_nodes = list(depgraph.nodes())
            k_random = min(15, len(all_nodes))
            random_neighbors = random.sample(all_nodes, k_random)

            # Find simple paths from predicted_root to random neighbors
            for target in random_neighbors:
                if target == predicted_root:
                    continue

                try:
                    # Use NetworkX to find all simple paths (limited length)
                    all_paths = list(nx.all_simple_paths(
                        depgraph,
                        source=predicted_root,
                        target=target,
                        cutoff=10  # Limit path length to avoid explosion
                    ))
                    
                    # Take top 5 shortest paths
                    all_paths.sort(key=len)
                    paths_by_target[target] = all_paths[:5]
                    
                except nx.NetworkXNoPath:
                    paths_by_target[target] = []
                except Exception as e:
                    # Handle node not in graph, etc.
                    paths_by_target[target] = []
        
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # ================================================================
        # STEP 4: Compute Metrics
        # ================================================================

        # Path metrics
        predicted_paths = [p for ps in paths_by_target.values() for p in ps]
        path_count = len(predicted_paths)

        # Root localization metrics
        hit_list, coverage_list, purity_list, root_ranks = [], [], [], []

        for rid in gt_root_set:
            if rid not in depgraph:
                continue
            
            # Hit: Is GT root in predicted community?
            hit_list.append(1.0 if rid in comm_nodes else 0.0)

            # Coverage: Fraction of GT root's neighbors in predicted community
            neigh = set(depgraph.neighbors(rid)) | {rid}

            if len(neigh) > 0:
                coverage_list.append(len(neigh & comm_nodes) / len(neigh))

            # Purity: what faction of community is GT root's neighborhood
            if len(comm_nodes) > 0:
                purity_list.append(len(neigh & comm_nodes) / len(comm_nodes))
            
            # rank: position of GT root in centrality ranking
            if rid in centrality_scores:
                sorted_nodes = sorted(
                    centrality_scores,
                    key=lambda x: centrality_scores[x],
                    reverse=True
                )
                try:
                    rank = sorted_nodes.index(rid) + 1
                    root_ranks.append(rank)
                except ValueError:
                    # Node not in sorted list
                    pass
            

        # Event ranking metrics
        normalized_scores = _zscore(centrality_scores)
        mrr, h3 = None, None

        if event_match and event_match.get("targets"):
            try:
                mrr, h3 = _rank_metrics(normalized_scores, event_match["targets"])
            except Exception as e:
                # Event ranking failed
                pass

        # Prepare lead time data (for final aggregation)
        # Keep only top 100 scores to save memory
        top_scores = dict(sorted(
            normalized_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:100])
        
        return {
            'window_idx': window_idx,
            'latency': latency_ms,
            'metrics': {
                'mrr': mrr,
                'h3': h3,
                'hit_list': hit_list,
                'coverage_list': coverage_list,
                'purity_list': purity_list,
                'root_ranks': root_ranks,
                'path_count': path_count,
                'lead_time_data': {
                    't_eval': t_eval,
                    'top_scores': top_scores
                }
            }
        }
    
    except Exception as e:
        # Catch-all error handler
        import traceback
        print(f"[ERROR] Window {window_idx} failed: {e}")
        traceback.print_exc()
        
        return {
            'window_idx': window_idx,
            'error': str(e),
            'latency': 0,
            'metrics': None
        }

# ============================================================================
# MAIN ABLATION FUNCTION: Batched processing with memory control
# ============================================================================

def benchmark_ablation_variant(
    depgraph,
    tempcent,
    node_cve_scores,
    nodeid_to_texts,
    events,
    window_iter,
    gt_root_ids,
    gt_paths_by_root,
    variant_name,
    use_vector_search=True,
    use_temporal=True,
    use_cve_scores=True,
    use_community=True,
    n_workers=None,
    batch_size=20,
    window_size=10,
):
    """
    Benchmark a single ablation variant using batched processing.
    
    This function:
    1. Matches events in batch (reuses EventMatcher)
    2. Processes windows in batches of 20 (memory control)
    3. Uses multiprocessing pool (64 workers)
    4. Aggregates results progressively
    5. Returns same metrics as main benchmarks
    
    Args:
        depgraph: Dependency graph
        tempcent: Centrality provider
        node_cve_scores: CVE severity scores
        nodeid_to_texts: Text data for embeddings
        events: List of events for evaluation
        window_iter: Iterator yielding (t_s, t_e, t_eval) tuples
        gt_root_ids: Ground truth root node IDs
        gt_paths_by_root: Ground truth paths dict
        variant_name: Name of this ablation (e.g., "w/o Vector Search")
        use_vector_search: Whether to use Vamana ANN
        use_temporal: Whether to use temporal subgraphs
        use_cve_scores: Whether to use CVE severity scores
        use_community: Whether to use community detection
        n_workers: Number of parallel workers (default: 80% of CPU cores)
        batch_size: Windows per batch (default: 20 for memory control)
        window_size: Event matching window in days (default: 10)
    
    Returns:
        dict: {variant_name: {MRR: ..., Hit-Root: ..., Path-F1: ..., ...}}
    """

    print(f"\n{'='*70}")
    print(f"[ABLATION] {variant_name}")
    print(f"{'='*70}")
    print(f"[CONFIG] VectorSearch={use_vector_search}, Temporal={use_temporal}, "
          f"CVE={use_cve_scores}, Community={use_community}")
    
    # set worker count
    if n_workers is None:
        n_workers = min(int(cpu_count() * 0.8), 64) 

    print(f"[CONFIG] Workers={n_workers}, BatchSize={batch_size}")

    gt_root_set = set(gt_root_ids)

    # ========================================================================
    # PHASE 1: Batch-match events (reuse optimized infrastructure)
    # ========================================================================
    
    print(f"\n[PHASE 1/3] Batch-matching events...")
    window_size_ms = window_size * 86400000.0
    event_matcher = EventMatcher(events, window_size_ms)
    
    windows = list(window_iter())
    t_eval_list = [t_eval for _, _, t_eval in windows]
    event_matches = event_matcher.batch_match(t_eval_list)
    
    print(f"[INFO] Total windows: {len(windows)}")
    print(f"[INFO] Batches: {(len(windows) + batch_size - 1) // batch_size}")
    print(f"[INFO] Matched events: {sum(1 for e in event_matches if e)}/{len(event_matches)}")

    # ========================================================================
    # PHASE 2: Process windows in batches (memory control)
    # ========================================================================
    print(f"\n[PHASE 2/3] Processing windows in batches...")

    # result aggregators
    all_latencies = []
    all_mrr_values, all_h3_values = [], []
    all_hit_list, all_coverage_list, all_purity_list, all_root_rank_list = [], [], [], []
    all_path_counts = []
    all_lead_time_data_list = []
    failed_count = 0

    total_start_time = time.time()
    num_batches = (len(windows) + batch_size - 1) // batch_size
    
    for batch_idx in range(num_batches):
        batch_start = batch_idx * batch_size
        batch_end = min((batch_idx + 1) * batch_size, len(windows))
        batch_windows = windows[batch_start:batch_end]
        
        print(f"\n[BATCH {batch_idx + 1}/{num_batches}] "
              f"Windows {batch_start}-{batch_end-1} ({len(batch_windows)} windows)")

        # prepare worker arguments for this batch
        worker_args = [
            (batch_start + idx, t_s, t_e, t_eval, depgraph, tempcent,
             node_cve_scores, nodeid_to_texts, gt_root_set, event_matches[batch_start + idx],
             use_vector_search, use_temporal, use_cve_scores, use_community)
            for idx, (t_s, t_e, t_eval) in enumerate(batch_windows)
        ]

        batch_start_time = time.time()

        # Process this batch in parallel
        effective_workers = min(len(batch_windows), n_workers)
        
        with Pool(processes=effective_workers) as pool:
            batch_results = pool.map(process_ablation_window, worker_args)
        
        batch_elapsed = time.time() - batch_start_time
        print(f"[BATCH {batch_idx + 1}] Completed in {batch_elapsed:.1f}s "
              f"({batch_elapsed/len(batch_windows):.2f}s/window)")
        

        # aggregate results from this batch
        for result in batch_results:
            if result.get('error'):
                failed_count += 1
                print(f"[WARNING] Window {result['window_idx']} failed: {result['error']}")
                continue
            
            if result['metrics'] is None:
                continue

            all_latencies.append(result['latency'])
            m = result['metrics']

            # event metrics
            if m['mrr'] is not None:
                all_mrr_values.append(m['mrr'])
            if m['h3'] is not None:
                all_h3_values.append(m['h3'])

            # Root metrics
            all_hit_list.extend(m['hit_list'])
            all_coverage_list.extend(m['coverage_list'])
            all_purity_list.extend(m['purity_list'])
            all_root_rank_list.extend(m['root_ranks'])

            # Path metrics
            all_path_counts.append(m['path_count'])

            # Lead time data
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
        
        print(f"[PROGRESS] {windows_done}/{len(windows)} windows "
              f"({100*windows_done/len(windows):.1f}%)")
        print(f"[TIME] Elapsed: {total_elapsed/60:.1f}min, "
              f"Remaining: ~{estimated_remaining/60:.1f}min")
        
    # ========================================================================
    # PHASE 3: Calculate final metrics
    # ========================================================================
    
    print(f"\n[PHASE 3/3] Calculating final metrics...")

    total_elapsed = time.time() - total_start_time
    
    print(f"\n{'='*70}")
    print(f"[COMPLETED] {variant_name}")
    print(f"{'='*70}")
    print(f"[TIME] Total: {total_elapsed:.1f}s ({total_elapsed/60:.1f}min)")
    print(f"[TIME] Average: {total_elapsed/len(windows):.2f}s/window")
    
    if failed_count > 0:
        print(f"[WARNING] {failed_count}/{len(windows)} windows failed")
    
    print(f"[SUCCESS] {len(windows) - failed_count}/{len(windows)} windows processed")
    
    # Calculate lead time
    try:
        lead_time_days = _lead_time(all_lead_time_data_list, events, thresh=0.8)
    except Exception as e:
        print(f"[WARNING] Could not calculate lead time: {e}")
        lead_time_days = 0.0
    
    # Return results in same format as main benchmarks
    return {
        variant_name: {
            "MRR": avg(all_mrr_values),
            "Hits@3": avg(all_h3_values),
            "LeadTime(days)": lead_time_days,
            "Latency(ms)": avg(all_latencies),
            "Hit-Root": avg(all_hit_list),
            "RootCoverage": avg(all_coverage_list),
            "RootPurity": avg(all_purity_list),
            "RootRankInComm": avg(all_root_rank_list),
            "PredictedPathCount": avg(all_path_counts),
        }
    }

# ============================================================================
# CONVENIENCE FUNCTION: Run all ablations
# ============================================================================

def benchmark_all_ablations(
    depgraph, tempcent, node_cve_scores, nodeid_to_texts,
    events, window_iter, gt_root_ids, gt_paths_by_root,
    n_workers=None, batch_size=20, window_size=10
):
    """
    Run all 4 ablation variants.
    
    Returns:
        dict: {
            "w/o Vector Search": {...},
            "w/o Temporal": {...},
            "w/o CVE Score": {...},
            "w/o Community": {...},
        }
    """
    
    print("\n" + "="*70)
    print("ABLATION STUDY - Memory-Optimized Batched Processing")
    print("="*70)
    
    results = {}
    
    # Ablation 1: w/o Vector Search
    results.update(benchmark_ablation_variant(
        depgraph, tempcent, node_cve_scores, nodeid_to_texts,
        events, window_iter, gt_root_ids, gt_paths_by_root,
        variant_name="w/o Vector Search",
        use_vector_search=False,  # ❌ Disabled
        use_temporal=True,
        use_cve_scores=True,
        use_community=True,
        n_workers=n_workers,
        batch_size=batch_size,
        window_size=window_size,
    ))
    
    # Ablation 2: w/o Temporal
    results.update(benchmark_ablation_variant(
        depgraph, tempcent, node_cve_scores, nodeid_to_texts,
        events, window_iter, gt_root_ids, gt_paths_by_root,
        variant_name="w/o Temporal",
        use_vector_search=True,
        use_temporal=False,  # ❌ Disabled
        use_cve_scores=True,
        use_community=True,
        n_workers=n_workers,
        batch_size=batch_size,
        window_size=window_size,
    ))
    
    # Ablation 3: w/o CVE Score
    results.update(benchmark_ablation_variant(
        depgraph, tempcent, node_cve_scores, nodeid_to_texts,
        events, window_iter, gt_root_ids, gt_paths_by_root,
        variant_name="w/o CVE Score",
        use_vector_search=True,
        use_temporal=True,
        use_cve_scores=False,  # ❌ Disabled
        use_community=True,
        n_workers=n_workers,
        batch_size=batch_size,
        window_size=window_size,
    ))
    
    # Ablation 4: w/o Community
    results.update(benchmark_ablation_variant(
        depgraph, tempcent, node_cve_scores, nodeid_to_texts,
        events, window_iter, gt_root_ids, gt_paths_by_root,
        variant_name="w/o Community",
        use_vector_search=True,
        use_temporal=True,
        use_cve_scores=True,
        use_community=False,  # ❌ Disabled
        n_workers=n_workers,
        batch_size=batch_size,
        window_size=window_size,
    ))
    
    return results
