'''
 # @ Create Time: 2024-09-19 15:12:43
 # @ Modified time: 2024-09-19 15:43:34
 # @ Description: modules to identity vulnerablity propagation paths

 
    Read an already ENRICHED dependency graph (augmented pickle) that contains
      node attrs: release, has_cve, cve_count, cve_list, timestamp (and any others)

    Then:
      - Build a temporal DiGraph using node 'timestamp'
      - Attach edge weights using time lag + optional centrality + optional node scores
      - Find up to K shortest temporal paths from a source to targets
      - Output results and optional GEXF subgraphs

    Inputs:
      --aug-graph  dep_graph_with_cves.pkl   (networkx or dict-like with 'nodes'/'edges')
      --source     node_id
      [--targets   node_id ...]              (optional; default: leaf nodes of temporal graph)
      [--similarity-json sim.json]           (optional; node_id -> similarity score, e.g. from Vamana)
      [--paths-jsonl paths.jsonl]            (optional; write path summaries JSONL)
      [--subgraph-gexf subgraph.gexf]        (optional; union-of-paths subgraph)
      [--tree-gexf tree.gexf]                (optional; arborescence rooted at source)

    We assume nodes ALREADY have:
      - release (str or None), has_cve (bool), cve_count (int), cve_list (list of dicts), timestamp (number)

    Weight model:
      weight(u->v) = alpha * time_lag(u,v) + beta * 1/(centrality[v]+eps) + gamma * 1/(score[v]+eps)
    Where score[v] comes from either:
      - provided similarity-json (node_id -> similarity), optionally blended with severity score
      - OR severity-derived score from node's cve_list/cve_count
      
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import argparse
import json
import pickle
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import networkx as nx
from utils.util import _safe_load_json, _safe_load_pickle, _safe_save_pickle
from utils.util import _detect_graph_nodes_and_edges, to_undirected_graph


# --------- build temporal graph ----------
def build_temporal_digraph(
        
    )




