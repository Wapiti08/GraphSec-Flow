"""
Benchmark Framework for Temporal Root Cause Localization

Evaluates localization algorithms on ground truth data.

Usage:
    python benchmark_temporal.py \
        --gt data/gt_temporal.jsonl \
        --dep-graph data/dep_graph_cve.pkl \
        --cve-meta data/cve_records_for_meta.pkl \
        --node-texts data/nodeid_to_texts.pkl \
        --node-scores data/node_cve_scores.pkl \
        --output results/temporal_results.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pickle
import argparse
from collections import defaultdict
from typing import Dict, List, Optional
import time

# import localization algorithms
from src.temp_localize import (
    TemporalLocalizer,
    NaiveBaselineLocalizer,
    ConservativeBaselineLocalizer
)

from cve.cvevector import CVEVector
from ground.helper import SemVer

class TemporalLocalizationBenchmark:
    """
    Benchmark framework for temporal localization
    
    Evaluates:
    - Version distance accuracy
    - Time estimation error
    - Confidence calibration
    - Performance (latency)
    """
    
    class TemporalLocalizationBenchmark:
    """
    Benchmark framework for temporal localization
    
    Evaluates:
    - Version distance accuracy
    - Time estimation error
    - Confidence calibration
    - Performance (latency)
    """
    
    def __init__(
        self,
        ground_truth_path: str,
        dep_graph,
        cve_meta,
        node_texts,
        node_cve_scores,
        timestamps
    ):
        """
        Args:
            ground_truth_path: Path to GT JSONL file
            dep_graph: NetworkX graph
            cve_meta: CVE metadata dict
            node_texts: Node texts for vector search
            node_cve_scores: Node CVE scores
            timestamps: Node timestamps
        """
        self.gt_path = ground_truth_path
        self.graph = dep_graph
        self.cve_meta = cve_meta
        self.node_texts = node_texts
        self.node_cve_scores = node_cve_scores
        self.timestamps = timestamps
        
        # Load ground truth
        self.ground_truth = self._load_ground_truth()
        
        # Initialize algorithms
        self.embedder = CVEVector()
        
        self.algorithms = {
            'TemporalLocalizer': TemporalLocalizer(
                dep_graph=dep_graph,
                cve_embedder=self.embedder,
                node_cve_scores=node_cve_scores,
                timestamps=timestamps,
                node_texts=node_texts
            ),
            'NaiveBaseline': NaiveBaselineLocalizer(dep_graph),
            'ConservativeBaseline': ConservativeBaselineLocalizer(dep_graph, n_versions_back=3)
        }