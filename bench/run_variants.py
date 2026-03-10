"""
run_variants.py

Orchestrator script for running specific benchmark variants.

This script:
1. Separates variant evaluation from main benchmark.py
2. Lets you choose which variants to run
3. Reuses all setup code from benchmark.py
4. Keeps memory < 1TB via batched processing

Usage:
    # Run only ablations
    python run_variants.py --variants ablations --ref-layer data/ref_paths_layer.jsonl
    
    # Run with custom batch size and workers
    python run_variants.py --variants ablations --batch-size 10 --workers 32
    
    # Run specific ablation
    python run_variants.py --variants ablations --ablation "w/o Vector Search"

"""

import json
import sys
import argparse
import time
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

# ============================================================================
# Import setup utilities from main benchmark.py
# ============================================================================
import pickle
import random
import os
import numpy as np
from datetime import datetime, timedelta
import pandas as pd
from multiprocessing import cpu_count

# Set random seeds for reproducibility
os.environ["PYTHONHASHSEED"] = "0"
random.seed(0)
np.random.seed(0)
try:
    import torch
    torch.manual_seed(0)
    torch.cuda.manual_seed_all(0)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
except ImportError:
    pass

# Import core components
from cent.temp_cent_fast import TempCentricityOptimized
from eval.events import build_events_from_vamana_meta
from eval.events import _first_cve_data_of_node, _last_cve_data_of_node, _to_same_type, _to_float_time
from bench.helper import _safe_node_timestamps
from utils.util import read_jsonl

# ============================================================================
# Import variant benchmarks
# ============================================================================

# Import the separated variant modules
from bench.bench_ablations import benchmark_all_ablations, benchmark_ablation_variant
from bench.benchmark import parse_ref_paths, load_ground_truth

# ============================================================================
# Main function
# ============================================================================


