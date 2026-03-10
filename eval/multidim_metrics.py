"""
Multi-Dimensional Evaluation Metrics for Temporal Localization

Implements additional metrics beyond basic version distance:
1. Temporal Accuracy (time-based metrics)
2. Practical Utility (code review effort, confidence calibration)
3. Robustness (performance across CVE types, time lags)

Usage:
    from multidim_metrics import MultiDimEvaluator
    
    evaluator = MultiDimEvaluator(ground_truth, predictions, timestamps)
    metrics = evaluator.compute_all_metrics()

"""

from typing import Dict, List, Optional
from collections import defaultdict
import numpy as np

class MultiDimEvaluator:
    """
    Compute multi-dimensional metrics for temporal localization
    """

    def __init__(
        self,
        ground_truth: List[Dict],
        predictions: List[Dict],
        timestamps: Dict[str, float],
        cve_severities: Optional[Dict[str, str]] = None
    ):
        """
        Args:
            ground_truth: List of GT entries
            predictions: List of predictions
            timestamps: {version_str: timestamp} mapping
            cve_severities: {cve_id: severity} mapping
        """
        self.ground_truth = ground_truth
        self.predictions = predictions
        self.timestamps = timestamps
        self.cve_severities = cve_severities or {}

    