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

    def compute_all_metrics(self) -> Dict[str, float]:
        """
        Compute all metrics and return as a dictionary

        Returns:
            {
                'temporal_accuracy': {...},
                'practical_utility': {...},
                'robustness': {...}
            }
        """
        return {
            'temporal_accuracy': self.compute_temporal_accuracy(),
            'practical_utility': self.compute_practical_utility(),
            'robustness': self.compute_robustness()
        }
    
    # ========================================================================
    # 1. Temporal Accuracy Metrics
    # ========================================================================

    def compute_temporal_accuracy(self) -> Dict:
        """
        Time-based accuracy metrics
        
        Returns:
            {
                'time_error_days_mean': float,
                'time_error_days_median': float,
                'temporal_precision_30d': float,
                'temporal_precision_90d': float,
            }
        """
        time_errors = []
        temporal_precision_30d = 0
        temporal_precision_90d = 0
        
        for gt_entry, pred in zip(self.ground_truth, self.predictions):
            if not pred.get('origin_version'):
                continue
            
            # Get timestamps
            gt_origin = gt_entry.get('origin_version')
            pred_origin = pred.get('origin_version')
            
            gt_ts = self._get_timestamp(gt_origin)
            pred_ts = self._get_timestamp(pred_origin)
            
            if gt_ts is None or pred_ts is None:
                continue
            
            # Time error in days
            time_error_days = abs(gt_ts - pred_ts) / (24 * 3600)
            time_errors.append(time_error_days)
            
            # Temporal precision (within N days)
            if time_error_days <= 30:
                temporal_precision_30d += 1
            if time_error_days <= 90:
                temporal_precision_90d += 1
        
        total = len(time_errors)
        
        return {
            'time_error_days_mean': np.mean(time_errors) if time_errors else 0,
            'time_error_days_median': np.median(time_errors) if time_errors else 0,
            'temporal_precision_30d': temporal_precision_30d / total if total > 0 else 0,
            'temporal_precision_90d': temporal_precision_90d / total if total > 0 else 0,
            'num_samples': total
        }
    
    # ========================================================================
    # 2. Practical Utility Metrics
    # ========================================================================
    
    def compute_practical_utility(self) -> Dict:
        """
        Practical utility metrics
        
        Returns:
            {
                'avg_review_effort_versions': float,
                'high_conf_accuracy': float,
                'calibration_error': float,
            }
        """
        review_efforts = []
        high_conf_predictions = []
        
        for gt_entry, pred in zip(self.ground_truth, self.predictions):
            if not pred.get('origin_version'):
                continue
            
            # Review effort: number of versions to review
            version_seq = gt_entry.get('version_sequence', [])
            gt_origin = gt_entry.get('origin_version', '').split('@')[-1]
            pred_origin = pred.get('origin_version', '').split('@')[-1]
            
            effort = self._count_versions_between(
                version_seq, pred_origin, gt_origin
            )
            if effort is not None:
                review_efforts.append(effort)
            
            # High confidence predictions
            confidence = pred.get('confidence', 0)
            if confidence >= 0.8:
                # Check if correct
                is_correct = (pred.get('origin_version') == gt_entry.get('origin_version'))
                high_conf_predictions.append(is_correct)
        
        # Calibration error
        calibration_error = self._compute_calibration_error()
        
        return {
            'avg_review_effort_versions': np.mean(review_efforts) if review_efforts else 0,
            'median_review_effort_versions': np.median(review_efforts) if review_efforts else 0,
            'high_conf_accuracy': np.mean(high_conf_predictions) if high_conf_predictions else 0,
            'high_conf_count': len(high_conf_predictions),
            'calibration_error': calibration_error
        }
    
    # ========================================================================
    # 3. Robustness Metrics
    # ========================================================================

    def compute_robustness(self) -> Dict:
        """
        Robustness across different conditions
        
        Returns:
            {
                'by_severity': {...},
                'by_time_lag': {...},
            }
        """
        # Group by severity
        by_severity = self._group_by_severity()
        
        # Group by time lag
        by_time_lag = self._group_by_time_lag()
        
        return {
            'by_severity': by_severity,
            'by_time_lag': by_time_lag
        }
    
    def _group_by_severity(self) -> Dict:
        """Group accuracy by CVE severity"""
        severity_groups = defaultdict(list)
        
        for gt_entry, pred in zip(self.ground_truth, self.predictions):
            cve_id = gt_entry.get('cve_id')
            severity = self.cve_severities.get(cve_id, 'UNKNOWN')
            
            is_correct = (
                pred.get('origin_version') == gt_entry.get('origin_version')
            )
            severity_groups[severity].append(is_correct)
        
        return {
            severity: {
                'accuracy': np.mean(results) if results else 0,
                'count': len(results)
            }
            for severity, results in severity_groups.items()
        }
    
    def _group_by_time_lag(self) -> Dict:
        """Group accuracy by time lag between origin and discovery"""
        lag_groups = {
            'short (<30d)': [],
            'medium (30-180d)': [],
            'long (180-365d)': [],
            'very_long (>365d)': []
        }
        
        for gt_entry, pred in zip(self.ground_truth, self.predictions):
            # Get time lag
            time_lag_days = gt_entry.get('time_lag_days', 0)
            
            is_correct = (
                pred.get('origin_version') == gt_entry.get('origin_version')
            )
            
            if time_lag_days < 30:
                lag_groups['short (<30d)'].append(is_correct)
            elif time_lag_days < 180:
                lag_groups['medium (30-180d)'].append(is_correct)
            elif time_lag_days < 365:
                lag_groups['long (180-365d)'].append(is_correct)
            else:
                lag_groups['very_long (>365d)'].append(is_correct)
        
        return {
            lag: {
                'accuracy': np.mean(results) if results else 0,
                'count': len(results)
            }
            for lag, results in lag_groups.items()
        }
    
    # ========================================================================
    # Helper Methods
    # ========================================================================
    
    def _get_timestamp(self, version_str: str) -> Optional[float]:
        """Get timestamp for a version string"""
        if not version_str:
            return None
        return self.timestamps.get(version_str)
    
    def _count_versions_between(
        self, 
        version_seq: List[str], 
        pred_ver: str, 
        gt_ver: str
    ) -> Optional[int]:
        """Count versions between prediction and ground truth"""
        if not version_seq:
            return None
        
        try:
            pred_idx = version_seq.index(pred_ver)
            gt_idx = version_seq.index(gt_ver)
            return abs(pred_idx - gt_idx)
        except ValueError:
            return None
    
    def _compute_calibration_error(self) -> float:
        """
        Compute calibration error (ECE - Expected Calibration Error)
        
        How well does predicted confidence match actual accuracy?
        """
        confidence_buckets = defaultdict(list)
        
        for gt_entry, pred in zip(self.ground_truth, self.predictions):
            confidence = pred.get('confidence', 0)
            if confidence == 0:
                continue
            
            # Bucket by confidence (0.1 intervals)
            bucket = int(confidence * 10) / 10
            
            is_correct = (
                pred.get('origin_version') == gt_entry.get('origin_version')
            )
            confidence_buckets[bucket].append(is_correct)
        
        # Compute calibration error
        calibration_errors = []
        
        for bucket, results in confidence_buckets.items():
            if not results:
                continue
            
            actual_accuracy = np.mean(results)
            predicted_conf = bucket
            
            error = abs(predicted_conf - actual_accuracy)
            calibration_errors.append(error)
        
        return np.mean(calibration_errors) if calibration_errors else 0


def print_multidim_metrics(metrics: Dict, method_name: str = "Method"):
    """
    Pretty print multi-dimensional metrics
    
    Args:
        metrics: Output from MultiDimEvaluator.compute_all_metrics()
        method_name: Name of the method being evaluated
    """
    print(f"\n{'='*70}")
    print(f" MULTI-DIMENSIONAL METRICS: {method_name} ".center(70, "="))
    print(f"{'='*70}\n")
    
    # Temporal Accuracy
    print("TEMPORAL ACCURACY:")
    temp = metrics['temporal_accuracy']
    print(f"  Time Error (mean):     {temp['time_error_days_mean']:.1f} days")
    print(f"  Time Error (median):   {temp['time_error_days_median']:.1f} days")
    print(f"  Temporal Prec @30d:    {temp['temporal_precision_30d']:.1%}")
    print(f"  Temporal Prec @90d:    {temp['temporal_precision_90d']:.1%}")
    print()
    
    # Practical Utility
    print("PRACTICAL UTILITY:")
    util = metrics['practical_utility']
    print(f"  Avg Review Effort:     {util['avg_review_effort_versions']:.1f} versions")
    print(f"  Median Review Effort:  {util['median_review_effort_versions']:.1f} versions")
    print(f"  High Conf Accuracy:    {util['high_conf_accuracy']:.1%} ({util['high_conf_count']} samples)")
    print(f"  Calibration Error:     {util['calibration_error']:.3f}")
    print()
    
    # Robustness
    print("ROBUSTNESS:")
    robust = metrics['robustness']
    
    if robust['by_severity']:
        print("  By Severity:")
        for severity, stats in robust['by_severity'].items():
            print(f"    {severity:12s}: {stats['accuracy']:.1%} ({stats['count']} samples)")
    
    if robust['by_time_lag']:
        print("  By Time Lag:")
        for lag, stats in robust['by_time_lag'].items():
            print(f"    {lag:20s}: {stats['accuracy']:.1%} ({stats['count']} samples)")
    
    print()