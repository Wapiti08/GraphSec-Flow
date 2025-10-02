'''
 # @ Create Time: 2025-10-01 11:59:00
 # @ Modified time: 2025-10-01 11:59:02
 # @ Description: helper functions for temporal window selection
 '''

from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Callable
import numpy as np
import networkx as nx


def _medium_dt(timestamps: np.ndarray) -> float:
    ts = np.asarray(timestamps, dtype=float)
    if ts.size < 2:
        return np.inf
    # computes the difference between consecutive elements along a specified axis
    dts = np.diff(ts)
    return float(np.median(dts))

def _autocorr_time(x: np.ndarray) -> float:
    ''' rough e-folding or half-decay time using normalized autocorrelation.
    return lag (in index units) where autocorr first drops below 0.5.
    
    '''
    x = np.asarray(x, dtype=float)
    x = x - np.mean(x)
    if np.allclose(x, 0):
        return 1
    n = len(x)

    # FFT-based autocorr
    corr = np.correlate(x, x, mode='full')
    # normalized
    corr /= corr[0] if corr[0] != 0 else 1
    # find first lag where corr < 0.5
    for lag in range(1, len(corr)):
        if corr[lag] < 0.5:
            return float(lag)
    # if never drops below 0.5, return
    return float(max(1, n//4))

def _fwhm_widths(x: np.ndarray, y: np.ndarray, peaks: np.ndarray) -> List[float]:
    ''' approximate full-width at half-maximum for each peak in y.
    
    '''
    if len(peaks) == 0:
        return []
    widths = []
    for p in peaks:
        y0 = y[p]
        half = y0 / 2
        # left
        i = p
        while i > 0 and y[i] > half:
            i -= 1
        left_x = x[i]
        # right
        while j < len(y) - 1 and y[j] > half:
            j += 1
        right_x = x[j]
        widths.append(float(max(0.0, right_x - left_x)))
    
    return widths

# -------------- aggregator of individual nodes to global centrality scores --------------
def agg_network_influence(pr_scores: dict, method="topk_mean", k =5):
    # create a new 1-dimensional array from an iterable object
    vals = np.fromiter(pr_scores.values(), dtype=float)
    if vals.size == 0:
        return 0.0
    
    if method == "topk_mean":
        k = max(1, min(k, vals.size))
        # sort starts from smallest, so take the last k elements
        return float(np.mean(np.sort(vals)[-k:]))
    
    if method == "max":
        return float(np.max(vals))
    
    if method == "mean":
        return float(np.mean(vals))

    # demonstrate the centrality degree (larger -> more central)
    if method == "gini":
        x = np.sort(vals)
        n = x.size
        if n == 0: return 0.0
        # Return the cumulative sum
        cum = np.cumsum(x)
        gini = (n + 1 - 2 * np.sum(cum) / cum[-1]) / n if cum[-1] > 0 else 0.0
        return float(max(0.0, gini))

    # define entropy (larger --- most dispersed)
    if method == "entropy":
        p = vals / vals.sum() if vals.sum() > 0 else np.ones_like(vals) / vals.size
        h = -np.sum(p * np.log(p + 1e-10))  # add small constant to avoid log(0)
        return float(h)

    return ValueError(f"Unknown aggregation method: {method}")
