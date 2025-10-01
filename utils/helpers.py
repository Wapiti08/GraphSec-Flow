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

