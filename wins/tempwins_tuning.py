'''
 # @ Create Time: 2025-10-01 11:54:00
 # @ Modified time: 2025-10-01 11:54:17
 # @ Description: data-driven recommendation of (window_size, step_size) for temporal
 network sliding-window centrality analysis
  
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from utils.helpers import _medium_dt, _autocorr_time, _fwhm_widths
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Callable
import numpy as np
import networkx as nx
from scipy.signal import find_peaks

@dataclass
class TimeScaleEstimate:
    tau_c: float            # autocorrelation half-decay, in index units or time units depending on input
    tau_chg: float          # typical change duration (FWHM median), same units as provided x
    grad_median: float      # median of |dC/dt|
    grad_mad: float         # Median Absolute Deviation - MAD of |dC/dt|


@dataclass
class Candidate:
    window_size: float
    step_size: float

@dataclass
class CandidateScore:
    candiate: Candidate
    stability_S: float
    sensitivity_C: float
    resolvability_R: float
    total_score: float

# ------------- connectivity lower bound -------------
def estimate_conn_lower_bound(
        G: nx.Graph,
        timestamps: np.ndarray,
        alpha: float = 0.8,
        coverage: float = 0.95,
        initial_w: Optional[float] = None,
        max_iters: int = 10
    ) -> float:
    ''' find minimal window size to achieve desired connectivity coverage.
    
    note:
    - induce the subgraph by filtering nodes with timestamp in [t, t+w)
    
    '''
    ts = np.asarray(timestamps, dtype=float)
    if ts.size < 2:
        return 1.0
    
    t_min, t_max = ts[0], ts[-1]
    dt_med = _medium_dt(ts)
    if not np.isfinite(dt_med) or dt_med <= 0:
        dt_med = max(1.0, (t_max - t_min) / max(10, ts.size))
    
    # starting guess
    w = initial_w if initial_w and initial_w > 0 else 5 * dt_med

    def ok(w_size: float) -> bool:
        if w_size <= 0:
            return False
        # slide with 50% overlap for probing
        step = w_size / 2
        t = t_min
        good, total = 0, 0
        while t < t_max:
            t_s, t_e = t, t + w_size
            # induce nodes
            nodes = [n for n, d in G.nodes(data=True)
                     if (d.get("timestamp", None) is not None) and (t_s <= float(d["timestamp"]) < t_e)]
            if len(nodes) >= 2:
                H = G.subgraph(nodes)
                if len(H) > 0:
                    gcc = max((len(c) for c in nx.connected_components(H)), default=0)
                    frac = gcc / max(1, len(H))
                    if frac >= alpha:
                        good += 1
                    total += 1
            t += step
        if total == 0:
            return False
        return (good / total) >= coverage
    
    # increase w until ok or reach iterations
    for _ in range(max_iters):
        if ok(w):
            return float(w)
        w += 1.5
    
    return float(w)
        

# ------------- pilot series & time scales -------------
def build_series_and_estimate_timescales(
      timestamps: np.ndarray,
      series_values: np.ndarray  
    ) -> TimeScaleEstimate:
    ''' given a time series (t, C(t)), estimate tau_c, tau_chg and gradient stats
    
    '''
    ts = np.asarray(timestamps, dtype=float)
    cs = np.asarray(series_values, dtype=float)

    if ts.size < 3:
        # minimal fallback
        return TimeScaleEstimate(
            tau_c=2.0,
            tau_chg=max(2.0, np.ptp(ts)/10 if ts.size>1 else 2.0),
            grad_median=0.0,
            grad_mad=0.0
        )

    # gradient wrt time
    dC = np.gradient(cs, ts)
    y = np.abs(dC)

    # autocorr time in index units -> convert to time using median step
    tau_c_idx = _autocorr_time(cs) 
    dt_med = _medium_dt(ts)
    tau_c = max(dt_med, tau_c_idx * dt_med)

    # peaks on |dC/dt|
    peaks, _ = find_peaks(y, prominence=np.median(y) + 2.0 * (np.median(np.abs(y - np.median(y))) + 1e-12))
    widths = _fwhm_widths(ts, y, peaks)
    tau_chg = np.median(widths) if len(widths) > 0 else 5.0 * dt_med

    # robust stats
    med = float(np.median(y))
    mad = float(np.median(np.abs(y - med)) + 1e-12)

    return TimeScaleEstimate(tau_c=float(max(dt_med, tau_c)),
                              tau_chg=float(max(dt_med, tau_chg)),
                              grad_median=med,
                              grad_mad=mad)

# ------------- scoring candidates -------------
def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 or b.size == 0:
        return 0.0
    na = np.linalg.norm(a)
    nb = np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))

def score_candidate(
        candidates: List[Candidate],
        centrality_vectors: List[np.ndarray],
        timestamps: List[float],
        beta: float = 1.0
    ) -> List[CandidateScore]:
    '''
    
    '''