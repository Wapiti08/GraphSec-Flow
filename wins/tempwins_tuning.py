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
from cent.helper import _build_time_index, _iter_windows, _node_in_window

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
    candidate: Candidate
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
                    # ignore the connection on direction
                    if H.is_directed():
                        comps = nx.weakly_connected_components(H)
                    else:
                        comps = nx.connected_components(H)
                    gcc = max((len(c) for c in comps), default=0)
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

def score_candidates(
        candidates: List[Candidate],
        centrality_vectors: List[np.ndarray],
        timestamps: List[float],
        beta: float = 1.0
    ) -> List[CandidateScore]:
    ''' Score stability (S), sensitivity (C), and resolvability (R).
    assume centrality_vectors are already computed for each candidate;
    each element is an array stacked over windows

    '''
    K = len(candidates)
    if K == 0:
        return []
    
    # 1） Stability S:  mean cosine similarity of successive
    S = np.zeros(K, dtype=float)
    for k in range(K):
        x = np.asarray(centrality_vectors[k], dtype=float)
        if x.size < 3:
            # there is no enough windows to compute stability
            S[k] = 0.0
        else:
            mu = np.mean(x)
            sd = np.std(x)
            # calculate Coefficient of Variation to measure stability
            cv = sd / (abs(mu) + 1e-12)
            S[k] = float(np.clip(1.0 - cv, 0.0, 1.0))

    # 2） Sensitivity C: number of peaks per unit time on |dC/dt| times average prominence proxy
    C = np.zeros(K, dtype=float)
    for k in range(K):
        t = np.asarray(timestamps[k], dtype=float)
        x = np.asarray(centrality_vectors[k], dtype=float)
        if x.size < 3:
            C[k]=0.0
            continue
        # measure the change rate
        d = np.gradient(x, t)
        med = np.median(d)
        # Measuring volatility
        mad = np.median(np.abs(d - med)) + 1e-12
        # measure peaks
        thr = med + 2.5*mad
        peaks, _ = find_peaks(d, prominence=thr)

        # check the density of peaks
        if t.size >= 2:
            span = t[-1] - t[0]
            density = len(peaks) / max(span, 1e-9)
        else:
            density = 0.0
        
        # prominence proxy
        prom_proxy = float(np.mean(d[d > thr])) if np.any(d<thr) else 0.0
        # normalize with tanh --- only when the change is frequent and also intensive
        C[k] = float(np.tanh(0.5 * density) * np.tanh(0.5 * prom_proxy / (mad if mad>0 else 1.0)))
    
    # 3) Resolvability R: proxy with number of windows and variation (not too low)
    R = np.zeros(K, dtype=float)
    for k in range(K):
        x = np.asarray(centrality_vectors[k], dtype=float)
        if x.size < 3:
            R[k] = 0.0
        else:
            # encourage enough windows but penelize extreme flatness
            nfac = np.tanh(len(x) / 20.0) # more data points, better identify patterns
            varfac = np.tanh(np.var(x) / (np.mean(x**2) + 1e-12))
            R[k] = float(0.6 * nfac + 0.4 * varfac)

    # harmonic trade-off between S and C, then multiply by R
    scores = []
    for k in range(K):
        if (beta**2 * S[k] + C[k]) == 0:
            f = 0.0
        else:
            f = ((1 + beta**2) * S[k] * C[k]) / (beta**2 * S[k] + C[k])
        total = float(f * R[k])
        scores.append(CandidateScore(candidate=candidates[k],
                                     stability_S=float(S[k]),
                                     sensitivity_C=float(C[k]),
                                     resolvability_R=float(R[k]),
                                     total_score=total))
    return scores


# ------------- top-level function -------------

def recommend_window_params(
        G: nx.Graph,
        build_series_fn: Callable[[float, float], Tuple[np.ndarray, np.ndarray]],
        N_min: int = 100,
        alpha: float = 0.8,
        coverage: float = 0.95,
        r_candidates: Tuple[float, ...] = [0.5, 0.65, 0.8],
        beta: float = 1.0,
        tau_min: Optional[float] = None,
        candidate_multipliers: Tuple[float, ...] = (0.5, 0.65, 0.8, 1.0),
    ) -> Dict[str, float]:
    '''
    Returns a dict including best window_size, step_size, and suggested
    distance/prominence parameters for TempWinSelect.

    args:
        G: input graph, every node needs to have timestamp attr
        build_series_fn: 
            given (win_size, step_size), computes a scalar
            aggregated centrality time series over sliding windows and returns
            (t_centers, series)
        N_min: the least number of nodes within one window
        alpha: to estimate connectivity lower bound
        coverage: use to estimate connectivity lower bound
        r_candidates: candidate window overlap rate
        beta: the parameter to adjust the weight of stability and sensitivity
    '''
    # collect timestamps
    ts_all = sorted(float(d.get("timestamp", 0)) for _, d in G.nodes(data=True) if d.get("timestamp", None) is not None)
    if len(ts_all) < 3:
        raise ValueError("Not enough timestamps on nodes to recommend parameters.")

    ts = np.asarray(ts_all, dtype=float)
    dt_med = _medium_dt(ts)
    # event rate
    lam = 1.0 / max(dt_med, 1e-9)

    # connectivity lower bound
    w_conn_min = estimate_conn_lower_bound(G, ts, alpha=alpha, coverage=coverage)

    # initial window
    w_pilot = max(N_min / lam, w_conn_min)
    t_pilot, s_pilot = build_series_fn(w_pilot, w_pilot * 0.2)  # 80% overlap
    ts_est = build_series_and_estimate_timescales(t_pilot, s_pilot)
    # variable for correlated time
    tau_c = ts_est.tau_c
    # variable for changes
    tau_chg = ts_est.tau_chg

    # build candidate parameters
    candidates: List[Candidate] = []
    time_series_per_candidate: List[np.ndarray] = []
    time_stamps_per_candidate: List[np.ndarray] = []
    for m in candidate_multipliers:
        w = max(m * tau_chg, w_conn_min, N_min / lam)
        for r in r_candidates:       # (0.5, 0.65, 0.8)
            step = min((1.0 - r) * w, tau_c / 2.0)
            t_c, s_c = build_series_fn(w, step)
            if len(t_c) >= 3:
                candidates.append(Candidate(window_size=w, step_size=step))
                time_series_per_candidate.append(s_c)
                time_stamps_per_candidate.append(t_c)
    
    # 4) score and pick best
    scores = score_candidates(candidates, time_series_per_candidate, time_stamps_per_candidate, beta=beta)
    if not scores:
        # fallback: return pilot-based
        step_fb = min(0.25 * w_pilot, tau_c / 2.0)
        dist_suggest = int(np.ceil((tau_min or 0.5 * tau_chg) / max(step_fb, 1e-9)))
        prom_suggest = ts_est.grad_median + 2.5 * ts_est.grad_mad
        return dict(window_size=float(w_pilot),
                    step_size=float(step_fb),
                    suggest_distance=float(dist_suggest),
                    suggest_prominence=float(prom_suggest),
                    tau_c=float(tau_c),
                    tau_chg=float(tau_chg),
                    w_conn_min=float(w_conn_min))

    # choose best in normal status
    best = max(scores, key=lambda z: z.total_score)
    best_step = max(1e-9, best.candidate.step_size)
    dist_suggest = int(np.ceil((tau_min or 0.5 * tau_chg) / best_step))
    prom_suggest = ts_est.grad_median + 2.5 * ts_est.grad_mad

    return dict(window_size=float(best.candidate.window_size),
                step_size=float(best.candidate.step_size),
                suggest_distance=float(dist_suggest),
                suggest_prominence=float(prom_suggest),
                tau_c=float(tau_c),
                tau_chg=float(tau_chg),
                w_conn_min=float(w_conn_min))

