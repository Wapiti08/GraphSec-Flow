'''
 # @ Create Time: 2025-06-25 16:18:24
 # @ Modified time: 2025-06-25 16:18:27
 # @ Description: temporal window selection for dynamic time windows and chagne point detection
 '''

import numpy as np
import pandas as pd
from scipy.signal import find_peaks
from pathlib import Path
import pickle

class TempWinSelect:
    ''' select time windows based on significant changes in centrality scores
    accepts either aligned arrays or a dict {timestamp: centrality_score}
    
    '''
    def __init__(self, centrality_scores, timestamps=None, smooth_window=0):
        # normalize inputs
        if isinstance(centrality_scores, dict):
            # sort by timestamp
            items = sorted(centrality_scores.items())
            self.timestamps = np.asarray([t for t, _ in items], dtype=float)
            self.centrality = np.asarray([c for _, c in items], dtype=float)
        else:
            assert timestamps is not None, "timestamps must be provided when centrality_scores is a sequence."
            self.timestamps = np.asarray(timestamps, dtype=float)
            self.centrality = np.asarray(centrality_scores, dtype=float)

        # Basic checks
        if self.timestamps.ndim != 1 or self.centrality.ndim != 1:
            raise ValueError("timestamps and centrality must be 1-D.")
        if len(self.timestamps) != len(self.centrality):
            raise ValueError("timestamps and centrality must have the same length.")
        if not np.all(np.diff(self.timestamps) > 0):
            raise ValueError("timestamps must be strictly increasing.")
        
        # optional simple smoothing
        if smooth_window and smooth_window >1:
            k = int(smooth_window)
            # use odd window
            if k%2 ==0: k += 1
            pad = k // 2
            x = np.pad(self.centrality, (pad, pad), mode='edge')
            kernel = np.ones(k) / k
            self.centrality_scores = np.convolve(x, kernel, mode='valid')
        
    
    def detect_sign_changes(self, prominence=0.01, use_abs_gradient=True,  distance=None):
        '''
        Detect indices of significant change points via peaks in the (absolute) first derivative.
        
        args:
            prominence (float): peak prominence in derivative space.
            use_abs_gradient (bool): If true, peaks on |dC/dt| (capture up & down)
            distance (int): minimum number of samples between peaks
        
        returns:
            List[int]: indices in the ORIGINAL series taht correspond to change points
        '''
        # compute derivative with respect to time
        dC = np.gradient(self.centrality, self.timestamps)
        y = np.abs(dC) if use_abs_gradient else dC

        peaks, _ = find_peaks(y, prominence=prominence, distance=distance)

        return peaks.list()
        
    
    def select_time_windows(self, threshold=0.1):
        """
        Detect significant changes in centrality scores using peak detection.
        
        Args:
            threshold (float): Minimum height of peaks to be considered significant.
        
        Returns:
            list: Indices of significant change points.
        """
        peaks, _ = find_peaks(self.centrality_scores, height=threshold)
        return peaks.tolist()
    
    def select_time_windows(self, start_time=None, end_time=None,
                            prominence=0.01, distance=None, include_boundaries=True):
        '''
        Return time intervals bracketed by significant change points within [start_time, end_time].
        
        Returns:
            List[Tuple[float, float, dict]]: list of (t_start, t_end, meta) windows, where meta includes
                {'start_idx', 'end_idx', 'peak_indices'}.
        '''
        # Default to full range
        t0 = self.timestamps[0] if start_time is None else start_time
        t1 = self.timestamps[-1] if end_time   is None else end_time
        if t0 >= t1:
            return []

        # restrict to the requested time span
        left = int(np.searchsorted(self.timestamps, t0, side='left'))
        right = int(np.searchsorted(self.timestamps, t1, side='right'))

        ts = self.timestamps[left:right]
        cs = self.centrality[left:right]
        if len(ts) < 2:
            return []
        
        # detect change points on the restricted segment
        # Note: indices are local to [left:right], convert back to global with +left if needed

        dC = np.gradient(cs, ts)
        y = np.abs(dC)
        peaks_local, _ = find_peaks(y, prominence=prominence, distance=distance)
        peaks = (peaks_local + left).tolist()  # convert to global indices

        # build window boundaries
        boundaries = []
        if include_boundaries:
            boundaries.append(left)
        boundaries.extend(peaks)
        if include_boundaries:
            # end boundary (last index inside slice)
            boundaries.append(right - 1)
        
        boundaries = sorted(set(boundaries))
        # Convert consecutive boundary indices into half-open intervals in time
        windows = []
        for i in range(len(boundaries) - 1):
            s_idx = boundaries[i]
            e_idx = boundaries[i + 1]
            t_start = self.timestamps[s_idx]
            t_end   = self.timestamps[e_idx]
            if t_start < t_end:  # skip zero-length
                # Collect peaks that lie inside this interval
                local_peaks = [p for p in peaks if s_idx <= p <= e_idx]
                windows.append((t_start, t_end, {
                    "start_idx": s_idx,
                    "end_idx": e_idx,
                    "peak_indices": local_peaks
                }))
        return windows


if __name__ == "__main__":
    # data path
    small_depdata_path = Path.cwd().parent.joinpath("data", "dep_graph_small.pkl")
    # depdata_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    # load the graph
    with small_depdata_path.open('rb') as fr:
        depgraph = pickle.load(fr)
    

    selector = TempWinSelect(centrality_scores=centrality_series, timestamps=ts, smooth_window=5)

    # Change points (indices in the original arrays)
    peaks = selector.detect_significant_changes(prominence=0.02, distance=5)

    # Time windows segmented by those change points within a query range
    wins = selector.select_time_windows(start_time=1600000000, end_time=1700000000,
                                        prominence=0.02, distance=5)
    for (t0, t1, meta) in wins:
        print(f"[{t0}, {t1}) via peaks @ {meta['peak_indices']}")