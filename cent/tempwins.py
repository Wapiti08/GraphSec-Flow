'''
 # @ Create Time: 2025-06-25 16:18:24
 # @ Modified time: 2025-06-25 16:18:27
 # @ Description: temporal window selection for dynamic time windows and chagne point detection
 '''

import numpy as np
import pandas as pd
from scipy.signal import find_peaks

class TempWindsSelec:
    def __init__(self, centrality_scores, timestamps):
        self.centrality_scores = centrality_scores
        self.timestamps = timestamps
    
    def detect_significant_changes(self, threshold=0.1):
        """
        Detect significant changes in centrality scores using peak detection.
        
        Args:
            threshold (float): Minimum height of peaks to be considered significant.
        
        Returns:
            list: Indices of significant change points.
        """
        peaks, _ = find_peaks(self.centrality_scores, height=threshold)
        return peaks.tolist()
    
    def select_time_windows(self, start_time, end_time):
        '''
        select the time window based on the detected significant changes in centrality scores
        '''
        # get the time indices of significant centrality changes
        peaks = self.detect_significant_changes()

        # find the first and last peaks within the desired time window
        start_idx = np.searchsorted(self.timestamps, start_time)
        end_idx = np.searchsorted(self.timestamps, end_time)

        # return the subset of timestamps and centrality within the time window
        time_window = [(self.timestamps[i], self.centrality_scores[i]) for i in range(start_idx, end_idx) if i in peaks]
        return time_window

