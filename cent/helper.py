'''
 # @ Create Time: 2025-10-09 12:02:34
 # @ Modified time: 2025-10-09 12:02:36
 # @ Description: functions to speed up tempcentrality computation
 '''
from pathlib import Path
import pickle
import numpy as np
import networkx as nx

def _build_time_index(G):
    ts = []
    for n, d in G.nodes(data=True):
        t = d.get("timestamp")
        if t is not None:
            ts.append(float(t))
    if not ts:
        raise ValueError("Graph nodes lack 'timestamp' for sliding windows.")
    ts = np.asarray(ts, dtype=float)
    return float(ts.min()), float(ts.max())

def _iter_windows(t_min, t_max, win_size, step):
    t = t_min
    while t < t_max:
        t_s = t
        t_e = min(t+win_size, t_max)
        yield t_s, t_e
        t += step

def _node_in_window(G, t_s, t_e):
    return [n for n, d in G.nodes(data=True)
        if d.get("timestamp") is not None and t_s <= float(d["timestamp"]) < t_e]

