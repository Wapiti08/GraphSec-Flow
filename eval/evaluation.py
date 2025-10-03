'''
 # @ Create Time: 2025-10-02 15:37:17
 # @ Modified time: 2025-10-02 15:37:42
 # @ Description: Normalization and evaluation
 '''
from typing import Dict

def _pick_total(d):
    # compatible with (in, out, total), default choose total to compare with undirected graph
    return d["total"] if isinstance(d, dict) and "total" in d else d

def _zscore(scores):
    ''' standalized z scores
    
    '''
    if not scores:
        return {}
    vals = list(scores.values())
    mu = sum(vals) / len(vals)
    var = sum((x-mu)**2 for x in vals) / max(1, len(vals) - 1)
    std = var ** 0.5 or 1.0
    return {n: (v-mu)/std for n, v in scores.items()}

def _rank_metrics(scores: Dict, targets):
    ''' calculate Mean Reciprocal Rank (MRR) and Hits@3
    
    '''
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    order = [n for n, _ in ranked]

    # MRR, compute RR and then mean for per target
    rr = []
    for t in targets:
        try:
            rr.append(1.0 / (order.index(t) + 1))
        except ValueError:
            rr.append(0.0)
    # more close to 1, higher ranking
    mrr = sum(rr) / len(rr) if rr else 0.0
    # in top 3
    hits3 = 1.0 if any(n in targets for n in order[:3]) else 0.0
    return mrr, hits3


def _lead_time(series_scores, events, thresh=1.0):
    ''' Compute the amount of time before a node is detected 
    (score exceeds threshold) "before an event occurs"
    
    args:
        series_scores: [(t_eval, {node: zscore})...]
    '''
    from collections import defaultdict
    # save node -> (t,zscore)
    node2ts = defaultdict(list)

    for t, sc in series_scores:
        for n, v in sc.items():
            node2ts[n].append((t, v))
    
    leads = []

    for ev in events:
        te = ev['t']
        for n in ev["targets"]:
            first = None
            for t, v in node2ts.get(n, []):
                if v >= thresh:
                    first = t
                    break
            if first is not None:
                leads.append(te - first)
    
    return sum(leads)/len(leads) if leads else 0.0
    

    