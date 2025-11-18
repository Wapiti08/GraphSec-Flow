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


def _lead_time(series_scores, events, thresh=0.8):
    """
    LeadTime = event_time − first detection time (only if first < event_time)
    If detection happens after the event -> not counted as lead.
    """

    from collections import defaultdict

    node2ts = defaultdict(list)

    # flatten scores: node -> [(timestamp, zscore), ...]
    for t, sc in series_scores:
        for n, v in sc.items():
            node2ts[n].append((float(t), v))

    leads = []

    for ev in events:
        te = float(ev.get("t", 0))
        if te < 1e11:   # seconds → ms
            te *= 1000.0

        for n in ev.get("targets", []):
            first = None

            for t, v in node2ts.get(n, []):
                if t < 1e11:
                    t *= 1000.0

                if v >= thresh:
                    first = t
                    break

            # Only count if detection happens BEFORE event
            if first is not None and first < te:
                delta_days = (te - first) / 86400000.0
                if delta_days < 36500:   # sanity (<100 years)
                    leads.append(delta_days)

    # Return mean lead time (days)
    return sum(leads) / len(leads) if leads else 0.0


    