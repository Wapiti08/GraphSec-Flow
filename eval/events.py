'''
 # @ Create Time: 2025-10-03 14:06:50
 # @ Modified time: 2025-10-03 14:06:53
 # @ Description: create events for benchmark evaluation based on earliest published timestamp
 '''

from datetime import datetime, date
from collections import defaultdict
import pandas as pd

def _to_date(x):
    ''' convert published/modified timestamp string (2023-09-12T15:15:24Z) in OSV to date

    '''
    if x is None:
        return None
    
    s = str(x)
    try:
        return pd.to_datetime(s, utc=True).date()
    except Exception:
        try:
            return pd.to_datetime(s, utc=True).date()
        except Exception:
            try:
                return datetime.fromisoformat(s.replace("Z","")).date()
            except Exception:
                return None

def _first_cve_data_of_node(cve_list_for_node):
    ''' extract timestamp from cve_records_for_meta[node_id], return earliest date
    
    '''
    ds = []
    for rec in (cve_list_for_node or []):
        d = _to_date(rec.get("timestamp"))
        if d:
            ds.append(d)
    return min(ds) if ds else None

def _last_cve_data_of_node(cve_list_for_node):
    ''' latest data among CVE meta records for a node
    
    '''
    ds = []
    for rec in (cve_list_for_node or []):
        d = _to_date(rec.get("timestamp"))
        if d:
            ds.append(d)
    return max(ds) if ds else None

def _to_same_type(t, ref_type):
    if isinstance(ref_type, pd.Timestamp):
        ts = pd.Timestamp(t)
        return ts.tz_localize("UTC") if ts.tz is None else ts.tz_convert("UTC")
    if isinstance(ref_type, datetime):
        return datetime.combine(t, datetime.min.time())
    return t 

# ------------ generate events according to earliest timestamp --------------
def build_events_from_vamana_meta(
        depgraph, cve_records_for_meta, t_eval_list, fallback_to_release=True
    ):
    '''
    depgraph: networkx.Graph with timestamp on release node
    cve_records_for_meta: Dict[node_id, List[{name, severity, timestamp}]]
    t_eval_list: the type with t_eval in window_iter(), increasing order
    fallback_to_release: if there is no CVE time, fallback to release time
    '''

    # 1) calculate event time for every node: earliest CVE time, if no, fallback to release time
    node_event_date = {}

    for nid in depgraph.nodes():
        cves = cve_records_for_meta.get(nid, [])
    
        t0 = _first_cve_data_of_node(cves)
        if not t0 and fallback_to_release:
            rel = depgraph.nodes[nid].get("timestamp")
            rel_d = None
            if rel is not None:
                if isinstance(rel, date) and not isinstance(rel, datetime):
                    rel_d = rel
                else:
                    rel_d = _to_date(rel)
                t0 = rel_d

            if t0:
                node_event_date[nid] = t0
    
    # 2) align with t_eval
    events_map = defaultdict(set)
    ref = t_eval_list[0] if t_eval_list else None

    for nid, d0 in node_event_date.items():
        tkey = _to_same_type(d0, ref) if ref is not None else d0
        events_map[tkey].add(nid)
    
    # 3) generate list of events
    events = []
    for t in t_eval_list:
        tg = events_map.get(t, set())
        if tg:
            events.append({"t": t, "targets": tg})
    
    events.sort(key=lambda e: e["t"])
    return events