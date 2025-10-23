import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import json, pickle, random, collections, math, os
import networkx as nx
from utils.util import read_jsonl, write_jsonl, _safe_load_pickle

DEP_GRAPH_PKL = Path.cwd().parent.joinpath("data", "dep_graph_cve.pkl").as_posix()
REF_PATHS_JSONL = Path.cwd().parent.joinpath("data", "ref_paths.jsonl").as_posix()
ROOT_CAUSE_JSONL = Path.cwd().parent.joinpath("data","root_causes.jsonl").as_posix()

def read_jsonl(p):
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)

def brief(v, n=5):
    a = list(v)
    return a[:n], max(0, len(a)-n)

def to_int(x):
    try:
        if x is None: return None
        if isinstance(x,(int,float)): return int(x)
        s = str(x).strip()
        if s == "" or s.lower()=="nan": return None
        return int(float(s))
    except:
        return None
    
def check_graph(G):
    total = G.number_of_nodes()
    ts_ok = sum(1 for _,d in G.nodes(data=True) if to_int(d.get("timestamp")) is not None)
    ts_vals = [to_int(d.get("timestamp")) for _,d in G.nodes(data=True) if to_int(d.get("timestamp")) is not None]
    print(f"[Graph] nodes={total}, with_timestamp={ts_ok} ({ts_ok/total:.1%})")
    if ts_vals:
        print(f"[Graph] timestamp range: {min(ts_vals)} ~ {max(ts_vals)}")
    else:
        print("[Graph] no usable timestamps at all!")


def make_temporal_digraph(G, strict_increase=False):
    """convert indirect graph to direct graph according to timestamps
    
    """
    D = nx.DiGraph()
    for n, d in G.nodes(data=True):
        ts = to_int(d.get("timestamp"))
        if ts is not None:
            attrs = dict(d)
            attrs["timestamp"] = ts 
            D.add_node(n, **attrs)
    for u, v in G.edges():
        if u not in D or v not in D: 
            continue
        tsu = D.nodes[u]["timestamp"]
        tsv = D.nodes[v]["timestamp"]
        if tsu is None or tsv is None:
            continue
        if strict_increase:
            if tsu < tsv: D.add_edge(u, v, time_lag=tsv-tsu)
            if tsv < tsu: D.add_edge(v, u, time_lag=tsu-tsv)
        else:
            if tsu <= tsv: D.add_edge(u, v, time_lag=tsv-tsu)
            if tsv <= tsu: D.add_edge(v, u, time_lag=tsu-tsv)
    return D


def main():
    assert Path(DEP_GRAPH_PKL).exists(), f"Missing {DEP_GRAPH_PKL}"
    assert Path(ROOT_CAUSE_JSONL).exists(), f"Missing {ROOT_CAUSE_JSONL}"
    assert Path(REF_PATHS_JSONL).exists(), f"Missing {REF_PATHS_JSONL}"

    G = pickle.loads(Path(DEP_GRAPH_PKL).read_bytes())
    if isinstance(G, dict) and "nodes" in G and "edges" in G:
        GG = nx.Graph()
        for n, attrs in G["nodes"]:
            GG.add_node(n, **attrs)
        GG.add_edges_from(G["edges"])
        G = GG

    print("=== 1) Health Degree of Graph in Global ===")
    check_graph(G)

    print("\n=== 2) root_cause coverage ===")
    root_ids = []
    for rec in read_jsonl(ROOT_CAUSE_JSONL):
        rid = rec.get("root_cause") or rec.get("root") or rec.get("source") or rec.get("src")
        if rid is not None:
            root_ids.append(str(rid))
    roots_in_graph = [r for r in root_ids if r in G]
    print(f"root_cause count={len(root_ids)}, in_graph={len(roots_in_graph)} ({len(roots_in_graph)/max(1,len(root_ids)):.1%})")
    if len(roots_in_graph)<len(root_ids):
        missing = set(root_ids)-set(roots_in_graph)
        some, more = brief(missing, 10)
        print(f"  - Missing {len(missing)} root nodes in graph, e.g. {some}{' and +%d more'%more if more else ''}")

    print("\n=== 3) ref_paths.jsonl ===")
    empty_cnt = 0
    total = 0
    sample_empty = []
    for rec in read_jsonl(REF_PATHS_JSONL):
        total += 1
        paths = rec.get("paths") or rec.get("path") or []
        if not paths:
            empty_cnt += 1
            if len(sample_empty)<5:
                sample_empty.append(rec)
    print(f"ref_paths total={total}, empty={empty_cnt} ({(empty_cnt/max(1,total)):.1%})")
    if sample_empty:
        print("Example empty items (truncated keys):")
        for e in sample_empty:
            print({k:e[k] for k in list(e)[:6]})

    print("\n=== 4) Time Window & Impact of strictness on reachability (sampling 50 roots) ===")
    roots = roots_in_graph[:]
    random.shuffle(roots)
    roots = roots[:50] if len(roots)>50 else roots

    D_relaxed = make_temporal_digraph(G, strict_increase=False)  # loose（allow equalent time）
    D_strict  = make_temporal_digraph(G, strict_increase=True)   # strict（in increasing order）

    def reachable_stats(D):
        s = []
        for r in roots:
            if r not in D: 
                s.append(0); continue
            s.append(len(nx.descendants(D, r)))
        return s

    r_relaxed = reachable_stats(D_relaxed)
    r_strict  = reachable_stats(D_strict)

    if r_relaxed:
        print(f"Relaxed median reachable: {int(sorted(r_relaxed)[len(r_relaxed)//2])} (mean={sum(r_relaxed)/len(r_relaxed):.1f})")
        print(f" Strict median reachable: {int(sorted(r_strict)[len(r_strict)//2])} (mean={sum(r_strict)/len(r_strict):.1f})")

    zeros_relaxed = sum(1 for x in r_relaxed if x==0)
    zeros_strict  = sum(1 for x in r_strict if x==0)
    print(f"roots with 0 reachable nodes -> relaxed={zeros_relaxed}/{len(r_relaxed)}, strict={zeros_strict}/{len(r_strict)}")

    print("\n=== 5) Sampling path sanity check (relaxing restrictions, shortest path) ===")
    ok_paths = 0
    for r in roots[:10]:
        if r not in D_relaxed: 
            print(f" - {r}: not in temporal graph"); 
            continue
        succ = list(D_relaxed.successors(r))
        if not succ:
            print(f" - {r}: no forward successors (even relaxed)")
            continue
        targets = sorted(succ, key=lambda n: (D_relaxed.nodes[n]["timestamp"], D_relaxed.out_degree(n)))
        tgt = targets[min(5, len(targets)-1)]
        try:
            p = nx.shortest_path(D_relaxed, r, tgt, weight="time_lag")
            print(f" - {r} -> {tgt}: path_len={len(p)}")
            ok_paths += 1
        except nx.NetworkXNoPath:
            print(f" - {r} -> {tgt}: no path (unexpected, edge existed)")
    print(f"Sanity check with relaxed edges: found {ok_paths} sample paths.")

if __name__ == "__main__":
    main()