'''
 # @ Create Time: 2025-09-30 11:49:43
 # @ Modified time: 2025-09-30 11:50:59
 # @ Description: timeline links extraction from temporal communities
 '''

from typing import Dict, List, Tuple, Mapping
import networkx as nx

def build_interwins_links(
        dep_graph: nx.Graph,
        timestamps: Mapping[str, float],
        windows: List[Tuple[float, float, str]], # [(t_s,t_e,wid), ...] increasing order
        window_results: Mapping[str, dict]  # wid -> { 'comm_to_nodes', 'representatives', ... }
    ) -> Tuple[Dict[Tuple[str, int, str, int], int], List[Tuple[str, str]]]:
    '''
    return:
        cluster_edges: {(widA, cidA, widA, cidB): edge_count}
        rep_edges: [(rep_u, rep_v)] # only represent edge between representatives
    '''
    cluster_edges: Dict[Tuple[str, int, str, int], int] = {}
    rep_edges: List[Tuple[str, str]] = []

    for i in range(len(windows) - 1):
        (tA_s, tA_e, widA) = windows[i]
        (tB_s, tB_e, widB) = windows[i + 1]
        # get community results
        resA, resB = window_results.get(widA, {}), window_results.get(widB, {})
        commA = resA.get('comm_to_nodes', {})
        commB = resB.get('comm_to_nodes', {})
        repsA = resA.get('representatives', {})
        repsB = resB.get('representatives', {})

        belongA = {n: cid for cid, S in commA.items() for n in S}
        belongB = {n: cid for cid, S in commB.items() for n in S}

        # count inter-community edges
        for u, v in dep_graph.edges():
            tu = timestamps.get(u); tv = timestamps.get(v)
            if tu is None or tv is None:
                continue
            if (tA_s <= tu <= tA_e) and (tB_s <= tv <= tB_e):
                if (u in belongA) and (v in belongB):
                    cidA, cidB = belongA[u], belongB[v]
                    key = (widA, cidA, widB, cidB)
                    cluster_edges[key] = cluster_edges.get(key, 0) + 1
        
        # connect representative nodes
        for (WA, a, WB, b), _ in list(cluster_edges.items()):
            if WA == widA and WB == widB:
                ru, rv = repsA.get(a), repsB.get(b)
                if (ru is not None) and (rv is not None):
                    rep_edges.append((ru, rv))
    
    return cluster_edges, rep_edges