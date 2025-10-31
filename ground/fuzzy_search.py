'''
 # @ Create Time: 2025-10-31 09:36:32
 # @ Modified time: 2025-10-31 09:36:33
 # @ Description: fuzzy search potential cve propagation paths to overcome the drawbacks of technical lags
 '''

import networkx as nx
from packaging import version


def is_version_close(ver, affected_versions, tol=1):
    """Check if version is within ±tol minor versions of affected ones."""
    try:
        v = version.parse(ver)
        for av in affected_versions:
            avv = version.parse(av)
            if abs((v.release[1] if len(v.release) > 1 else 0) -
                   (avv.release[1] if len(avv.release) > 1 else 0)) <= tol:
                return True
    except Exception:
        pass
    return False


def layer_based_search(G, root, cve_meta, family_index=None, max_depth=3):
    '''
    Approximate vulnerable paths via layered (BFS) exploration.

    Parameters
    ----------
    G : nx.DiGraph
        Dependency graph.
    root : str
        Root package node (e.g., "django@3.2.1").
    cve_meta : list[dict]
        CVE metadata entries.
    family_index : dict, optional
        Mapping of package families from release index.
    max_depth : int
        Max number of dependency layers to explore.

    Returns
    -------
    list[dict]
        List of candidate vulnerable paths, each with:
        {"root": ..., "path": [...], "match": ..., "distance": ...}
    '''
    candidates = []
    root_pkg = root.split("@")[0]
    cve_pkgs = {c["package"] for c in cve_meta}

    def in_same_family(pkg1, pkg2):
        if pkg1 == pkg2:
            return True
        if not family_index:
            return False
        fam1 = family_index.get(pkg1)
        fam2 = family_index.get(pkg2)
        return fam1 is not None and fam1 == fam2
    
    # BFS layer expansion
    visited = {root}
    queue = [(root, [root], 0)]

    while queue:
        node, path, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        for nbr in G.successors(node):
            if nbr in visited:
                continue
            visited.add(nbr)
            new_path = path + [nbr]
            pkg = nbr.split("@")[0]
            ver = nbr.split("@")[-1]

            # check CVE match (package name or family)
            for c in cve_meta:
                if in_same_family(pkg, c["package"]):
                    # fuzzy version proximity
                    if is_version_close(ver, c.get("affected_versions", [])):
                        candidates.append({
                           "root": root,
                            "path": new_path,
                            "match": c["cve_id"],
                            "distance": depth + 1
                        })
                        break
            queue.append((nbr, new_path, depth + 1))
    
    return candidates
