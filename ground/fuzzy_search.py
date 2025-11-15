'''
 # @ Create Time: 2025-10-31 09:36:32
 # @ Modified time: 2025-10-31 09:36:33
 # @ Description: fuzzy search potential cve propagation paths to overcome the drawbacks of technical lags
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import networkx as nx
from packaging import version
import random
import re
from cve.cvescore import _osv_infer_packages

def layer_based_search(G, root, cve_meta, family_index=None, max_depth=6, sample_limit=5):
    """Layer-based path search with detailed debugging and auto inference."""
    
    print(f"[DEBUG][LAYER] start_id={root}, total_nodes={len(G.nodes)}")

    candidates = []
    visited = {root}
    queue = [(root, [root], 0)]

    # --- New debug: print node summary ---
    if hasattr(G, "nodes") and root in G.nodes:
        node = G.nodes[root]
        pkg = getattr(node, "package", None)
        ver = getattr(node, "version", None)
        print(f"[DEBUG][LAYER] start node package={pkg} version={ver}")
    else:
        print(f"[DEBUG][LAYER] start node not found in graph!")


    # for debug
    debug=True

    # ============================================================
    # ---- Helper extractors (compatible with OSV/NVD structure)
    # ============================================================
    def get_pkg_name(c):
        """
        Robust CVE package name extractor that reuses _osv_infer_packages().
        """
        # Explicit fields first
        pkg = c.get("package") or c.get("pkg") or c.get("name")
        if pkg:
            return pkg

        # Reuse existing helper to extract packages from OSV structure
        pkgs = _osv_infer_packages(c)
        if pkgs:
            # Usually there’s just one package per CVE entry
            return pkgs[0].lower()

        # As a final fallback, use any previously inferred version-based name
        return c.get("__pkg_inferred__")

    def get_versions(c):
        vers = set()
        for af in c.get("affected", []) or []:
            for v in af.get("versions", []) or []:
                vers.add(str(v))
        return list(vers)

    def get_cve_id(c):
        return c.get("cve_id") or c.get("id")

    # ============================================================
    # ---- Inference: try to recover pkg names from versions
    # ============================================================
    def infer_pkg_from_versions(versions):
        """Heuristically extract probable package name from mixed version strings."""
        for v in versions:
            # Capture strings like 'mutt-0.92.10i', 'nifi-1.8.0', 'karaf-4.3.4'
            m = re.search(r"([a-zA-Z0-9_.\-]+?)(?:[-_.]v?\d+|\d+\.\d+)", v)
            if m:
                pkg = m.group(1)
                if len(pkg) > 2 and not pkg.startswith("v"):
                    return pkg
        return None

    for c in cve_meta:
        if not get_pkg_name(c):
            inferred = infer_pkg_from_versions(get_versions(c))
            if inferred:
                c["__pkg_inferred__"] = inferred

    # ============================================================
    # ---- Node-level extractor (DepGraph-Aware)
    # ============================================================
    def get_node_pkg(n):
        """Extract package name from Depgraph node attributes."""
        node_data = G.nodes[n]
        # example of node: 
        """
        Node(id='n2905925', package='org.opendaylight.bgpcep:features-aggregator-bgpcep-extras', version='0.8.0', time=datetime.datetime(2017, 9, 19, 21, 3, 44))
        """
        # Case 1: DepGraph Node object
        if hasattr(node_data, "package"):
            pkg_full = getattr(node_data, "package", "")
            # Split Maven-style 'group:artifact'
            parts = pkg_full.split(":")
            if len(parts) >= 2:
                return parts[-1].lower()  # artifact name
            return pkg_full.lower()

        # Case 2: dict-style node (e.g., networkx)
        if isinstance(node_data, dict):
            pkg_full = node_data.get("package") or node_data.get("name")
            if pkg_full:
                parts = pkg_full.split(":")
                if len(parts) >= 2:
                    return parts[-1].lower()
                return pkg_full.lower()

        return str(n).lower()

    def get_node_version(n):
        """Extract version string from node attributes."""
        data = G.nodes[n]
        # DepGraph Node object
        if hasattr(node, "version"):
            v = getattr(node, "version", None)
            return "" if v is None else str(v)
        # dict node
        if isinstance(node, dict):
            if "version" in node:
                return str(node["version"])
        s = str(n)
        return s.split("@")[-1] if "@" in s else ""

    # ============================================================
    # ---- Utility: successor iteration (Depgraph or NetworkX)
    # ============================================================

    def iter_successors(G, node, use_reverse=False):
        """Iterate successors in normal or reverse direction."""
        if use_reverse and hasattr(G, "rev") and isinstance(G.rev, dict):
            for edge in G.rev.get(node, []):
                yield edge.src
            return
        # Normal direction
        for edge in G.adj.get(node, []):
            yield edge.dst

    # ============================================================
    # ---- Matching utilities
    # ============================================================

    def _node_display_name(n):
        data = G.nodes[n]
        if isinstance(data, dict):
            for k in ("name", "artifactId", "artifact", "id", "key"):
                if data.get(k):
                    return str(data[k])
        return str(n)

    def _in_same_family_wrapped(p1, p2):
        try:
            return in_same_family(p1, p2, family_index)
        except TypeError:
            return in_same_family(p1, p2)

    def normalize_pkg_name(name):
        """Normalize package names for flexible matching."""
        if not name:
            return None
        name = name.lower().strip()

        # Handle common ecosystem prefixes
        for prefix in ("maven.", "pypi.", "npm.", "pkg:", "github:"):
            if name.startswith(prefix):
                name = name[len(prefix):]

        # Split Maven-like groupId:artifactId
        if ":" in name:
            name = name.split(":")[-1]

        # Handle repo paths like github:apache/struts
        if "/" in name:
            name = name.split("/")[-1]

        # Drop org/company parts (e.g., org.springframework → spring)
        if "." in name:
            name = name.split(".")[-1]

        # Remove common suffixes
        name = re.sub(r"[-_.](core|parent|service|lib|impl|common|api|test)$", "", name)
        name = re.sub(r"[-_.]+", "-", name)

        return name.strip("-_.")
    
    def in_same_family(pkg1, pkg2):
        pkg1, pkg2 = pkg1.lower(), pkg2.lower()
        return (pkg1 == pkg2 or pkg1 in pkg2 or pkg2 in pkg1
                or family_index.get(pkg1) == family_index.get(pkg2))

    def is_version_close(ver, affected_versions, tol=1):
        ''' choose reasonable version closeness within tolerance to avoid explosive matches
         
        '''
        try:
            v = version.parse(str(ver))
            for av in affected_versions:
                avv = version.parse(str(av))
                # major must be the same
                if len(v.release) > 0 and len(avv.release) > 0 and v.release[0] != avv.release[0]:
                    continue
                
                # match when minor/patch difference within tolerance
                minor_diff = abs((v.release[1] if len(v.release) > 1 else 0) -
                             (avv.release[1] if len(avv.release) > 1 else 0))
                patch_diff = abs((v.release[2] if len(v.release) > 2 else 0) -
                                (avv.release[2] if len(avv.release) > 2 else 0))
                if minor_diff + patch_diff <= tol:
                    return True
        except Exception:
            pass
        return False

    # ============================================================
    # ---- Debug: sample inspection
    # ============================================================
    if debug and cve_meta:
        sample_cves = random.sample(cve_meta, min(len(cve_meta), sample_limit))
        print(f"[DEBUG] CVE sample keys:", list(sample_cves[0].keys()))
        for c in sample_cves:
            print("  ↳", get_cve_id(c),
                  "pkg=", get_pkg_name(c),
                  "vers=", get_versions(c)[:3])

        example_nodes = random.sample(list(G.nodes), min(len(G.nodes), sample_limit))
        node_labels = [get_node_pkg(n) for n in example_nodes]
        print("[DEBUG] Example graph nodes:", node_labels)
        all_pkg_names = {get_pkg_name(c) for c in cve_meta if get_pkg_name(c)}
        node_pkgs = set(node_labels)
        overlap = len(all_pkg_names & node_pkgs)
        print(f"[DEBUG] CVE packages={len(all_pkg_names)}, sample overlap={overlap}")

    # ============================================================
    # ---- BFS search
    # ============================================================
    found_pkg = 0
    version_hit = 0
    total_checked = 0

    while queue:
        node, path, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        print(f"[DEBUG][LAYER] depth={depth} exploring node={node}")

        for nbr in iter_successors(G, node):
            if nbr in visited:
                continue
            if depth + 1 > max_depth:
                continue

            visited.add(nbr)
            new_path = path + [nbr]
            pkg = get_node_pkg(nbr)
            ver = get_node_version(nbr)
            total_checked += 1

            for c in cve_meta:
                pkg_name = normalize_pkg_name(get_pkg_name(c))
                if not pkg_name:
                    continue
                
                node_display = _node_display_name(node)              
                pkg_norm  = normalize_pkg_name(pkg_name)              
                node_norm = normalize_pkg_name(node_display)          

                name_hit = False                                      
                if pkg_norm and node_norm:                            
                    if (pkg_norm == node_norm                         
                        or pkg_norm in node_norm                      
                        or node_norm in pkg_norm                      
                        or _in_same_family_wrapped(pkg_norm, node_norm)):  
                        name_hit = True

                if not name_hit:                                     
                    continue      
                
                found_pkg += 1
                versions = get_versions(c)
                if is_version_close(ver, versions):

                    version_hit += 1
                    candidates.append({
                        "root": root,
                        "path": new_path,
                        "match": get_cve_id(c),
                        "distance": depth + 1,
                        "mode": "layer"
                    })
                    break
            queue.append((nbr, new_path, depth + 1))

    # ============================================================
    # ---- Debug summary
    # ============================================================
    if debug:
        inferred_count = sum(1 for c in cve_meta if "__pkg_inferred__" in c)
        print(f"[DEBUG] Inferred package names for {inferred_count}/{len(cve_meta)} CVEs.")
        print(f"[DEBUG] Total edges checked={total_checked}")
        print(f"[DEBUG] Family-matched packages={found_pkg}")
        print(f"[DEBUG] Version-close matches={version_hit}")
        if not candidates:
            print("[DEBUG] ⚠ No candidates found — possible causes:")
            print("         • dependency graph nodes anonymized (e.g., n1234)")
            print("         • CVE records missing package names")
            print("         • inconsistent ecosystem or naming (pypi., maven., etc.)")

    return candidates