'''
 # @ Create Time: 2025-10-06 10:40:15
 # @ Modified time: 2025-10-06 10:40:17
 # @ Description:

 Reference (ground-truth-like) constructor for vulnerability diffusion studies.

Builds *inferred reference* root causes and propagation paths from:
- OSV/NVD CVE records (real OSV schema supported: affected[].versions, ranges.events, references FIX)
- A time-aware dependency graph (JSON)
- Optional maintainer signals (release notes / PRs)

Outputs JSONL files: root_causes.jsonl and ref_paths.jsonl
No third-party dependencies (standard library only).

 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

from ground.helper import SemVer, VersionRange, smoke_dep_graph, smoke_nvd_jsonl, smoke_osv_jsonl
from ground.helper import parse_date, iso, infer_pkg_ver_from_release
from ground.helper import split_cve_meta_to_builder_inputs, _extract_cve_id, _unwrap_record
from ground.helper import _extract_coordinates_from_osv_pkg
from ground.helper import _get_release,_get_version,_get_time,_node_key
import argparse
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Iterable, Set, Any
from collections import defaultdict, deque
from datetime import datetime, timezone
from utils.util import read_jsonl, write_jsonl, _safe_load_pickle
import time
from cve.cvescore import _osv_extract_fix_commits
from functools import lru_cache

# --------------------------------
# Data Models
# --------------------------------

@dataclass
class EvidenceItem:
    source: str
    fields: Dict[str, Any] = field(default_factory=dict)

@lru_cache(maxsize=500000)
def _semver_cached(ver: str):
    try:
        return SemVer.parse(ver)
    except Exception:
        return None

@dataclass
class RootCause:
    cve_id: str
    package: str
    version: str
    time_introduced: Optional[str]
    fix_commits: List[str] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    confidence: float = 0.0

    def to_json(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "package": self.package,
            "version": self.version,
            "time_introduced": self.time_introduced,
            "fix_commits": self.fix_commits,
            "evidence": [dict(source=e.source, fields=e.fields) for e in self.evidence],
            "confidence": round(self.confidence, 4),
        }

@dataclass
class PathEdge:
    src: str
    dst: str
    time: Optional[str] = None

@dataclass
class ReferencePath:
    cve_id: str
    root_id: str
    path: List[PathEdge]
    evidence: List[EvidenceItem] = field(default_factory=list)
    confidence: float = 0.0

    def to_json(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "root_id": self.root_id,
            "path": [dict(src=e.src, dst=e.dst, time=e.time) for e in self.path],
            "evidence": [dict(source=e.source, fields=e.fields) for e in self.evidence],
            "confidence": round(self.confidence, 4),
        }

@dataclass
class Node:
    id: str
    package: str
    version: str
    time: Optional[datetime] = None

@dataclass
class Edge:
    src: str
    dst: str
    time: Optional[datetime] = None

class DepGraph:
    ''' Time-aware directed graph of package dependencies, using adjcency list representation.'''
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        # adjacency list
        self.adj: Dict[str, List[Edge]] = defaultdict(list)
        # reverse adjacency list
        self.rev: Dict[str, List[Edge]] = defaultdict(list)
        # ------- build mapping index to avoid repeated searching ------- 
        # package -> list of nodes
        self.by_pkg: Dict[str, List[Node] ] = defaultdict(list)
        # (package, version) -> node
        self.by_pkg_ver: Dict[Tuple[str, str], Node] = {}
        # (group, artifact) -> node
        self.by_coords: Dict[Tuple[str, str], List[Node]] = defaultdict(list)
        # node.id -> release lower
        self.release_lc: Dict[str, str] = {}

    @staticmethod
    def from_json(obj: Dict[str, Any]):
        g = DepGraph()
        for n in obj.get("nodes", []):
            if not isinstance(n, dict):
                continue
            nid = n.get("id") or n.get("name")
            if not nid:
                continue

            pkg = n.get("package")
            ver = n.get("version")
            t = None

            if n.get("timestamp") is not None:
                try:
                    t= datetime.fromtimestamp(int(n["timestamp"]) / 1000.0, tz=timezone.utc).replace(tzinfo=None)
                except Exception:
                    t= None
            if t is None and n.get("time"):
                t = parse_date(n.get("time"))
            
            if (not pkg or not ver) and n.get("release"):
                rpkg, rver = infer_pkg_ver_from_release(n["release"])
                pkg = pkg or rpkg
                ver = ver or rver
            
            if not pkg:
                if "@" in nid:
                    pkg = nid.split("@")[0]
                elif n.get("release"):
                    pkg = n["release"].split(":")[0]
                else:
                    pkg = "unknown"
            if not ver:
                if "@" in nid:
                    ver = nid.split("@")[1]
                else:
                    ver = n.get("version") or ""
            
            g.nodes[nid] = Node(id = nid, package=pkg, version=ver, time=t)
        
        for e in obj.get("edges", []):
            if not isinstance(e, dict):
                continue
            src = e.get("src") or e.get("source")
            dst = e.get("dst") or e.get("target")

            if not src or not dst:
                continue
            edge = Edge(src = src, dst = dst, time=parse_date(e.get("time")))
            g.adj[edge.src].append(edge)
            g.rev[edge.dst].append(edge)

        # build mutiple indexing
        release = _get_release(g.nodes[nid]) if "_get_release" in globals() else f"{g.nodes[nid].package}:{g.nodes[nid].version}"
        pkg_l = (g.nodes[nid].package or "").lower()
        ver_l = (g.nodes[nid].version or "").lower()
        g.by_pkg[pkg_l].append(g.nodes[nid])
        if pkg_l and ver_l:
            g.by_pkg_ver[(pkg_l, ver_l)] = g.nodes[nid]
        
        g.release_lc[nid] = (release or "").lower()
        parts = release.split(":")
        if len(parts) >= 3:
            g.by_coords[(parts[0].lower(), parts[1].lower())].append(g.nodes[nid])

        return g

    def neighbors(self, node_id: str) -> List[Edge]:
        return self.adj.get(node_id, [])

    def reverse_neighbors(self, node_id: str) -> List[Edge]:
        return self.rev.get(node_id, [])
    

class GTBuilder:
    def __init__(
        self,
        dep_graph: DepGraph,
        osv_records: List[Dict[str, Any]],
        nvd_records: List[Dict[str, Any]],
        prefer_upstream_direction: bool = True,
    ):
        self.g = dep_graph
        self.osv = osv_records or []
        self.nvd = nvd_records or []
        self.prefer_upstream_direction = prefer_upstream_direction
    
    @staticmethod
    def _osv_infer_package(record: Dict[str, Any]) -> Optional[str]:
        for af in record.get("affected", []) or []:
            pkg_obj = af.get("package")
            if isinstance(pkg_obj, dict) and pkg_obj.get("name"):
                return pkg_obj["name"]
            for rng in af.get("ranges", []) or []:
                repo = rng.get("repo")
                if repo and isinstance(repo, str):
                    m = re.search(r"/([^/]+?)(?:\\\\.git)?$", repo)
                    if m:
                        return m.group(1)
        return None
    
    @staticmethod
    def _osv_extract_versions(record: Dict[str, Any]) -> Set[str]:
        versions: Set[str] = set()
        for af in record.get("affected", []) or []:
            for v in af.get("versions", []) or []:
                sv = SemVer.parse(str(v)) or None
                versions.add(str(sv) if sv else str(v))        
        return versions
    
    @staticmethod
    def _collect_ranges(record: Dict[str, Any]) -> List[VersionRange]:
        ranges: List[VersionRange] = []
        for af in record.get("affected", []) or []:
            for rng in af.get("ranges", []) or []:
                evs = rng.get("events", []) or []
                introduced = [e.get("introduced") for e in evs if e.get("introduced") not in (None, "")]
                fixed      = [e.get("fixed")      for e in evs if e.get("fixed") not in (None, "")]
                cur_intro = None
                for e in evs:
                    if "introduced" in e and e["introduced"] not in (None, ""):
                        cur_intro = e["introduced"]
                    elif "fixed" in e and e["fixed"] not in (None, "") and cur_intro is not None:
                        try:
                            ranges.append(VersionRange.parse(f">={cur_intro},<{e['fixed']}"))
                        except Exception:
                            pass
                        cur_intro = None
                if cur_intro:
                    try:
                        ranges.append(VersionRange.parse(f">={cur_intro}"))
                    except Exception:
                        pass

        return ranges


    @staticmethod
    def _package(record: Dict[str, Any]) -> Optional[str]:
        pkg = record.get("package") or record.get("pkg") or record.get("name")
        if pkg:
            return pkg
        return GTBuilder._osv_infer_package(record)

    @staticmethod
    def _fix_commits(record: Dict[str, Any]) -> List[str]:
        commits: Set[str] = set()
        val = record.get("fix_commits") or record.get("fixes") or []
        if isinstance(val, str):
            commits.add(val)
        else:
            commits.update(list(val))
        commits.update(_osv_extract_fix_commits(record))
        return list(commits)

    def _candidate_nodes_for_package(self, record: Dict[str, Any]) -> List[Node]:
        ''' extract package from OSV records to match dep_graph.release
        
        '''
        if isinstance(record, dict):
            pkgname = (self._package(record) or "").lower()
        else:
            pkgname = str(record).lower()

        candidates: List[Node] = []
        coords = None

        for af in record.get("affected", []) or []:
            coords = _extract_coordinates_from_osv_pkg(af.get("package") or {})
            if coords.get("group") or coords.get("artifact"):
                break
        
        # 1) strong match: coords: group:artifact
        if coords and (coords.get("artifact")):
            g = (coords.get("group") or "").lower()
            a = (coords.get("artifact") or "").lower()
            cand = self.g.by_coords.get((g, a), [])
            if cand:
                return cand
        
        # 2) less strong matchL package name
        if pkgname:
            candidates.extend(self.g.by_pkg.get(pkgname, []))
            if candidates:
                return candidates
            
        # 3) regex matching on release_lc
        if pkgname:
            for nid, r in self.g.release_lc.items():
                if pkgname in r:
                    candidates.append(self.g.nodes[nid])

        return candidates

    def _match_nodes_by_versions_or_ranges(self, nodes: List[Node], versions_set: Optional[Set[str]], ranges: List[VersionRange]) -> List[Node]:
        if versions_set:
            vers_l = {str(SemVer.parse(v) or v).lower() for v in versions_set}
            fast = []
            # match (pkg, ver):
            pkg_l = (self._package(nodes[0] if nodes else {}) or "").lower() if nodes else ""
            for v in vers_l:
                n = self.g.by_pkg_ver.get((pkg_l, v))
                if n:
                    fast.append(n)
            if fast:
                return fast
            # check inside small candidates
            matched = []
            for n in nodes:
                sv = _semver_cached(_get_version(n))
                if sv and str(sv).lower() in vers_l:
                    matched.append(n)
            if matched:
                return matched

        if not ranges:
            return nodes
        
        matched = []
        for n in nodes:
            sv = _semver_cached(_get_version(n))
            if not sv:
                continue
            if any(r.contains(sv) for r in ranges):
                matched.append(n)
        return matched


    def _earliest_node(self, nodes: List[Node]) -> Optional[Node]:
        if not nodes:
            return None
        nodes_sorted = sorted(nodes, key=lambda x: (_get_time(x) or datetime.max, SemVer.parse(_get_version(x)) or SemVer(9999, 9999, 9999)))
        return nodes_sorted[0]
    
    def _confidence_root(self, sources: Set[str], has_fix_commit: bool, src_agreement: float) -> float:
        w_src = min(len(sources)/2.0, 1.0)
        w_fix = 0.2 if has_fix_commit else 0.0
        w_agree = 0.8 * max(0.0, min(src_agreement, 1.0))
        return min(1.0, 0.2 + 0.5 * w_src + w_fix + w_agree)

    def build_root_causes(self) -> List[RootCause]:
        by_cve: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "packages": defaultdict(lambda: {"nodes": [], "sources": set(), "fix_commits": set(), "evidence": []}),
                "published": None
            }
        )

        def ingest(records: List[Dict[str, Any]], source: str):
            total = len(records)
            last_log = 0
            for i, r in enumerate(records):
                # unwrap record
                r = _unwrap_record(r)
                cve = _extract_cve_id(r) or r.get("id")
                if not cve:
                    continue
                pkg = self._package(r)
                versions_set: Set[str] = set()
                if source == "osv":
                    versions_set = self._osv_extract_versions(r)
                    if not pkg:
                        pkg = self._osv_infer_package(r)
                if not pkg:
                    continue
                
                ranges = self._collect_ranges(r)
                candidates = self._match_nodes_by_versions_or_ranges(self._candidate_nodes_for_package(r), versions_set or None, ranges)
                bucket = by_cve[cve]["packages"][pkg]
                bucket["nodes"].extend(candidates)
                bucket["sources"].add(source)
                bucket["fix_commits"].update(self._fix_commits(r))

                ev_fields = {"published": r.get("published")}
                if source == "osv":
                    has_git = any((rng.get("type") == "GIT") for af in (r.get("affected") or []) for rng in (af.get("ranges") or []))
                    ev_fields.update({"versions_count": len(versions_set), "has_git_ranges": has_git})
                bucket["evidence"].append(EvidenceItem(source=source, fields=ev_fields))

                if i - last_log >= 1000:  # print out every 1000
                    print(f"[{source}] processed {i}/{total} ({i/total:.1%})")
                    last_log = i

        ingest(self.osv, "osv")
        ingest(self.nvd, "nvd")

        roots: List[RootCause] = []
        for cve, group in by_cve.items():
            for pkg, item in group["packages"].items():
                nodes_unique = {}
                for n in item["nodes"]:
                    nodes_unique[_node_key(n)] = n
                nodes = list(nodes_unique.values())

                earliest = self._earliest_node(nodes)

                time_introduced = iso(earliest.time) if earliest else None
                fix_commits = sorted(list(item["fix_commits"]))
                agree = 1.0 if earliest else 0.0

                ev = list(item["evidence"])
                srcs = set(item["sources"])
                has_fix_commit = len(fix_commits) > 0

                conf = self._confidence_root(srcs, has_fix_commit, agree)
                version = earliest.version if earliest else ""

                roots.append(RootCause(
                    cve_id=cve, package=pkg, version=version, time_introduced=time_introduced,
                    fix_commits=fix_commits, evidence=ev, confidence=conf
                ))

        print(f"[GTBuilder] Finished ingest: {len(by_cve)} CVE groups collected.")

        return roots

    def build_reference_paths(self, roots: List[RootCause], max_depth: int = 5, time_constrained: bool = True) -> List[ReferencePath]:
        refs: List[ReferencePath] = []

        def node_id(pkg: str, ver: str) -> str:
            return f"{pkg}@{ver}"
        
        for idx, root in enumerate(roots):
            if idx % 50 == 0:
                print(f"[RefPaths] {idx}/{len(roots)} roots processed")
            rid = node_id(root.package, root.version) if root.version else None
            if not rid or rid not in self.g.nodes:
                refs.append(
                    ReferencePath(
                    cve_id=root.cve_id, root_id=rid or f"{root.package}@",
                    path=[], evidence=[EvidenceItem(source="GTBUILDER", fields={"reason": "root node missing"})],
                    confidence=max(0.0, root.confidence * 0.5)
                    )
                )
                continue
        
            start_node = self.g.nodes[rid]
            start_time = start_node.time
            visited: Set[str] = set([rid])
            q = deque([(rid, 0)])
            edges_accum: List[PathEdge] = []

            while q:
                cur, depth = q.popleft()
                if depth >= max_depth:
                    continue
                neighbors = self.g.neighbors(cur) if self.prefer_upstream_direction else self.g.reverse_neighbors(cur)
                for e in neighbors:
                    # make sure the direction is from src to dst
                    nxt = e.dst if self.prefer_upstream_direction else e.src
                    if nxt in visited:
                        continue
                    # core novel part -- restrict by time
                    if time_constrained:
                        src_time = self.g.nodes[cur].time
                        nxt_time = self.g.nodes.get(nxt, Node(nxt, "", "")).time
                        basis = src_time or start_time
                        if basis and nxt_time and nxt_time < basis:
                            continue
                    visited.add(nxt)
                    q.append((nxt, depth + 1))
                    edges_accum.append(
                        PathEdge(src=e.src, dst=e.dst) if self.prefer_upstream_direction
                        else PathEdge(src=e.dst, dst=e.src)
                    )
        
            depth_factor = 1.0 if not edges_accum else max(0.3, 1.0 - 0.05 * len(edges_accum))
            conf = max(0.0, min(1.0, root.confidence * depth_factor))

            ev = [EvidenceItem(source="osv"), EvidenceItem(source="nvd")]
            refs.append(ReferencePath(cve_id=root.cve_id, root_id=rid, path=edges_accum, evidence=ev, confidence=conf))
        
        return refs

if __name__ == "__main__":

    ap = argparse.ArgumentParser(description="Ground-truth-like reference constructor for vulnerability diffusion studies.")
    ap.add_argument("--dep-graph", required=True)
    ap.add_argument("--cve-meta", required=False, default=None, help="Pre-cached mixed CVE metadata (JSONL): each line has {'source': 'osv'|'nvd', 'data': {...}}")
    # keep smoke-test for quick sanity checks
    ap.add_argument("--smoke-test", action="store_true", help="Run an in-memory example (ignores file inputs)")

    ap.add_argument("--out-root", required=True)
    ap.add_argument("--out-paths", required=True)
    ap.add_argument("--downstream", action="store_true")
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--no-time-constraint", action="store_true")

    args = ap.parse_args()
    t0 = time.time()

    # ---- load inputs ---------
    if args.smoke_test:
        g_obj = smoke_dep_graph()
        osv = smoke_osv_jsonl()
        nvd = smoke_nvd_jsonl()
        G = DepGraph.from_json(g_obj)

    else:
        if not args.dep_graph:
            ap.error("--dep-graph is required unless --smoke-test is used.")
        G = _safe_load_pickle(Path(args.dep_graph))

        # If pre-cached meta is provided, split to OSV/nü d for the builder
        if args.cve_meta:
            cve_meta = _safe_load_pickle(Path(args.cve_meta))
            osv_records, nvd_records = split_cve_meta_to_builder_inputs(cve_meta)
        else:
            osv_records, nvd_records = [], []

    # ---- Build roots & paths -------
    builder = GTBuilder(
        dep_graph=G,
        osv_records=osv_records,
        nvd_records=nvd_records,
        prefer_upstream_direction=not args.downstream
    )

    t1 = time.time()
    roots = builder.build_root_causes()
    t2 = time.time()
    paths = builder.build_reference_paths(
        roots=roots, max_depth=args.max_depth, time_constrained=not args.no_time_constraint
    )
    t3 = time.time()

    # -------- Write outputs ----------
    write_jsonl(args.out_root, (r.to_json() for r in roots))
    write_jsonl(args.out_paths, (p.to_json() for p in paths))

    # -------- Summary ----------
    print(f"[Summary]")
    print(f"  Nodes: {len(G.nodes)} | Edges: {sum(len(v) for v in G.adj.values())}")
    print(f"  CVEs (OSV): {len(osv_records)} | CVEs (NVD): {len(nvd_records)}")
    print(f"  Roots: {len(roots)} | Paths: {len(paths)}")
    print(f"[Timing]")
    print(f"  Load/Init: {(t1 - t0)*1000:.1f} ms")
    print(f"  Roots    : {(t2 - t1)*1000:.1f} ms")
    print(f"  Paths    : {(t3 - t2)*1000:.1f} ms")
    print(f"  Total    : {(t3 - t0)*1000:.1f} ms")