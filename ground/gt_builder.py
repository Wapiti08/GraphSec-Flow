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

CLI:
    python gt_builder.py \
        --dep-graph dep_graph.json \
        --osv osv.jsonl --nvd nvd.jsonl \
        --maintainer maintainer.jsonl \
        --out-root root_causes.jsonl \
        --out-paths ref_paths.jsonl

 '''
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

from ground.helper import *
import argparse
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Iterable, Set, Any
from collections import defaultdict, deque
from datetime import datetime, timezone
from utils.util import read_jsonl, write_jsonl
from ground.helper import smoke_dep_graph, smoke_nvd_jsonl, smoke_osv_jsonl, read_jsonl, split_cve_meta_to_builder_inputs
import time
from cve.cvescore import _osv_extract_fix_commits
# --------------------------------
# Data Models
# --------------------------------

@dataclass
class EvidenceItem:
    source: str
    fields: Dict[str, Any] = field(default_factory=dict)

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
                sv = SemVer.parse(str(v))
                if sv:
                    versions.add(str(sv))
        return versions
    
    @staticmethod
    def _collect_ranges(record: Dict[str, Any]) -> List[VersionRange]:
        ranges: List[VersionRange] = []
        for key in ("introduced", "affected", "fixed"):
            vals = record.get(key) or []
            if isinstance(vals, str):
                vals = [vals]
            for expr in vals:
                try:
                    ranges.append(VersionRange.parse(str(expr)))
                except Exception:
                    continue
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

    def _candidate_nodes_for_package(self, package: str) -> List[Node]:
        return [n for n in self.g.nodes.values() if n.package == package]

    def _match_nodes_by_versions_or_ranges(self, nodes: List[Node], versions_set: Optional[Set[str]], ranges: List[VersionRange]) -> List[Node]:
        if versions_set:
            vers = set(versions_set)
            matched = []
            for n in nodes:
                sv = SemVer.parse(n.version)
                if sv and str(sv) in vers:
                    matched.append(n)
            if matched:
                return matched
        if not ranges:
            return nodes
        matched = []
        for n in nodes:
            sv = SemVer.parse(n.version)
            if not sv:
                continue
            if any(r.contains(sv) for r in ranges):
                matched.append(n)
        return matched


    def _earliest_node(self, nodes: List[Node]) -> Optional[Node]:
        if not nodes:
            return None
        nodes_sorted = sorted(nodes, key=lambda x: (x.time or datetime.max, SemVer.parse(x.version) or SemVer(9999, 9999, 9999)))
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
            for r in records:
                cve = r.get("cve_id") or r.get("id")
                if not cve:
                    continue
                pkg = self._package(r)
                versions_set: Set[str] = set()
                if source == "OSV":
                    versions_set = self._osv_extract_versions(r)
                    if not pkg:
                        pkg = self._osv_infer_package(r)
                if not pkg:
                    continue
                
                ranges = self._collect_ranges(r)
                candidates = self._match_nodes_by_versions_or_ranges(self._candidate_nodes_for_package(pkg), versions_set or None, ranges)
                bucket = by_cve[cve]["packages"][pkg]
                bucket["nodes"].extend(candidates)
                bucket["sources"].add(source)
                bucket["fix_commits"].update(self._fix_commits(r))

                ev_fields = {"published": r.get("published")}
                if source == "OSV":
                    has_git = any((rng.get("type") == "GIT") for af in (r.get("affected") or []) for rng in (af.get("ranges") or []))
                    ev_fields.update({"versions_count": len(versions_set), "has_git_ranges": has_git})
                bucket["evidence"].append(EvidenceItem(source=source, fields=ev_fields))

        ingest(self.osv, "OSV")
        ingest(self.nvd, "NVD")

        roots: List[RootCause] = []
        for cve, group in by_cve.items():
            for pkg, item in group["packages"].items():
                nodes_unique: Dict[str, Node] = {n.id: n for n in item["nodes"]}
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
        return roots

    def build_reference_paths(self, roots: List[RootCause], max_depth: int = 6, time_constrained: bool = True) -> List[ReferencePath]:
        refs: List[ReferencePath] = []

        def node_id(pkg: str, ver: str) -> str:
            return f"{pkg}@{ver}"
        
        for root in roots:
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

            ev = [EvidenceItem(source="OSV"), EvidenceItem(source="NVD")]
            refs.append(ReferencePath(cve_id=root.cve_id, root_id=rid, path=edges_accum, evidence=ev, confidence=conf))
        
        return refs

def main():

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
    else:
        if not args.dep_graph:
            ap.error("--dep-graph is required unless --smoke-test is used.")
        g_obj = read_jsonl(args.dep_graph)

        # If pre-cached meta is provided, split to OSV/NVD for the builder
        if args.cve_meta:
            cve_meta = read_jsonl(args.cve_meta)
            osv_records, nvd_records = split_cve_meta_to_builder_inputs(cve_meta)
        else:
            osv_records, nvd_records = [], []

    G = DepGraph.from_json(g_obj)

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




    





