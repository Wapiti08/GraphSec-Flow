'''
 # @ Create Time: 2025-10-29 10:59:00
 # @ Modified time: 2025-10-29 10:59:51
 # @ Description: merge release to family to check potentially efficient propagation paths
 '''

import re

# -------- define common ecosystem family_map ----------

FAMILY_MAP = {
    # Apache eco
    "org.apache.tomcat": "tomcat",
    "org.apache.tomcat.embed": "tomcat",
    "org.apache.hadoop": "hadoop",
    "org.apache.kafka": "kafka",
    "org.apache.camel": "camel",
    "org.apache.nifi": "nifi",
    "org.apache.struts": "struts",
    "org.apache.commons": "commons",
    "org.apache.httpcomponents": "httpclient",
    "org.apache.spark": "spark",

    # Spring & Java eco
    "org.springframework": "spring",
    "org.springframework.boot": "spring",
    "com.fasterxml.jackson": "jackson",
    "org.slf4j": "slf4j",
    "ch.qos.logback": "logback",
    "io.netty": "netty",
    "com.google.guava": "guava",
    "com.alibaba.fastjson": "fastjson",
    "junit": "junit",

    # RedHat / Keycloak
    "org.keycloak": "keycloak",
    "org.wildfly": "wildfly",
}


# ----------- merge family key ---------------
def _family_key(group: str, artifact: str) -> str:
    """
    Normalize and merge related artifacts under one family name.
    Combines explicit FAMILY_MAP + heuristic rules.
    """
    for prefix, fam in FAMILY_MAP.items():
        if group.startswith(prefix):
            return fam

    base = artifact.lower().strip()
    # remove common extension
    base = re.sub(r"-(embed|core|common|client|starter|server|runtime|impl|lib|api|all|bundle|parent)$", "", base)

    # normalize commone pre-fix
    base = re.sub(r"^spring-boot-", "spring-", base)
    base = re.sub(r"^spring-", "spring", base)
    base = re.sub(r"^hadoop-", "hadoop", base)
    base = re.sub(r"^jackson-", "jackson", base)
    base = re.sub(r"^commons-", "commons", base)
    base = re.sub(r"^log4j-", "log4j", base)

    # keyword merge
    if "tomcat" in base:
        base = "tomcat"
    elif "keycloak" in base:
        base = "keycloak"
    elif "camel" in base:
        base = "camel"
    elif "nifi" in base:
        base = "nifi"
    elif "spark" in base:
        base = "spark"
    elif "kafka" in base:
        base = "kafka"
    elif "hadoop" in base:
        base = "hadoop"
    elif "struts" in base:
        base = "struts"

    # if too short, return to group info
    if len(base) < 3:
        if "apache" in group:
            base = "apache"
        elif "springframework" in group:
            base = "spring"
        elif "fasterxml" in group:
            base = "jackson"

    return base

# --------- construct release index ----------
def build_release_index_from_depgraph(G):
    """
    Build a mapping from artifact family to [(node_id, release, timestamp)].
    Families merge related artifacts across groups and submodules.
    """
    idx = {}

    for nid, node in G.nodes.items():
        attrs = getattr(node, "__dict__", node) if not isinstance(node, dict) else node
        rel = attrs.get("release")
        if not rel or rel.count(":") < 2:
            pkg = attrs.get("package") or attrs.get("group")
            ver = attrs.get("version")
            if not (pkg and ver):
                continue
            rel = f"{pkg}:{ver}"

        parts = rel.split(":")
        group, artifact = parts[0].lower(), parts[1].lower()
        fam = _family_key(group, artifact)

        ts = 0
        t = attrs.get("timestamp") or attrs.get("time")
        if t:
            try:
                if hasattr(t, "timestamp"):
                    ts = t.timestamp()
                elif isinstance(t, (int, float)):
                    ts = t
            except Exception:
                pass

        idx.setdefault(fam, []).append((nid, rel, ts))

    for k in idx:
        idx[k].sort(key=lambda x: x[2] or 0)

    return idx


# print out family coverage result
def debug_families(release_index, topn=20):
    print(f"[family] total families = {len(release_index)}")
    for k, lst in sorted(release_index.items(), key=lambda x: -len(x[1]))[:topn]:
        ts_values = [x[2] for x in lst if x[2]]
        t_min = min(ts_values) if ts_values else 0
        t_max = max(ts_values) if ts_values else 0
        print(f"  {k:<20} count={len(lst):<6}  time_range=({t_min:.0f}, {t_max:.0f})")
