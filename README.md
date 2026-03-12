# GraphSec-Flow
![Python](https://img.shields.io/badge/Python3-3.10.13-brightgreen.svg) 

Temporal dependency propagation and root-cause analysis for OSS ecosystems

## Structure

- cause: causality analysis part, implementation of custom DAS, the code to generate two files with CVE related features (one-hop neighbor, two-hop neighbor)

- cent: three centrality measurement methods: degree (three directions), betweenness, and eigenvector

- data: extracted other format data sets

- exp: the exploration code on different files, code to call diverse centrality measurement, notebooks to visualize data and perform stastical analysis

- process: the code to call neo4j and export other formats of graphs, like graphml and csv

## Instructions
- How to install Goblin Weaver
```
java -Dneo4jUri="bolt://localhost:7687/" -Dneo4jUser="neo4j" -Dneo4jPassword="password" -jar goblinWeaver-2.1.0.jar
```

## Data Export
- configuration of neo4j.conf: add the following lines to conf file to enable apoc output
```
dbms.security.procedures.unrestricted=apoc.*
dbms.security.procedures.allowlist=apoc.*
apoc.export.file.enabled=true
```

- run script:
```
# export dump into graphml and csv formats
python3 data_export.py
```

## Running Instructions 
(tested on macOS and Ubuntu 20.04.5 LTS for small-scale data)

```
# configure virtualenv environment
curl https://pyenv.run | bash
export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# specify python version
pyenv install 3.10
pyenv global 3.10

# create local environment
pyenv virtualenv 3.10 GraphSec-Flow
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
pyenv activate GraphSec-Flow

# upgrade building tools - avoid compatibility problem
python -m pip install -U pip setuptools wheel build

sudo apt-get update
sudo apt-get install -y build-essential libffi-dev libssl-dev zlib1g-dev \
  libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev tk-dev uuid-dev

# download dependencies
pip3 install -r requirements.txt

```

## How to use

- generate cve enriched dependency graph
```
cd cve
python3 graph_cve.py --dep_graph {your local path}/data/dep_graph.pkl --cve_json {your local path}/data/aggregated_data.json --nodes_pkl {your local path}/data/graph_nodes_edges.pkl --augment_graph {your local path}/data/dep_graph_cve.pkl
```
 
- generate ground truth data
```
# with depth 3 without time constraint:
python3 gt_builder_parallel.py   --dep-graph /workspace/GraphSec-Flow/data/dep_graph_cve.pkl   --cve-meta /workspace/GraphSec-Flow/data/cve_records_for_meta.pkl   --out-root /workspace/GraphSec-Flow/data   --out-paths /workspace/GraphSec-Flow/data   --no-time-constraint   --max-depth 3   --num-workers 64
```

- Root Cause Analysis
```
python3 root_ana.py --cve_id "CVE-2017-5650"
```

- Root Cause Path Analysis
```
python3 path_track.py --aug_graph /workspace/GraphSec-Flow/data/dep_graph_cve.pkl --paths_jsonl /workspace/GraphSec-Flow/result/result.json --subgraph_gexf  /workspace/GraphSec-Flow/result/result.gexf --t_start 1021437154000 --t_end 1724985046000
```

- Generate node lookup for manual validation:

```
python3 - << 'EOF'
import pickle, json, csv
from pathlib import Path

print("Loading graph...")
with open('data/dep_graph_cve.pkl', 'rb') as f:
    G = pickle.load(f)

node_ids = set()
with open('data/validation/manual_labels_predicted.csv') as f:
    for row in csv.DictReader(f):
        for nid in row['top_predicted_nodes'].split('|'):
            if nid.strip():
                node_ids.add(nid.strip())

print(f"Resolving {len(node_ids)} node IDs...")
result = {}
for nid in sorted(node_ids):
    if nid in G.nodes:
        d = G.nodes[nid]
        result[nid] = {
            'release': d.get('release', d.get('artifact', d.get('name', '?'))),
            'group':   d.get('group_id', d.get('groupId', '')),
            'artifact':d.get('artifact_id', d.get('artifactId', '')),
            'version': d.get('version', ''),
            'has_cve': d.get('has_cve', False),
        }
    else:
        result[nid] = {'release': 'NOT FOUND'}

with open('data/validation/node_lookup.json', 'w') as f:
    json.dump(result, f, indent=2)

for nid, info in result.items():
    r = info.get('release','')
    g = info.get('group','')
    a = info.get('artifact','')
    v = info.get('version','')
    label = f"{g}:{a}:{v}" if g and a else r
    print(f"  {nid:15s} → {label}")

print(f"\n✓ Saved to data/validation/node_lookup.json")
EOF
```
```

- Benchmark
```
python bench/run_all_eval.py   --gt data/gt_temporal.jsonl   --dep-graph data/dep_graph_cve.pkl   --cve-meta data/cve_records_for_meta.pkl   --node-texts data/nodeid_to_texts.pkl   --node-scores data/node_cve_scores.pkl   --output-dir results/  
 --max-samples 10

```

- Small Scale Validation Benchmark

```
# for small graph
nohup python bench/benchmark_opt.py --dep-graph data/dep_graph_cve_2hop.pkl --ref-layer data/ref_paths_layer_3.jsonl --node-texts data/nodeid_to_texts.pkl --cve-meta data/cve_records_for_meta.pkl --per-cve data/per_cve_scores.pkl --node-scores data/node_cve_scores.pkl > logs/benchmark_2hop_g3_baseline.txt 2>&1 &
# for full graph
nohup python bench/benchmark_opt.py --dep-graph data/dep_graph_cve.pkl --ref-layer data/ref_paths_layer_3.jsonl --node-texts data/nodeid_to_texts.pkl --cve-meta data/cve_records_for_meta.pkl --per-cve data/per_cve_scores.pkl --node-scores data/node_cve_scores.pkl > logs/benchmark_g3_baseline.txt 2>&1 &

# for small graph
nohup python bench/benchmark_opt.py --dep-graph data/dep_graph_cve_2hop_random.pkl --ref-layer data/ref_paths_layer_3.jsonl --node-texts data/nodeid_to_texts.pkl --cve-meta data/cve_records_for_meta.pkl --per-cve data/per_cve_scores.pkl --node-scores data/node_cve_scores.pkl > logs/benchmark_2hop_g3_random.txt 2>&1 &
# for full graph
nohup python bench/benchmark_opt.py --dep-graph data/validation/dep_graph_cve_random_timestamps.pkl --ref-layer data/ref_paths_layer_3.jsonl --node-texts data/nodeid_to_texts.pkl --cve-meta data/cve_records_for_meta.pkl --per-cve data/per_cve_scores.pkl --node-scores data/node_cve_scores.pkl > logs/benchmark_g3_random.txt 2>&1 &

```

- Batch Prediction
```
nohup python3 validation/batch_predict.py --max-cves 100 > batch_predict_100.txt 2>&1 &
```

- Actionability Test
```
# need to finish batch_predict to generate results first
python validation/actionability.py -k_values 1 3 5 10 15 > logs/actionability_small_ks.txt
```

- Depth Validation (on sub graph)
```
python validation/depth_ablation.py \
    --dep-graph   data/dep_graph_cve_sub.pkl \
    --cve-meta data/cve_records_for_meta.pkl \
    --predictions data/validation/predictions.json \
    --depths 2 3 4 6 8 \
    --out         data/validation/depth_ablation_sub.json \
    2>&1 | tee logs/depth_ablation_sub.log

```

- 

## Ground-truth construction (silver, inferred)

We build a **silver** ground truth for evaluation using (i) earliest-affected release selection from OSV/NVD metadata and
(ii) a time-respecting, depth-bounded traversal to generate reference propagation edges. This GT is **inferred** (not manually verified).

### Algorithm 1: Root cause inference (earliest vulnerable release)

**Input:** vulnerability metadata (affected ranges `R`, optional fixing commits `F`, publication time), dependency graph `G`  
**Output:** inferred root-cause release node `r`

1. Resolve package id `p` from the advisory (name / repo URL).
2. Normalize semantic versions in affected ranges `R`.
3. Collect candidate releases `S = { s in G | package(s)=p and version(s) in R }`.
4. For each `s in S`, get release time `t(s)`.
5. Return `r = argmin_{s in S} t(s)`.

### Algorithm 2: Reference propagation path generation (depth-bounded)

**Input:** root `r`, graph `G`, max depth `d_max`  
**Output:** reference edge set `P`

1. Initialize queue `Q = [(r,0)]`, set `P = ∅`.
2. While `Q` not empty:
   - Pop `(u,d)`. If `d == d_max`, continue.
   - For each downstream dependent release `v` of `u` in `G`:
     - If `release_time(v) >= release_time(u)`:
       - Add edge `(u → v)` to `P`
       - Push `(v, d+1)` into `Q`
3. Return `P`

See `docs/ground_truth.md` for the full LaTeX version and validation checks.

## Statistical Analysis (extra material)

- Distributed of Number of Packages per CVE (Top 100):
    
    ![Distributed of Number of Packages per CVE (Top 100)](imgs/number_of_packages.png)

- Releases by number of CVEs (Top 6):

    ![Releases by number of CVEs (Top 6)](imgs/releases_by_num_cve.png)

- Top 10 Packages with Vulnerable Releases: 
    
    ![Top 10 Packages with Vulnerable Releases](imgs/top_10_degree_releases_with_cve.png)

- Top 10 Packages with Highest Degree Centrality:   

    ![Top 10 Packages with Highest Degree Centrality](imgs/top_10_degree_packs.png)

- Top 10 Vulnerable Releases with Highest Out-degree:

    ![Top 10 Vulnerable Releases with Highest Out-degree](imgs/top_10_degree_releases_with_cve.png)

- Top 10 Nodes Heatmap:

    ![Top 10 Nodes Heatmap](imgs/cent_heatmap.png)

- Package by number of CVEs:

    ![Package by number of CVEs](imgs/packages_by_num_cve.png)
