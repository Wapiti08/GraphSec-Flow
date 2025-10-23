# GraphSec-Flow
dependency propagation analyser on graphs
![Python](https://img.shields.io/badge/Python3-3.10.13-brightgreen.svg) 


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
pip3 install -r requirmentst.txt

```

## How to use

- generate cve enriched dependency graph
```
cd cve
python3 graph_cve.py --dep_graph {your local path}/data/dep_graph.pkl --cve_json {your local path}/data/aggregated_data.json --nodes_pkl {your local path}/data/graph_nodes_edges.pkl --augment_graph {your local path}/data/dep_graph_cve.pkl
```
 
- generate ground truth data
```
python3 gt_builder.py --dep-graph /workspace/GraphSec-Flow/data/dep_graph_cve.pkl --cve-meta /workspace/GraphSec-Flow/data/cve_records_for_meta.pkl --out-root /workspace/GraphSec-Flow/data/root_causes.jsonl --out-paths /workspace/GraphSec-Flow/data/ref_paths.jsonl
```

- Root Cause Analysis
```
python3 root_ana.py --cve_id "CVE-2017-5650"
```

- Root Cause Path Analysis
```
python3 path_track.py --aug_graph /workspace/GraphSec-Flow/data/dep_graph_cve.pkl --paths_jsonl /workspace/GraphSec-Flow/result/result.json --subgraph_gexf  /workspace/GraphSec-Flow/result/result.gexf --t_start 1021437154000 --t_end 1724985046000
```

- Benchmark
```
nohup python3 benchmark.py > bench.txt 2>&1 &
```


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
