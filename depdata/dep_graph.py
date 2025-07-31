'''
 # @ Create Time: 2024-11-17 12:01:10
 # @ Modified time: 2024-11-17 12:01:21
 # @ Description: extract the dependency nodes only and construct new dependency based on timeline info
 '''

from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path
import logging
import pickle
import networkx as nx
from functools import partial
from tqdm import tqdm
import os
import uuid
import json
import random

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('dep_graph.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


# Define a wrapper function for processing chunks
def process_wrapper(chunk,release_nodes, time_ranges, nodes, rel_to_soft, get_timestamp, is_release):
        return process_edges_chunk(
            chunk, release_nodes, time_ranges, nodes, rel_to_soft, get_timestamp, is_release
    )


def process_edges_chunk(chunk, release_nodes, time_ranges, nodes, rel_to_soft, 
                    get_timestamp, is_release):
    """
    Worker function to process a chunk of edges.
    """
    local_graph = nx.DiGraph()
    rel_to_soft_map = rel_to_soft()
    for src, tgt, _ in chunk:
        if is_release(nodes[src]):  # Only consider release nodes for the source
            src_range = time_ranges.get(src, (0, float('inf')))
            if not is_release(nodes[tgt]):  # If the target is a software node
                # Get all releases for the target software
                if tgt in rel_to_soft_map:  # Check if the software has associated releases
                    for release in rel_to_soft_map[tgt]:  # Iterate through all releases of the software
                        if release in release_nodes:  # Ensure the release exists in the graph
                            tgt_timestamp = get_timestamp(nodes[release])  # Timestamp of the target release
                            if src_range[0] <= tgt_timestamp < src_range[1]:  # Check if within range
                            
                                # add src node attributes
                                if src not in local_graph:
                                    print('111111')
                                    print(nodes[src])
                                    local_graph.add_node(src, **{
                                        'version': nodes[src].get('version', ''),
                                        'timestamp': nodes[src].get('timestamp', '')
                                    })

                                # add tgt node attributes
                                if release not in local_graph:
                                    print('222222')
                                    print(nodes[release])
                                    local_graph.add_node(release, **{
                                        'version': nodes[release].get('version', ''),
                                        'timestamp': nodes[release].get('timestamp', '')
                                    })

                                local_graph.add_edge(src, release)  # Add edge between releases
                                
            elif is_release(nodes[tgt]):  # If the target is also a release
                tgt_timestamp = get_timestamp(nodes[tgt])  # Timestamp of the target release
                if src_range[0] <= tgt_timestamp < src_range[1]:
                    local_graph.add_edge(src, tgt)  # Add direct edge between releases
    
    # save the subgraph to disk
    subgraph_file = Path.cwd().parent.joinpath('data', f"subgraph_{os.getpid()}_{uuid.uuid4().hex}.graphml")
    nx.write_graphml(local_graph, subgraph_file)

    return subgraph_file

class DepGraph:
    def __init__(self, nodes, edges):
        self.nodes = nodes
        self.edges = edges
        self.get_addvalue_edges()

    def str_to_json(self, escaped_json_str):
        try:
            clean_str = escaped_json_str.replace('\\"', '"')
            return json.loads(clean_str)
        except ValueError as e:
            print(f"Error parsing JSON: {e}")
            return None

    def get_addvalue_edges(self,):
        # source node is release, target node is addedvalue
        self.addvalue_dict = defaultdict(list)

        # Iterate over the edges and add the targets for each source where the label is 'addedValues'
        for source, target, edge_att in self.edges:
            if edge_att['label'] == "addedValues":
                self.addvalue_dict[source].append(target)

    def cve_check(self, target:str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "CVE" and self.str_to_json(node["value"])['cve'] !=[]:
                return True
            else:
                return False

    def get_timestamp(self, node: dict):
        return int(node.get("timestamp", 0))
    
    def covt_ngb_format(self,):
        node_ngbs = {}

        for source, target in self.edges:
            node_ngbs.setdefault(source, []).append(target)
        
        return node_ngbs

    def is_release(self, node: dict):
        if node["labels"] == ":Release":
            return True
        else:
            return False

    def get_releases(self,):
        return {node_id: data for node_id, data in self.nodes.items() if data['labels'] == ":Release"}
    
    def get_cve_releases(self,):
        return {node_id: data for node_id, data in self.nodes.items() if data['labels'] == ":Release" and self.cve_check(node_id)}

    def rel_to_soft(self):
        ''' build the dict to map parent software to release
        
        '''
        release_to_software = {}

        for src, tgt, attr in self.edges:
            if attr['label'] == "dependency":
                # source is software, target is release
                release_to_software[tgt] = src
            elif attr['label'] == 'relationship_AR':
                release_to_software[src] = tgt

        return release_to_software

    def soft_to_rel(self, release_to_software: dict):
        ''' group releases by software using the mapping
        
        '''
        software_releases = defaultdict(list)

        for release, software in release_to_software.items():
            timestamp = self.get_timestamp(self.nodes[release])  
            software_releases[software].append((release, timestamp))

        # sort releases for each software by timestamp
        for software, releases in software_releases.items():
            software_releases[software] = sorted(releases, key=lambda x: x[1])

        return software_releases

    def time_ranges(self, software_to_release: dict):
        timestamp_ranges = {}
        for software, releases in software_to_release.items():
            timestamps = [ts for _, ts in releases] + [float('inf')]  # Add open-ended range
            for i, (nid, timestamp) in enumerate(releases):
                timestamp_ranges[nid] = (timestamp, timestamps[i + 1])
        return timestamp_ranges

    def filter_edges(self,):
        for src, tgt, attr in self.edges:
            if attr['label'] in {'dependency', 'relationship_AR'}:
                yield (src, tgt if attr['label'] == 'dependency' else tgt, src)
    
    def chunk_generator(self, generator, chunk_size):
        """
        Breaks a generator into chunks of size `chunk_size`.
        """
        chunk = []
        for item in generator:
            chunk.append(item)
            if len(chunk) == chunk_size:
                yield chunk
                chunk = []
        if chunk:  # Yield remaining items
            yield chunk

    def dep_graph_build_parallel(self, filter_edges, time_ranges):
        """
        Parallelized version of dep_graph_build.
        """
        # Get release nodes
        # release_nodes = self.get_releases()
        release_nodes = self.get_cve_releases()
        # Precompute other reusable data
        nodes = self.nodes
        rel_to_soft = self.rel_to_soft
        get_timestamp = self.get_timestamp
        is_release = self.is_release
        
        # Split edges into chunks for parallel processing
        num_processes = cpu_count()
        print('Available cpu count is', num_processes)

        # get the total number of edges
        filter_edges = list(filter_edges)
        total_edges = len(filter_edges)

        # self-adaptive chunk size based on the number of edges and processes
        factor = 4
        chunk_size = max(1, total_edges // (num_processes * factor))
        print(f"Total edges: {total_edges}, Chunk size per process: {chunk_size}")

        edge_chunks = self.chunk_generator(filter_edges, chunk_size)
        
        # Use multiprocessing pool to process chunks in parallel
        with Pool(processes=num_processes) as pool:
            subgraph_files = list(tqdm(
                pool.imap(
                    partial(process_wrapper,  # Pass the global function
                            release_nodes=release_nodes, time_ranges=time_ranges, nodes=nodes,
                            rel_to_soft=rel_to_soft, get_timestamp=get_timestamp, 
                            is_release=is_release),
                    edge_chunks
                ),
                desc="Parallel graph build",
            ))

        # Combine all subgraphs into one graph
        combined_graph = nx.DiGraph()
        for subgraph_file in subgraph_files:
            subgraph = nx.read_graphml(subgraph_file)
            combined_graph.update(subgraph)
            os.remove(subgraph_file)
        
        return combined_graph

    def graph_save(self, new_graph, graph_path):
        with graph_path.open('wb') as fw:
            pickle.dump(new_graph, fw)
    
    def graph_load(self, graph_path):
        with graph_path.open('rb') as fr:
            return pickle.load(fr)


def load_data(file_path):
    with file_path.open('rb') as f:
        data = pickle.load(f)
    
    return data['nodes'], data['edges']

if __name__ == "__main__":

    nodes_edges_path = Path.cwd().parent.joinpath("data", 'graph_nodes_edges.pkl')
    nodes, edges = load_data(nodes_edges_path)

    dep_graph_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    depgraph = DepGraph(nodes, edges)
    
    if not dep_graph_path.exists():
        release_to_software = depgraph.rel_to_soft()
        software_releases = depgraph.soft_to_rel(release_to_software)
        time_rangs = depgraph.time_ranges(software_releases)

        # get the filtered edges
        filter_edges = depgraph.filter_edges()

        graph = depgraph.dep_graph_build_parallel(filter_edges, time_rangs)
        # save graph
        depgraph.graph_save(graph, dep_graph_path)

    else:
        G = depgraph.graph_load(dep_graph_path)