import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from lxml import etree
import pickle
from cent import between_cent, degree_cent, eigen_cent
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('cent_cal.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


def parse_graphml_in_chunks(file_path):
    context = etree.iterparse(file_path, events=("start", "end"))
    nodes = {}
    edges = []
    
    for event, elem in context:
        if event == "end" and elem.tag == "{http://graphml.graphdrawing.org/xmlns}node":
            # Process node
            node_id = elem.attrib['id']
            # Extract other attributes if needed, e.g. CVE_Severity
            attributes = {data.attrib['key']: data.text for data in elem.findall("{http://graphml.graphdrawing.org/xmlns}data")}
            nodes[node_id] = attributes
            elem.clear()  # Clear memory

        elif event == "end" and elem.tag == "{http://graphml.graphdrawing.org/xmlns}edge":
            # Process edge
            source = elem.attrib['source']
            target = elem.attrib['target']
            # Extract edge attributes
            attributes = {data.attrib['key']: data.text for data in elem.findall("{http://graphml.graphdrawing.org/xmlns}data")}
            edges.append((source, target, attributes))
            elem.clear()  # Clear memory
            
    return nodes, edges

def save_data(nodes, edges, file_path):
    with file_path.open('wb') as f:
        pickle.dump({'nodes': nodes, 'edges': edges}, f)        
    

def load_data(file_path):
    with file_path.open('rb') as f:
        data = pickle.load(f)
    return data['nodes'], data['edges']


def match_top_nodes_to_ids(top_nodes, nodes):
    ''' Map top nodes by centrality to their corresponding `id` in the nodes dictionary. '''
    matched_nodes = []

    for node_id, centrality_score in top_nodes:
        node_info = nodes.get(node_id)
        
        if node_info and "id" in node_info:
            matched_nodes.append((node_info["id"], centrality_score))

    return matched_nodes

if __name__ == "__main__":

    # dep_graph_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")
    # with dep_graph_path.open('rb') as fr:
    #     G = pickle.load(fr)
    

    graph_path = Path.cwd().parent.joinpath("data", 'graph_nodes_edges.pkl')

    if  graph_path.exists():
        logger.info("Loading nodes and edges from saved file.")
        nodes, edges = load_data(graph_path)
    else:
        file_path = Path.cwd().parent.joinpath("data", "graph_metric.graphml").as_posix()
        logger.info("Parsing nodes and edges from GraphML.")
        # generate nodes and edges from graphml
        now = datetime.now()
        nodes, edges = parse_graphml_in_chunks(file_path)
        logger.info(f"Time spent for node loading from graphml is: {datetime.now() - now}")
    #     save_data(nodes, edges, graph_path)

    # ------ calculate the degree_centrality ------
    # top_degree_cel = degree_cent.cal_degree_centrality(nodes, edges)
    # addvalue_edges_dict = degree_cent.get_addvalue_edges(edges)
    # top_degree_cel = degree_cent.cal_degree_software_with_cve(nodes, edges, addvalue_edges_dict)
    # logger.info(f"the top 10 nodes with highest degree centrality are: {top_degree_cel}")
    # logger.info(f"the top 10 node ids with highest degree centrality are: {match_top_nodes_to_ids(top_degree_cel, nodes)}")

    # top_degree_cel = degree_cent.cal_degree_release_with_cve(nodes, edges, addvalue_edges_dict)
    # logger.info(f"the top 10 nodes with highest degree centrality are: {top_degree_cel}")
    # logger.info(f"the top 10 node ids with highest degree centrality are: {match_top_nodes_to_ids(top_degree_cel, nodes)}")
    # # ------ calculate the between_centrailty --------
    # print("the length of nodes is:", len(list(nodes.keys())))
    # print("the length of edges is:", len(edges))
    
    # betcenter = between_cent.BetCent(nodes, edges)
    # betcenter.get_addvalue_edges()
    # top_between_cel = betcenter.cal_between_cent_nx()
    # logger.info("The result with min_severity_threshold is:")
    # logger.info(f"the top 10 nodes with highest betweenness centrality are: {top_between_cel}")
    # logger.info(f"the top 10 node ids with highest betweenness centrality are: {match_top_nodes_to_ids(top_between_cel, nodes)}")



    # ------ calculate the eigenvector centrality ------

    sever_score_map = {
    "CRITICAL": 4,
    "HIGH":3, 
    "MODERATE":2,
    "LOW":1
    }
    att_features = ["freshness", "popularity", "speed", "severity"]

    eigencenter = eigen_cent.EigenCent(nodes, edges, att_features, sever_score_map)
    # generate addvalues nodes
    # process node attribute values to right format
    # eigencenter._quan_attrs()
    fea_matrix_path = Path.cwd().parent.joinpath("data", "fea_matrix.csv")

    eigencenter._covt_df(fea_matrix_path)
    
    # eigencenter._step_wise_reg(0.05, att_features)
    # analyse processed attributes
    eigencenter._weight_ana()
    # eigencenter.ave_weight()

    # get the eigen centrality
    top_eigen_nodes = eigencenter.cal_weighted_eigen_cent_nx()
    logger.info(f"the top 10 nodes with highest eigen centrality are: {top_eigen_nodes}")
    logger.info(f"the top 10 node ids with highest eigen centrality are: {match_top_nodes_to_ids(top_eigen_nodes, nodes)}")

