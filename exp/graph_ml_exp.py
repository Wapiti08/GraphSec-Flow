from pathlib import Path
import networkx as nx
import pickle
from lxml import etree
from itertools import islice

# Paths
graph_data_path = Path.cwd().parent.joinpath("data", "graph_metric.graphml")
file_path = Path.cwd().parent.joinpath("data", "graph_nodes_edges.pkl")

# Efficient XML parsing: use iterparse to load nodes and edges incrementally
# We are interested in only the first 10 nodes and 10 edges, so we stop once we have them
nodes = []
edges = []

# Use iterparse for incremental parsing of XML
context = etree.iterparse(graph_data_path, events=('end',))

for event, elem in context:
    if elem.tag == 'node' and len(nodes) < 10:
        nodes.append(elem)  # Save the node element
    elif elem.tag == 'edge' and len(edges) < 10:
        edges.append(elem)  # Save the edge element
    
    # Break early if both are collected
    if len(nodes) == 10 and len(edges) == 10:
        break
    
    # Clear the element to reduce memory usage
    elem.clear()

# Print the top 10 nodes and edges
print("Top 10 nodes:")
for node in nodes:
    print(node.attrib)  # Print node attributes or other relevant info

print("\nTop 10 edges:")
for edge in edges:
    print(edge.attrib)  # Print edge attributes or other relevant info

# Load the data from the .pkl file
with open(file_path, 'rb') as file:
    data = pickle.load(file)

# Only iterate over the first 10 items
for key, value in islice(data.items(), 10):
    try:
        # If value is a pandas Series/DataFrame, show only the first 5 rows
        if isinstance(value, (pd.Series, pd.DataFrame)):
            snippet = value.head()  # Only show the head of the Series/DataFrame
        else:
            # For other types, just show a truncated version of the output
            snippet = str(value)[:500]  # Limit the output to 500 characters
    except Exception as e:
        # In case of any other unexpected error, print a basic summary
        snippet = str(value)[:500]
        
    print(f"{key!r} → {snippet}")
