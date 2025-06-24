'''
 # @ Create Time: 2025-06-24 12:01:26
 # @ Modified time: 2025-06-24 12:01:28
 # @ Description: greedy search from the closest neighbors to a specified point in graph p
 '''
import numpy as np

class VamanaSearch:
    """ implementation of the vamana algorithm for approximate nearest neighbor search

    attributes:
        M: maximum number of edges per node
        ef_construction: size of the dynamic candidate list during construction
        data: list of vector (numpy arrays) 
        graph: adjacency list mapping node indicies to list of neighbor indices
    """
    def __init__(self, M=5, ef_construction=100):
        self.M = M
        self.ef_construction = ef_construction
        self.data = []
        self.graph = {}
        self.entry_point = None  # index of the graph entry point

    def _distance(self, a,b):
        ''' compute Eudlidean distance between two vectors a and b
        
        '''
        return np.linalg.norm(a - b)
    
    def _select_neighbors(self, candidates, M):
        ''' heuristic to select up to M best neighbors from candidates

        implements the "occlusion" heuristic: iterates in order of increasing distance,
        adds if it is not closer to any already chosen neighbor.
        
        '''
        selected = []
        for dist, idx in sorted(candidates, key=lambda x: x[0]):
            good = True
            for _, s in selected:
                # if candidate idx is closer to s than is s to idx, skip
                if self._distance(self.data[idx], self.data[s]) < dist:
                    good = False
                    break
            if good:
                selected.append((dist, idx))
            if len(selected) >= M:
                break  
        return [idx for _, idx in selected]

    def search(self, query, k=10):
        ''' approximate K-NN search for a query vector
        
        1. Start at entry_point
        2. Greedy search: move to neighbors if they are closer
        3. maintain a priority queue of visited candidates up to size ef.
        4. return top k unique points found
        '''
        if self.entry_point is None:
            return []
        




    def add_point(self, vector):
        ''' insert a new vector into the graph
        1. If first pint, initialize the graph and set entry point
        2. Else, search the graph to find ef_construction nearest neighbors,
        3. Select up to M neighbors using heuristic
        4. Link bi-directionally
        
        '''
        idx = len(self.data)
        self.data.append(np.array(vector))
        self.graph[idx] = []

        if self.entry_point is None:
            # first point
            self.entry_points = idx
            return
        
        # 1. Search for candidates using a best-first search
        




if __name__ == "__main__":

    v = VamanaSearch(M=8, ef_construction=200)
    for vec in dataset:
        v.add_point(vec)
    neighbors = v.search(query_vector, k=5)
