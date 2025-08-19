'''
 # @ Create Time: 2025-08-19 14:42:13
 # @ Modified time: 2025-08-19 15:44:22
 # @ Description: vector the description of CVE vulnerabilities
 '''


from typing import List, Optional, Union
import numpy as np

class CVEVector:
    '''
    use sentenc e transformers to vectorize the description of CVE vulnerabilities
    - default model: 'sentence-transformers/all-MiniLM-L6-v2'
    - output is normalized with L2
    
    '''
    def __init__(self,
                 model_name_or_path: str = "sentence-transformers/all-MiniLM-L6-v2",
                 normalize: bool = True,
                 device: Optional[str] = None,
                 batch_size: int = 32):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise ImportError("Please install sentence-transformers: pip install sentence-transformers") from e

        self._SentenceTransformer = SentenceTransformer
        self.model = SentenceTransformer(model_name_or_path, device=device)
        self.normalize = normalize
        self.batch_size = batch_size
    
    def _l2_norm(self, x: np.ndarray) -> np.ndarray:
        ''' normalize vector with L2 norm '''
        if x.ndim == 1:
            