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
            denom = np.linalg.norm(x) + 1e-12
            return (x / denom).astype(np.float32)
        elif x.ndim == 2:
            denom = np.linalg.norm(x, axis=1, keepdims=True) + 1e-12
            return (x / denom).astype(np.float32)
        return x.astype(np.float32)
    
    def encode(self, text: Optional[str]) -> np.ndarray:
        if text is None:
            text = ""
        emb = self.model.encode(
            text,
            batch_size=1,
            convert_to_numpy=True,
            # use manual embedding
            normalize_embeddings=False,
            show_progress_bar=False
        )

        if self.normalize:
            emb = self._l2_norm(emb)
        else:
            emb = emb.astype(np.float32)
        return emb
    
    def batch_encode(self, texts: Union[List[str], np.ndarray]) -> List[np.ndarray]:
        # replace None with blank string to avoid processing error
        texts = [("" if t is None else str(t)) for t in list(texts)]
        embs = self.model.encode(
            texts,
            batch_size = self.batch_size,
            convert_to_numpy=True,
            normalize_embeddings=False,
            show_progress_bar=False
        ) # shape: [N, dim]

        if self.normalize:
            emb = self._l2_norm(emb)
        else:
            emb = emb.astype(np.float32)
        # vamana expect list[np.ndarray]
        return [embs[i] for i in range(embs.shape[0])]
    
    
    
