'''
 # @ Create Time: 2025-08-19 14:42:13
 # @ Modified time: 2025-08-19 15:44:22
 # @ Description: vector the description of CVE vulnerabilities
 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from typing import List, Optional, Union
import numpy as np
from cve.cveinfo import osv_cve_api

class CVEVector:
    '''
    use sentenc e transformers to vectorize the description of CVE vulnerabilities
    - default model: 'sentence-transformers/all-mpnet-base-v2'
    - output is normalized with L2
    
    '''
    def __init__(self,
                #  model_name_or_path: str = "sentence-transformers/all-mpnet-base-v2",
                 model_name_or_path: str = "ehsanaghaei/SecureBERT",
                 normalize: bool = True,
                 device: Optional[str] = None,
                 batch_size: int = 32):
        try:
            from sentence_transformers import SentenceTransformer, models
        except ImportError as e:
            raise ImportError("Please install sentence-transformers: pip install sentence-transformers") from e

        word_emb = models.Transformer(model_name_or_path)
        # 2) add mean pooling (CLS-free for RoBERTa)
        pooling = models.Pooling(word_emb.get_word_embedding_dimension(), pooling_mode_mean_tokens=True)

        # 3) build a SentenceTransformer pipeline
        self.model = SentenceTransformer(modules=[word_emb, pooling], device=device)
        # self.model = SentenceTransformer(model_name_or_path, device=device)
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
    
    
if __name__ == "__main__":

    # get one instance of CVE instance
    # cve_id = "CVE-2016-9910"
    cve_id = "BIT-jenkins-2023-36478"
    cve_id_1 = "CVE-2024-55591"
    cve_data = osv_cve_api(cve_id)
    cve_data_1 = osv_cve_api(cve_id_1)

    cvevector = CVEVector()
    emb = cvevector.encode(cve_data["details"]) 
    print(f"the embedded description of {cve_id} is {emb}")
    emb_1 = cvevector.encode(cve_data["details"])
    print(f"the embedded description of {cve_id_1} is {emb_1}")