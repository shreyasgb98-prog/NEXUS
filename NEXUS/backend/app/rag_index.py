import os
import json
import logging
import math
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from .config import KNOWLEDGE_CORPUS_PATH, RAG_INDEX_DIR

logger = logging.getLogger("nexus.rag")

class DefensiveRAGIndex:
    """Local vector search index for defensive security guidance with pure NumPy and TF-IDF fallback."""

    def __init__(
        self,
        corpus_path: Path = KNOWLEDGE_CORPUS_PATH,
        index_dir: Path = RAG_INDEX_DIR
    ):
        self.corpus_path = Path(corpus_path)
        self.index_dir = Path(index_dir)
        self.documents: List[Dict[str, Any]] = []
        self.vector_engine: Optional[str] = None

        # Dense embedding references (SentenceTransformers + NumPy)
        self.encoder = None
        self.doc_embeddings = None

        # TF-IDF fallback structures
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.tfidf_doc_vectors: List[Dict[int, float]] = []

        self._load_corpus()
        self._init_engine()

    def _load_corpus(self) -> None:
        if self.corpus_path.exists():
            try:
                with open(self.corpus_path, "r", encoding="utf-8") as f:
                    self.documents = json.load(f)
                logger.info("Loaded %d RAG passages from %s", len(self.documents), self.corpus_path)
            except Exception as exc:
                logger.warning("Failed to load RAG corpus %s: %s", self.corpus_path, exc)
                self.documents = []
        else:
            logger.warning("RAG corpus file not found at %s", self.corpus_path)
            self.documents = []

    def _tokenize(self, text: str) -> List[str]:
        cleaned = re.sub(r"[^a-zA-Z0-9\s-]", " ", text.lower())
        return [tok for tok in cleaned.split() if len(tok) > 1]

    def _init_engine(self) -> None:
        if not self.documents:
            return

        # Attempt to initialize sentence-transformers with pure NumPy vectorized cosine similarity
        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np

            self.index_dir.mkdir(parents=True, exist_ok=True)
            self.encoder = SentenceTransformer("all-MiniLM-L6-v2")

            texts = [
                f"{doc.get('title', '')} {doc.get('description', '')} {doc.get('threat_mechanism', '')} {doc.get('defensive_mitigation', '')}"
                for doc in self.documents
            ]
            raw_embeddings = self.encoder.encode(texts, convert_to_numpy=True)
            
            # L2 normalize document vectors for inner-product cosine similarity
            norms = np.linalg.norm(raw_embeddings, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            self.doc_embeddings = raw_embeddings / norms
            self.vector_engine = "numpy_dense_cosine"

            meta_file = self.index_dir / "metadata.json"
            with open(meta_file, "w", encoding="utf-8") as mf:
                json.dump(self.documents, mf, indent=2)
            return
        except Exception:
            # Fall back to deterministic TF-IDF cosine similarity
            self.vector_engine = "tfidf_cosine_fallback"
            self._build_tfidf_index()

    def _build_tfidf_index(self) -> None:
        corpus_tokens: List[List[str]] = []
        df: Dict[str, int] = {}

        for doc in self.documents:
            content = f"{doc.get('topic', '')} {doc.get('title', '')} {doc.get('description', '')} {doc.get('threat_mechanism', '')} {doc.get('defensive_mitigation', '')}"
            tokens = self._tokenize(content)
            corpus_tokens.append(tokens)
            unique_tokens = set(tokens)
            for tok in unique_tokens:
                df[tok] = df.get(tok, 0) + 1

        num_docs = max(len(self.documents), 1)
        self.vocab = {term: idx for idx, term in enumerate(sorted(df.keys()))}
        self.idf = {
            term: math.log((num_docs + 1.0) / (freq + 1.0)) + 1.0
            for term, freq in df.items()
        }

        self.tfidf_doc_vectors = []
        for tokens in corpus_tokens:
            tf: Dict[str, int] = {}
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1

            vec: Dict[int, float] = {}
            squared_sum = 0.0
            for t, count in tf.items():
                if t in self.vocab:
                    weight = (count / len(tokens)) * self.idf.get(t, 1.0)
                    vec[self.vocab[t]] = weight
                    squared_sum += weight * weight

            norm = math.sqrt(squared_sum) if squared_sum > 0 else 1.0
            norm_vec = {dim: w / norm for dim, w in vec.items()}
            self.tfidf_doc_vectors.append(norm_vec)

    def search(self, query: str, top_k: int = 2) -> List[Dict[str, Any]]:
        if not self.documents:
            return []

        # 1. Dense embedding search via pure NumPy
        if self.vector_engine == "numpy_dense_cosine" and self.doc_embeddings is not None and self.encoder is not None:
            try:
                import numpy as np
                q_raw = self.encoder.encode([query], convert_to_numpy=True)
                q_norm = np.linalg.norm(q_raw)
                if q_norm > 0:
                    q_vec = q_raw / q_norm
                else:
                    q_vec = q_raw

                # Vectorized inner product: (N, D) . (D,) -> (N,)
                scores = np.dot(self.doc_embeddings, q_vec[0])
                top_indices = np.argsort(-scores)[:min(top_k, len(self.documents))]

                results = []
                for idx in top_indices:
                    doc_copy = dict(self.documents[idx])
                    doc_copy["retrieval_score"] = round(float(scores[idx]), 4)
                    doc_copy["retrieval_engine"] = "numpy_dense_cosine"
                    results.append(doc_copy)
                return results
            except Exception:
                pass

        # 2. TF-IDF cosine similarity search fallback
        q_tokens = self._tokenize(query)
        if not q_tokens:
            return [dict(doc) for doc in self.documents[:top_k]]

        tf_q: Dict[str, int] = {}
        for t in q_tokens:
            tf_q[t] = tf_q.get(t, 0) + 1

        vec_q: Dict[int, float] = {}
        squared_sum = 0.0
        for t, count in tf_q.items():
            if t in self.vocab:
                weight = (count / len(q_tokens)) * self.idf.get(t, 1.0)
                dim = self.vocab[t]
                vec_q[dim] = weight
                squared_sum += weight * weight

        norm_q = math.sqrt(squared_sum) if squared_sum > 0 else 1.0
        norm_vec_q = {dim: w / norm_q for dim, w in vec_q.items()}

        scored_docs: List[Tuple[float, int]] = []
        for doc_idx, doc_vec in enumerate(self.tfidf_doc_vectors):
            sim = 0.0
            for dim, weight in norm_vec_q.items():
                if dim in doc_vec:
                    sim += weight * doc_vec[dim]
            scored_docs.append((sim, doc_idx))

        scored_docs.sort(key=lambda item: item[0], reverse=True)
        results = []
        for score, idx in scored_docs[:top_k]:
            doc_copy = dict(self.documents[idx])
            doc_copy["retrieval_score"] = round(float(score), 4)
            doc_copy["retrieval_engine"] = "tfidf_cosine"
            results.append(doc_copy)
        return results

    def format_query_from_evidence(self, event_type: str, evidence: Dict[str, Any]) -> str:
        features = evidence.get("features", [])
        feat_names = [f.get("feature", "") for f in features]
        return f"{event_type} {' '.join(feat_names)} wireless network intrusion mitigation"
