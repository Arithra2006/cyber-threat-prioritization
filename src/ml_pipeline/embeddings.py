"""
Threat Embedding Generation
Uses SentenceTransformers to create semantic embeddings of threat descriptions
"""

import os
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List
import structlog
from tqdm import tqdm

logger = structlog.get_logger()

class ThreatEmbedder:
    """Generate semantic embeddings for threat descriptions"""
    
    def __init__(self, model_name: str = None):
        """
        Initialize embedding model
        
        Args:
            model_name: SentenceTransformer model name
                       Default: all-MiniLM-L6-v2 (fast, 384 dimensions)
        """
        if model_name is None:
            model_name = os.getenv('EMBEDDING_MODEL', 'sentence-transformers/all-MiniLM-L6-v2')
        # Save model_name as instance variable 
        self.model_name = model_name
        
        logger.info("Loading embedding model", model=model_name)
        print(f"📥 Loading embedding model: {model_name}")
        print("   (First time will download ~80MB, then cached)")
        
        self.model = SentenceTransformer(model_name)
        self.embedding_dim = self.model.get_sentence_embedding_dimension()
        
        logger.info("Embedding model loaded", 
                   dimension=self.embedding_dim,
                   model=model_name)
        print(f"✅ Model loaded! Embedding dimension: {self.embedding_dim}\n")
    
    def embed_single(self, text: str) -> np.ndarray:
        """
        Generate embedding for a single text
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding vector (numpy array)
        """
        if not text or not text.strip():
            # Return zero vector for empty text
            return np.zeros(self.embedding_dim)
        
        embedding = self.model.encode(text, convert_to_numpy=True, show_progress_bar=False)
        return embedding
    
    def embed_batch(self, texts: List[str], batch_size: int = 32) -> np.ndarray:
        """
        Generate embeddings for multiple texts (more efficient)
        
        Args:
            texts: List of texts to embed
            batch_size: Number of texts to process at once
            
        Returns:
            Matrix of embeddings (num_texts x embedding_dim)
        """
        logger.info("Starting batch embedding", num_texts=len(texts), batch_size=batch_size)
        
        # Filter out empty texts and track indices
        valid_texts = []
        valid_indices = []
        for i, text in enumerate(texts):
            if text and text.strip():
                valid_texts.append(text)
                valid_indices.append(i)
        
        if not valid_texts:
            logger.warning("No valid texts to embed")
            return np.zeros((len(texts), self.embedding_dim))
        
        # Generate embeddings with progress bar
        print(f"🔄 Generating embeddings for {len(valid_texts)} texts...")
        embeddings = self.model.encode(
            valid_texts,
            batch_size=batch_size,
            show_progress_bar=True,
            convert_to_numpy=True
        )
        
        # Create output array with zero vectors for invalid texts
        all_embeddings = np.zeros((len(texts), self.embedding_dim))
        all_embeddings[valid_indices] = embeddings
        
        logger.info("Batch embedding complete", 
                   embeddings_shape=all_embeddings.shape)
        print(f"✅ Generated {len(all_embeddings)} embeddings\n")
        
        return all_embeddings
    
    def cosine_similarity(self, emb1: np.ndarray, emb2: np.ndarray) -> float:
        """
        Calculate cosine similarity between two embeddings
        
        Args:
            emb1: First embedding vector
            emb2: Second embedding vector
            
        Returns:
            Similarity score (0 to 1, higher = more similar)
        """
        # Normalize vectors
        emb1_norm = emb1 / (np.linalg.norm(emb1) + 1e-8)
        emb2_norm = emb2 / (np.linalg.norm(emb2) + 1e-8)
        
        # Compute cosine similarity
        similarity = np.dot(emb1_norm, emb2_norm)
        
        return float(similarity)
    
    def similarity_matrix(self, embeddings: np.ndarray) -> np.ndarray:
        """
        Compute pairwise similarity matrix for all embeddings
        
        Args:
            embeddings: Matrix of embeddings (N x embedding_dim)
            
        Returns:
            Similarity matrix (N x N)
        """
        # Normalize all embeddings
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True) + 1e-8
        normalized = embeddings / norms
        
        # Compute all pairwise similarities at once
        similarity = np.dot(normalized, normalized.T)
        
        return similarity


if __name__ == "__main__":
    # Test the embedder
    print("="*60)
    print("TESTING THREAT EMBEDDER")
    print("="*60 + "\n")
    
    embedder = ThreatEmbedder()
    
    # Test single embedding
    test_text = "Ransomware attack targeting healthcare systems with credential theft"
    embedding = embedder.embed_single(test_text)
    print(f"Single embedding shape: {embedding.shape}")
    print(f"Sample values: {embedding[:5]}\n")
    
    # Test batch embedding
    test_texts = [
        "Ransomware attack on critical infrastructure",
        "Phishing campaign targeting financial institutions",
        "Supply chain compromise via software update",
    ]
    embeddings = embedder.embed_batch(test_texts)
    print(f"Batch embeddings shape: {embeddings.shape}")
    
    # Test similarity
    sim = embedder.cosine_similarity(embeddings[0], embeddings[1])
    print(f"\nSimilarity between threat 1 and 2: {sim:.3f}")
    
    sim_matrix = embedder.similarity_matrix(embeddings)
    print(f"Similarity matrix shape: {sim_matrix.shape}")
    print(f"Similarity matrix:\n{sim_matrix}")
    
    print("\n✅ Embedder test complete!")