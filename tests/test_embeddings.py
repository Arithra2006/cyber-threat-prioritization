"""
Unit tests for embedding generation module
"""

import pytest
import numpy as np
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ml_pipeline.embeddings import ThreatEmbedder

@pytest.fixture
def embedder():
    """Fixture to create embedder instance"""
    return ThreatEmbedder()

def test_embedder_initialization(embedder):
    """Test that embedder initializes correctly"""
    assert embedder.model is not None
    assert embedder.embedding_dim == 384

def test_single_embedding(embedder):
    """Test single text embedding"""
    text = "Ransomware attack targeting healthcare systems"
    embedding = embedder.embed_single(text)
    
    assert isinstance(embedding, np.ndarray)
    assert embedding.shape == (384,)
    assert not np.all(embedding == 0)

def test_empty_text_embedding(embedder):
    """Test embedding of empty text"""
    embedding = embedder.embed_single("")
    
    assert isinstance(embedding, np.ndarray)
    assert embedding.shape == (384,)
    assert np.all(embedding == 0)  # Should return zero vector

def test_batch_embedding(embedder):
    """Test batch embedding"""
    texts = [
        "Ransomware attack",
        "Phishing campaign",
        "Supply chain compromise"
    ]
    embeddings = embedder.embed_batch(texts)
    
    assert embeddings.shape == (3, 384)
    assert not np.all(embeddings == 0)

def test_cosine_similarity(embedder):
    """Test cosine similarity calculation"""
    text1 = "Ransomware attack on hospitals"
    text2 = "Ransomware targeting healthcare"
    text3 = "Phishing email campaign"
    
    emb1 = embedder.embed_single(text1)
    emb2 = embedder.embed_single(text2)
    emb3 = embedder.embed_single(text3)
    
    sim_12 = embedder.cosine_similarity(emb1, emb2)
    sim_13 = embedder.cosine_similarity(emb1, emb3)
    
    # Similar texts should have higher similarity
    assert sim_12 > sim_13
    assert 0 <= sim_12 <= 1
    assert 0 <= sim_13 <= 1

def test_similarity_matrix(embedder):
    """Test similarity matrix generation"""
    texts = ["Text 1", "Text 2", "Text 3"]
    embeddings = embedder.embed_batch(texts)
    
    sim_matrix = embedder.similarity_matrix(embeddings)
    
    assert sim_matrix.shape == (3, 3)
    
    # Diagonal should be 1 (self-similarity)
    np.testing.assert_array_almost_equal(np.diag(sim_matrix), np.ones(3), decimal=5)
    
    # Matrix should be symmetric
    np.testing.assert_array_almost_equal(sim_matrix, sim_matrix.T, decimal=5)

def test_batch_with_empty_texts(embedder):
    """Test batch embedding with some empty texts"""
    texts = ["Valid text", "", "Another valid text"]
    embeddings = embedder.embed_batch(texts)
    
    assert embeddings.shape == (3, 384)
    assert np.all(embeddings[1] == 0)  # Empty text should give zero vector
    assert not np.all(embeddings[0] == 0)  # Valid text should have non-zero embedding