"""
Unit tests for risk scoring module
"""

import pytest
import numpy as np
import pandas as pd
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ml_pipeline.risk_scoring import RiskScorer
from src.ml_pipeline.embeddings import ThreatEmbedder
from src.ml_pipeline.clustering import ThreatClusterer

@pytest.fixture
def scorer_components():
    """Create embedder and clusterer for scorer"""
    embedder = ThreatEmbedder()
    
    # Create minimal clustering
    sample_texts = ['Threat 1', 'Threat 2', 'Threat 3', 'Threat 4', 'Threat 5']
    embeddings = embedder.embed_batch(sample_texts)
    
    clusterer = ThreatClusterer(num_clusters=2)
    clusterer.fit(embeddings)
    
    return embedder, clusterer

@pytest.fixture
def scorer(scorer_components):
    """Create RiskScorer instance"""
    embedder, clusterer = scorer_components
    return RiskScorer(embedder, clusterer)

def test_scorer_initialization(scorer):
    """Test scorer initializes correctly"""
    assert scorer.embedder is not None
    assert scorer.clusterer is not None
    assert len(scorer.cisa_embeddings) == 12  # 12 CISA incidents

def test_keyword_scoring(scorer):
    """Test keyword-based scoring"""
    # High keyword match
    text_high = "ransomware supply chain attack with lateral movement and credential dumping"
    score_high, keywords_high = scorer.calculate_keyword_score(text_high)
    
    # Low keyword match
    text_low = "simple email notification"
    score_low, keywords_low = scorer.calculate_keyword_score(text_low)
    
    assert score_high > score_low
    assert len(keywords_high) > len(keywords_low)

def test_similarity_scoring(scorer):
    """Test similarity to CISA incidents"""
    embedder = scorer.embedder
    
    # Similar to supply chain attack
    text_similar = "Supply chain compromise via software update mechanism"
    emb_similar = embedder.embed_single(text_similar)
    score_similar, idx_similar = scorer.calculate_similarity_score(emb_similar)
    
    # Not similar
    text_different = "Random unrelated text"
    emb_different = embedder.embed_single(text_different)
    score_different, idx_different = scorer.calculate_similarity_score(emb_different)
    
    assert score_similar > score_different
    assert 0 <= score_similar <= 1
    assert 0 <= score_different <= 1

def test_complete_risk_calculation(scorer):
    """Test complete risk score calculation"""
    embedder = scorer.embedder
    clusterer = scorer.clusterer
    
    # High-risk threat
    text_high = "ransomware supply chain attack targeting critical infrastructure"
    emb_high = embedder.embed_single(text_high)
    cluster_high = clusterer.predict(emb_high.reshape(1, -1))[0]
    
    result = scorer.calculate_risk_score(emb_high, text_high, cluster_high)
    
    # Check result structure
    assert 'risk_score' in result
    assert 'similarity_score' in result
    assert 'keyword_score' in result
    assert 'novelty_score' in result
    assert 'matched_keywords' in result
    
    # Check score ranges
    assert 0 <= result['risk_score'] <= 1
    assert 0 <= result['similarity_score'] <= 1
    assert 0 <= result['keyword_score'] <= 1

def test_score_threats_batch(scorer):
    """Test scoring multiple threats"""
    df = pd.DataFrame({
        'description': [
            'ransomware attack with encryption',
            'phishing campaign',
            'supply chain compromise'
        ]
    })
    
    embedder = scorer.embedder
    clusterer = scorer.clusterer
    
    embeddings = embedder.embed_batch(df['description'].tolist())
    labels = clusterer.predict(embeddings)
    
    df_scored = scorer.score_threats(df, embeddings, labels)
    
    # Check all scores are present
    assert 'risk_score' in df_scored.columns
    assert 'similarity_score' in df_scored.columns
    assert 'keyword_score' in df_scored.columns
    assert 'novelty_score' in df_scored.columns
    
    # Check scores are sorted
    assert df_scored['risk_score'].is_monotonic_decreasing

def test_score_components_sum_correctly(scorer):
    """Test that weighted components produce correct final score"""
    embedder = scorer.embedder
    clusterer = scorer.clusterer
    
    text = "test threat"
    emb = embedder.embed_single(text)
    cluster = clusterer.predict(emb.reshape(1, -1))[0]
    
    result = scorer.calculate_risk_score(emb, text, cluster)
    
    # Calculate expected score from components using actual weights
    # Default RiskScorer uses: similarity=0.33, keyword=0.33, novelty=0.34
    expected = (
        scorer.similarity_weight * result['similarity_score'] +
        scorer.keyword_weight * result['keyword_score'] +
        scorer.novelty_weight * result['novelty_score']
    )
    
    # Should match within floating point precision
    assert abs(result['risk_score'] - expected) < 1e-6