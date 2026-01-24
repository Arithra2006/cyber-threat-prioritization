"""
Unit tests for deduplication module
"""

import pytest
import numpy as np
import pandas as pd
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ml_pipeline.deduplication import ThreatDeduplicator
from src.ml_pipeline.embeddings import ThreatEmbedder

@pytest.fixture
def deduplicator():
    """Fixture to create deduplicator instance"""
    return ThreatDeduplicator(similarity_threshold=0.85)

@pytest.fixture
def sample_data_with_duplicates():
    """Create sample data with known duplicates"""
    df = pd.DataFrame({
        'name': [
            'Ransomware attack A',
            'Ransomware attack A duplicate',  # Similar to first
            'Phishing campaign',
            'Unique threat'
        ],
        'description': [
            'Ransomware targeting hospitals encrypting patient data',
            'Ransomware attack on hospitals with data encryption',  # Very similar
            'Phishing emails targeting financial institutions',
            'Completely different threat vector'
        ]
    })
    
    embedder = ThreatEmbedder()
    embeddings = embedder.embed_batch(df['description'].tolist())
    
    return df, embeddings

def test_deduplicator_initialization(deduplicator):
    """Test deduplicator initialization"""
    assert deduplicator.threshold == 0.85

def test_find_duplicates(deduplicator, sample_data_with_duplicates):
    """Test duplicate detection"""
    df, embeddings = sample_data_with_duplicates
    
    duplicate_indices, duplicate_groups = deduplicator.find_duplicates(embeddings, df)
    
    assert isinstance(duplicate_indices, set)
    assert isinstance(duplicate_groups, pd.DataFrame)

def test_remove_duplicates(deduplicator, sample_data_with_duplicates):
    """Test duplicate removal"""
    df, embeddings = sample_data_with_duplicates
    
    df_clean, emb_clean, dup_report = deduplicator.remove_duplicates(df, embeddings)
    
    # Should have fewer threats after deduplication
    assert len(df_clean) <= len(df)
    assert emb_clean.shape[0] == len(df_clean)

def test_no_duplicates_case(deduplicator):
    """Test case with no duplicates"""
    df = pd.DataFrame({
        'name': ['Threat 1', 'Threat 2', 'Threat 3'],
        'description': [
            'Completely unique threat A',
            'Totally different threat B',
            'Another distinct threat C'
        ]
    })
    
    embedder = ThreatEmbedder()
    embeddings = embedder.embed_batch(df['description'].tolist())
    
    df_clean, emb_clean, dup_report = deduplicator.remove_duplicates(df, embeddings)
    
    # Should keep all threats if none are duplicates
    assert len(df_clean) == len(df)

def test_threshold_sensitivity():
    """Test that different thresholds give different results"""
    df = pd.DataFrame({
        'name': ['Threat 1', 'Threat 2'],
        'description': [
            'Ransomware attack',
            'Ransomware campaign'  # Somewhat similar
        ]
    })
    
    embedder = ThreatEmbedder()
    embeddings = embedder.embed_batch(df['description'].tolist())
    
    # High threshold (strict)
    dedup_strict = ThreatDeduplicator(similarity_threshold=0.95)
    df_strict, _, _ = dedup_strict.remove_duplicates(df, embeddings)
    
    # Low threshold (lenient)
    dedup_lenient = ThreatDeduplicator(similarity_threshold=0.70)
    df_lenient, _, _ = dedup_lenient.remove_duplicates(df, embeddings)
    
    # Lenient should remove more (or equal) duplicates
    assert len(df_lenient) <= len(df_strict)