"""
Threat Deduplication
Removes duplicate or near-duplicate threats using cosine similarity
"""

import os
import numpy as np
import pandas as pd
from typing import List, Set, Tuple
import structlog
from tqdm import tqdm

logger = structlog.get_logger()

class ThreatDeduplicator:
    """Remove duplicate threats based on semantic similarity"""
    
    def __init__(self, similarity_threshold: float = None):
        """
        Initialize deduplicator
        
        Args:
            similarity_threshold: Cosine similarity threshold for duplicates
                                 Default: 0.85 (85% similar = duplicate)
        """
        if similarity_threshold is None:
            similarity_threshold = float(os.getenv('SIMILARITY_THRESHOLD', 0.85))
        
        self.threshold = similarity_threshold
        logger.info("Deduplicator initialized", threshold=self.threshold)
        print(f"🔧 Deduplicator ready (threshold: {self.threshold})\n")
    
    def find_duplicates(self, 
                       embeddings: np.ndarray, 
                       df: pd.DataFrame) -> Tuple[Set[int], pd.DataFrame]:
        """
        Find duplicate threats using cosine similarity
        
        Args:
            embeddings: Threat embeddings (N x embedding_dim)
            df: DataFrame with threat data
            
        Returns:
            Tuple of (indices_to_remove, duplicate_groups_df)
        """
        logger.info("Starting duplicate detection", 
                   num_threats=len(embeddings),
                   threshold=self.threshold)
        
        print(f"🔍 Finding duplicates (threshold: {self.threshold})...")
        
        # Normalize embeddings for cosine similarity
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True) + 1e-8
        normalized = embeddings / norms
        
        # Compute similarity matrix
        similarity_matrix = np.dot(normalized, normalized.T)
        
        # Find duplicates
        duplicate_indices = set()
        duplicate_groups = []
        
        for i in tqdm(range(len(embeddings)), desc="Checking for duplicates"):
            if i in duplicate_indices:
                continue
            
            # Find all threats similar to this one
            similar_indices = np.where(similarity_matrix[i] >= self.threshold)[0]
            
            # Remove self-similarity
            similar_indices = similar_indices[similar_indices != i]
            
            if len(similar_indices) > 0:
                # Mark duplicates for removal (keep first, remove rest)
                for dup_idx in similar_indices:
                    if dup_idx > i:  # Only mark later occurrences
                        duplicate_indices.add(int(dup_idx))
                        
                        # Record duplicate group
                        duplicate_groups.append({
                            'original_idx': i,
                            'duplicate_idx': int(dup_idx),
                            'similarity': float(similarity_matrix[i, dup_idx]),
                            'original_name': df.iloc[i]['name'][:50],
                            'duplicate_name': df.iloc[int(dup_idx)]['name'][:50]
                        })
        
        duplicate_groups_df = pd.DataFrame(duplicate_groups)
        
        logger.info("Duplicate detection complete",
                   total_threats=len(embeddings),
                   duplicates_found=len(duplicate_indices),
                   dedup_rate=f"{len(duplicate_indices)/len(embeddings)*100:.1f}%")
        
        print(f"✅ Found {len(duplicate_indices)} duplicates "
              f"({len(duplicate_indices)/len(embeddings)*100:.1f}% of total)\n")
        
        return duplicate_indices, duplicate_groups_df
    
    def remove_duplicates(self, 
                         df: pd.DataFrame, 
                         embeddings: np.ndarray) -> Tuple[pd.DataFrame, np.ndarray, pd.DataFrame]:
        """
        Remove duplicate threats from dataset
        
        Args:
            df: DataFrame with threat data
            embeddings: Threat embeddings
            
        Returns:
            Tuple of (deduplicated_df, deduplicated_embeddings, duplicate_report)
        """
        print(f"📊 Starting deduplication on {len(df)} threats...\n")
        
        # Find duplicates
        duplicate_indices, duplicate_groups = self.find_duplicates(embeddings, df)
        
        if len(duplicate_indices) == 0:
            print("✅ No duplicates found! Dataset is clean.\n")
            return df, embeddings, duplicate_groups
        
        # Create mask for keeping only non-duplicates
        keep_mask = np.ones(len(df), dtype=bool)
        keep_mask[list(duplicate_indices)] = False
        
        # Filter dataframe and embeddings
        df_dedup = df[keep_mask].reset_index(drop=True)
        embeddings_dedup = embeddings[keep_mask]
        
        print(f"📈 Deduplication Summary:")
        print(f"   Original threats: {len(df)}")
        print(f"   Duplicates removed: {len(duplicate_indices)}")
        print(f"   Unique threats: {len(df_dedup)}")
        print(f"   Reduction: {len(duplicate_indices)/len(df)*100:.1f}%\n")
        
        # Show some example duplicates
        if len(duplicate_groups) > 0:
            print("📝 Sample duplicate pairs:")
            for _, row in duplicate_groups.head(3).iterrows():
                print(f"   Similarity: {row['similarity']:.3f}")
                print(f"   - Original: {row['original_name']}")
                print(f"   - Duplicate: {row['duplicate_name']}")
                print()
        
        return df_dedup, embeddings_dedup, duplicate_groups


if __name__ == "__main__":
    # Test deduplicator
    from embeddings import ThreatEmbedder
    
    print("="*60)
    print("TESTING DEDUPLICATOR")
    print("="*60 + "\n")
    
    # Create test data with duplicates
    test_threats = pd.DataFrame({
        'name': [
            'Ransomware attack on hospital systems',
            'Ransomware targeting healthcare facilities',  # Similar to #1
            'Phishing campaign against banks',
            'Supply chain compromise via software',
            'Phishing attack targeting financial sector',  # Similar to #3
        ],
        'description': [
            'Ransomware attack targeting hospital systems with data encryption',
            'Ransomware attack on healthcare facilities encrypting patient data',
            'Phishing campaign targeting financial institutions with fake emails',
            'Supply chain attack compromising software updates',
            'Phishing emails targeting banks and financial services',
        ]
    })
    
    # Generate embeddings
    embedder = ThreatEmbedder()
    embeddings = embedder.embed_batch(test_threats['description'].tolist())
    
    # Test deduplication
    dedup = ThreatDeduplicator(similarity_threshold=0.80)
    df_clean, emb_clean, dup_report = dedup.remove_duplicates(test_threats, embeddings)
    
    print(f"✅ Deduplication test complete!")
    print(f"   Kept {len(df_clean)} unique threats")