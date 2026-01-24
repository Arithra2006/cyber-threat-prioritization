"""
Threat Clustering
Groups threats into attack patterns using KMeans clustering
"""

import os
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from typing import Dict, List
import structlog
from collections import Counter

logger = structlog.get_logger()

class ThreatClusterer:
    """Cluster threats into attack patterns"""
    
    def __init__(self, num_clusters: int = None, random_state: int = 42):
        """
        Initialize clusterer
        
        Args:
            num_clusters: Number of clusters (default: 10)
            random_state: Random seed for reproducibility
        """
        if num_clusters is None:
            num_clusters = int(os.getenv('NUM_CLUSTERS', 10))
        
        self.num_clusters = num_clusters
        self.random_state = random_state
        self.model = None
        self.cluster_centers = None
        self.cluster_std_devs = None
        
        logger.info("Clusterer initialized", num_clusters=num_clusters)
        print(f"🎯 Clusterer ready (k={num_clusters} clusters)\n")
    
    def fit(self, embeddings: np.ndarray) -> 'ThreatClusterer':
        """
        Fit clustering model on threat embeddings
        
        Args:
            embeddings: Threat embeddings (N x embedding_dim)
            
        Returns:
            Self (for method chaining)
        """
        logger.info("Starting clustering", 
                   num_samples=len(embeddings),
                   num_clusters=self.num_clusters)
        
        print(f"🔄 Clustering {len(embeddings)} threats into {self.num_clusters} groups...")
        
        # Convert to float32 for scikit-learn compatibility
        embeddings = embeddings.astype(np.float32)
        
        # Fit KMeans
        self.model = KMeans(
            n_clusters=self.num_clusters,
            random_state=self.random_state,
            n_init=10,
            max_iter=300
        )
        
        self.model.fit(embeddings)
        self.cluster_centers = self.model.cluster_centers_
        
        # Calculate standard deviation for each cluster
        labels = self.model.labels_
        self.cluster_std_devs = np.zeros(self.num_clusters)
        
        for i in range(self.num_clusters):
            cluster_points = embeddings[labels == i]
            if len(cluster_points) > 0:
                distances = np.linalg.norm(
                    cluster_points - self.cluster_centers[i],
                    axis=1
                )
                self.cluster_std_devs[i] = np.std(distances)
        
        logger.info("Clustering complete", 
                   inertia=self.model.inertia_)
        print(f"✅ Clustering complete! Inertia: {self.model.inertia_:.2f}\n")
        
        return self
    
    def predict(self, embeddings: np.ndarray) -> np.ndarray:
        """
        Assign cluster labels to embeddings
        
        Args:
            embeddings: Threat embeddings (N x embedding_dim)
            
        Returns:
            Cluster labels (N,)
        """
        if self.model is None:
            raise ValueError("Model not fitted! Call fit() first.")
        
        # Convert to float32 for scikit-learn compatibility
        embeddings = embeddings.astype(np.float32)
        
        return self.model.predict(embeddings)
    
    def get_cluster_stats(self, 
                         labels: np.ndarray, 
                         df: pd.DataFrame) -> pd.DataFrame:
        """
        Get statistics for each cluster
        
        Args:
            labels: Cluster assignments
            df: DataFrame with threat data
            
        Returns:
            DataFrame with cluster statistics
        """
        stats = []
        
        for cluster_id in range(self.num_clusters):
            cluster_mask = labels == cluster_id
            cluster_threats = df[cluster_mask]
            
            # Get most common tags
            all_tags = []
            for tags_str in cluster_threats['tags']:
                if pd.notna(tags_str):
                    all_tags.extend([t.strip() for t in str(tags_str).split(',')])
            
            tag_counts = Counter(all_tags)
            top_tags = [tag for tag, _ in tag_counts.most_common(5)]
            
            # Get sample threat names
            sample_names = cluster_threats['name'].head(3).tolist()
            
            stats.append({
                'cluster_id': cluster_id,
                'size': int(np.sum(cluster_mask)),
                'percentage': float(np.sum(cluster_mask) / len(labels) * 100),
                'top_tags': ', '.join(top_tags) if top_tags else 'N/A',
                'sample_threats': ' | '.join([str(n)[:40] + '...' for n in sample_names]),
                'std_dev': float(self.cluster_std_devs[cluster_id])
            })
        
        stats_df = pd.DataFrame(stats)
        stats_df = stats_df.sort_values('size', ascending=False).reset_index(drop=True)
        
        return stats_df
    
    def calculate_novelty_score(self, 
                                embedding: np.ndarray, 
                                cluster_label: int) -> float:
        """
        Calculate novelty score for a threat
        Novelty = how far the threat is from its cluster center
        
        Args:
            embedding: Threat embedding
            cluster_label: Assigned cluster
            
        Returns:
            Novelty score (0 to 1, higher = more novel)
        """
        if self.cluster_centers is None:
            raise ValueError("Model not fitted!")
        
        # Convert to float32
        embedding = embedding.astype(np.float32)
        
        # Distance to cluster center
        cluster_center = self.cluster_centers[cluster_label]
        distance = np.linalg.norm(embedding - cluster_center)
        
        # Normalize by cluster standard deviation
        cluster_std = self.cluster_std_devs[cluster_label]
        
        if cluster_std < 1e-6:
            return 0.0
        
        # Novelty = how many standard deviations away from center
        # Threats > 2σ away are considered novel
        novelty = max(0, (distance - 2 * cluster_std) / (2 * cluster_std))
        
        # Cap at 1.0
        novelty = min(novelty, 1.0)
        
        return float(novelty)


if __name__ == "__main__":
    # Test clusterer
    from embeddings import ThreatEmbedder
    
    print("="*60)
    print("TESTING CLUSTERER")
    print("="*60 + "\n")
    
    # Create test data
    test_threats = pd.DataFrame({
        'name': [
            'Ransomware attack 1', 'Ransomware attack 2', 'Ransomware attack 3',
            'Phishing campaign 1', 'Phishing campaign 2', 'Phishing campaign 3',
            'Supply chain attack 1', 'Supply chain attack 2',
            'DDoS attack 1', 'DDoS attack 2',
        ],
        'description': [
            'Ransomware encrypting hospital data',
            'Ransomware targeting critical infrastructure',
            'Ransomware demanding bitcoin payment',
            'Phishing emails with malicious attachments',
            'Phishing campaign targeting executives',
            'Phishing using fake login pages',
            'Supply chain compromise via software update',
            'Supply chain attack on vendor systems',
            'Distributed denial of service attack',
            'DDoS overwhelming web servers',
        ],
        'tags': [
            'ransomware, malware', 'ransomware, malware', 'ransomware, malware',
            'phishing, social engineering', 'phishing, social engineering', 'phishing',
            'supply chain, apt', 'supply chain, apt',
            'ddos, botnet', 'ddos, botnet',
        ]
    })
    
    # Generate embeddings
    embedder = ThreatEmbedder()
    embeddings = embedder.embed_batch(test_threats['description'].tolist())
    
    # Test clustering
    clusterer = ThreatClusterer(num_clusters=4)
    clusterer.fit(embeddings)
    
    labels = clusterer.predict(embeddings)
    
    print(f"Cluster assignments: {labels}")
    
    # Get cluster stats
    stats = clusterer.get_cluster_stats(labels, test_threats)
    print(f"\nCluster Statistics:")
    print(stats[['cluster_id', 'size', 'percentage', 'top_tags']])
    
    # Test novelty scoring
    novelty = clusterer.calculate_novelty_score(embeddings[0], labels[0])
    print(f"\nNovelty score for first threat: {novelty:.3f}")
    
    print("\n✅ Clusterer test complete!")