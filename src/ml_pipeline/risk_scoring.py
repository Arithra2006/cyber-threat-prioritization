"""
Risk Scoring Engine
Calculates threat priority scores based on:
1. Similarity to CISA critical incidents
2. MITRE ATT&CK keyword matching
3. Novelty signal (distance from clusters)
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Tuple
import structlog

from src.data_collection.cisa_ground_truth import get_incident_descriptions
from src.data_collection.mitre_keywords import MITRE_CRITICAL_KEYWORDS

logger = structlog.get_logger()

class RiskScorer:
    """Calculate transparent, explainable risk scores for threats"""
    
    def __init__(self, 
                 embedder,
                 clusterer,
                 similarity_weight: float = 0.33,
                 keyword_weight: float = 0.33,
                 novelty_weight: float = 0.34):
        """
        Initialize risk scorer
        
        Args:
            embedder: ThreatEmbedder instance
            clusterer: ThreatClusterer instance
            similarity_weight: Weight for CISA similarity component
            keyword_weight: Weight for MITRE keyword component
            novelty_weight: Weight for novelty component
        """
        self.embedder = embedder
        self.clusterer = clusterer
        
        # Weights (should sum to 1.0)
        self.similarity_weight = similarity_weight
        self.keyword_weight = keyword_weight
        self.novelty_weight = novelty_weight
        
        # Pre-compute CISA incident embeddings
        print("📥 Loading CISA ground truth incidents...")
        cisa_descriptions = get_incident_descriptions()
        self.cisa_embeddings = embedder.embed_batch(cisa_descriptions)
        print(f"✅ Loaded {len(cisa_descriptions)} CISA incidents\n")
        
        # Load MITRE keywords
        self.critical_keywords = [kw.lower() for kw in MITRE_CRITICAL_KEYWORDS]
        
        logger.info("Risk scorer initialized",
                   cisa_incidents=len(cisa_descriptions),
                   mitre_keywords=len(self.critical_keywords),
                   weights={
                       'similarity': similarity_weight,
                       'keyword': keyword_weight,
                       'novelty': novelty_weight
                   })
    
    def calculate_similarity_score(self, threat_embedding: np.ndarray) -> Tuple[float, int]:
        """
        Calculate similarity to CISA critical incidents
        
        Args:
            threat_embedding: Embedding of the threat
            
        Returns:
            Tuple of (max_similarity_score, most_similar_incident_idx)
        """
        similarities = []
        
        for cisa_emb in self.cisa_embeddings:
            sim = self.embedder.cosine_similarity(threat_embedding, cisa_emb)
            similarities.append(sim)
        
        max_sim = max(similarities)
        max_idx = similarities.index(max_sim)
        
        return float(max_sim), int(max_idx)
    
    def calculate_keyword_score(self, threat_description: str) -> Tuple[float, List[str]]:
        """
        Calculate score based on MITRE critical keyword matches
        
        Args:
            threat_description: Threat description text
            
        Returns:
            Tuple of (keyword_score, matched_keywords)
        """
        description_lower = threat_description.lower()
        
        matched_keywords = []
        for keyword in self.critical_keywords:
            if keyword in description_lower:
                matched_keywords.append(keyword)
        
        # 0.15 points per matched keyword, capped at 1.0
        score = min(len(matched_keywords) * 0.15, 1.0)
        
        return float(score), matched_keywords
    
    def calculate_novelty_score(self, 
                                threat_embedding: np.ndarray,
                                cluster_label: int) -> float:
        """
        Calculate novelty score (how unusual the threat is)
        
        Args:
            threat_embedding: Embedding of the threat
            cluster_label: Assigned cluster
            
        Returns:
            Novelty score (0 to 1)
        """
        return self.clusterer.calculate_novelty_score(threat_embedding, cluster_label)
    
    def calculate_risk_score(self,
                            threat_embedding: np.ndarray,
                            threat_description: str,
                            cluster_label: int) -> Dict:
        """
        Calculate complete risk score with all components
        
        Args:
            threat_embedding: Embedding of the threat
            threat_description: Threat description text
            cluster_label: Assigned cluster
            
        Returns:
            Dictionary with risk score and component breakdown
        """
        # Component 1: Similarity to CISA incidents
        similarity_score, cisa_idx = self.calculate_similarity_score(threat_embedding)
        
        # Component 2: MITRE keyword matching
        keyword_score, matched_keywords = self.calculate_keyword_score(threat_description)
        
        # Component 3: Novelty signal
        novelty_score = self.calculate_novelty_score(threat_embedding, cluster_label)
        
        # Weighted final score
        final_score = (
            self.similarity_weight * similarity_score +
            self.keyword_weight * keyword_score +
            self.novelty_weight * novelty_score
        )
        
        return {
            'risk_score': float(final_score),
            'similarity_score': float(similarity_score),
            'keyword_score': float(keyword_score),
            'novelty_score': float(novelty_score),
            'most_similar_cisa_idx': cisa_idx,
            'matched_keywords': matched_keywords,
            'num_keywords_matched': len(matched_keywords)
        }
    
    def score_threats(self, 
                     df: pd.DataFrame, 
                     embeddings: np.ndarray,
                     cluster_labels: np.ndarray) -> pd.DataFrame:
        """
        Score all threats in the dataset
        
        Args:
            df: DataFrame with threat data
            embeddings: Threat embeddings
            cluster_labels: Cluster assignments
            
        Returns:
            DataFrame with added risk scores
        """
        logger.info("Starting risk scoring", num_threats=len(df))
        print(f"🎯 Calculating risk scores for {len(df)} threats...\n")
        
        scores_list = []
        
        for i in range(len(df)):
            description = df.iloc[i]['description']
            embedding = embeddings[i]
            cluster = cluster_labels[i]
            
            score_dict = self.calculate_risk_score(embedding, description, cluster)
            scores_list.append(score_dict)
        
        # Add scores to dataframe
        df_scored = df.copy()
        df_scored['risk_score'] = [s['risk_score'] for s in scores_list]
        df_scored['similarity_score'] = [s['similarity_score'] for s in scores_list]
        df_scored['keyword_score'] = [s['keyword_score'] for s in scores_list]
        df_scored['novelty_score'] = [s['novelty_score'] for s in scores_list]
        df_scored['most_similar_cisa_idx'] = [s['most_similar_cisa_idx'] for s in scores_list]
        df_scored['matched_keywords'] = [', '.join(s['matched_keywords']) for s in scores_list]
        df_scored['num_keywords_matched'] = [s['num_keywords_matched'] for s in scores_list]
        df_scored['cluster'] = cluster_labels
        
        # Sort by risk score (descending)
        df_scored = df_scored.sort_values('risk_score', ascending=False).reset_index(drop=True)
        
        logger.info("Risk scoring complete",
                   mean_score=df_scored['risk_score'].mean(),
                   max_score=df_scored['risk_score'].max(),
                   min_score=df_scored['risk_score'].min())
        
        print(f"✅ Risk scoring complete!")
        print(f"   Mean score: {df_scored['risk_score'].mean():.3f}")
        print(f"   Max score: {df_scored['risk_score'].max():.3f}")
        print(f"   Min score: {df_scored['risk_score'].min():.3f}\n")
        
        return df_scored


if __name__ == "__main__":
    # Test risk scorer
    from embeddings import ThreatEmbedder
    from clustering import ThreatClusterer
    
    print("="*60)
    print("TESTING RISK SCORER")
    print("="*60 + "\n")
    
    # Create test data
    test_threats = pd.DataFrame({
        'name': [
            'SolarWinds-like supply chain attack',
            'Ransomware targeting hospitals',
            'Low-severity phishing attempt',
        ],
        'description': [
            'Supply chain compromise via software update with backdoor trojan and persistence mechanisms',
            'Ransomware attack encrypting healthcare systems with credential dumping and lateral movement',
            'Simple phishing email with suspicious link',
        ]
    })
    
    # Initialize pipeline
    embedder = ThreatEmbedder()
    embeddings = embedder.embed_batch(test_threats['description'].tolist())
    
    clusterer = ThreatClusterer(num_clusters=2)
    clusterer.fit(embeddings)
    labels = clusterer.predict(embeddings)
    
    # Test scoring
    scorer = RiskScorer(embedder, clusterer)
    df_scored = scorer.score_threats(test_threats, embeddings, labels)
    
    print("Scored Threats:")
    print(df_scored[['name', 'risk_score', 'similarity_score', 'keyword_score', 'novelty_score']])
    
    print("\n✅ Risk scorer test complete!")