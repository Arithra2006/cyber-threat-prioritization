"""
Main ML Pipeline
Orchestrates the complete threat prioritization workflow
"""

import os
import pandas as pd
import numpy as np
import pickle
from datetime import datetime
import structlog

from src.ml_pipeline.embeddings import ThreatEmbedder
from src.ml_pipeline.deduplication import ThreatDeduplicator
from src.ml_pipeline.clustering import ThreatClusterer
from src.ml_pipeline.risk_scoring import RiskScorer

logger = structlog.get_logger()

class ThreatPrioritizationPipeline:
    """End-to-end ML pipeline for cyber threat prioritization"""
    
    def __init__(self):
        """Initialize pipeline components"""
        self.embedder = None
        self.deduplicator = None
        self.clusterer = None
        self.scorer = None
        
        self.df_raw = None
        self.df_dedup = None
        self.df_scored = None
        
        self.embeddings_raw = None
        self.embeddings_dedup = None
        self.cluster_labels = None
        
        logger.info("Pipeline initialized")
    
    def load_data(self, csv_path: str = 'data/raw/otx_threats_static.csv') -> pd.DataFrame:
        """
        Load raw threat data
        
        Args:
            csv_path: Path to threat CSV file
            
        Returns:
            DataFrame with threat data
        """
        print("="*70)
        print("🚀 THREAT PRIORITIZATION PIPELINE")
        print("="*70 + "\n")
        
        logger.info("Loading threat data", path=csv_path)
        print(f"📥 Loading threat data from: {csv_path}")
        
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Data file not found: {csv_path}")
        
        self.df_raw = pd.read_csv(csv_path)
        
        print(f"✅ Loaded {len(self.df_raw)} threats")
        print(f"   Columns: {list(self.df_raw.columns)}\n")
        
        logger.info("Data loaded", num_threats=len(self.df_raw))
        
        return self.df_raw
    
    def generate_embeddings(self) -> np.ndarray:
        """
        Generate semantic embeddings for all threats
        
        Returns:
            Embedding matrix
        """
        print("-"*70)
        print("STEP 1: EMBEDDING GENERATION")
        print("-"*70 + "\n")
        
        self.embedder = ThreatEmbedder()
        
        descriptions = self.df_raw['description'].tolist()
        self.embeddings_raw = self.embedder.embed_batch(descriptions, batch_size=32)
        
        logger.info("Embeddings generated", shape=self.embeddings_raw.shape)
        
        return self.embeddings_raw
    
    def deduplicate(self) -> pd.DataFrame:
        """
        Remove duplicate threats
        
        Returns:
            Deduplicated DataFrame
        """
        print("-"*70)
        print("STEP 2: DEDUPLICATION")
        print("-"*70 + "\n")
        
        self.deduplicator = ThreatDeduplicator()
        
        self.df_dedup, self.embeddings_dedup, dup_report = self.deduplicator.remove_duplicates(
            self.df_raw,
            self.embeddings_raw
        )
        
        # Save duplicate report
        if len(dup_report) > 0:
            dup_report_path = 'data/processed/duplicate_report.csv'
            dup_report.to_csv(dup_report_path, index=False)
            print(f"📝 Duplicate report saved to: {dup_report_path}\n")
        
        logger.info("Deduplication complete", 
                   original=len(self.df_raw),
                   deduplicated=len(self.df_dedup))
        
        return self.df_dedup
    
    def cluster_threats(self) -> np.ndarray:
        """
        Cluster threats into attack patterns
        
        Returns:
            Cluster labels
        """
        print("-"*70)
        print("STEP 3: CLUSTERING")
        print("-"*70 + "\n")
        
        self.clusterer = ThreatClusterer()
        self.clusterer.fit(self.embeddings_dedup)
        
        self.cluster_labels = self.clusterer.predict(self.embeddings_dedup)
        
        # Get cluster statistics
        cluster_stats = self.clusterer.get_cluster_stats(self.cluster_labels, self.df_dedup)
        
        print("📊 Cluster Distribution:")
        print(cluster_stats[['cluster_id', 'size', 'percentage', 'top_tags']].to_string(index=False))
        print()
        
        # Save cluster stats
        cluster_stats_path = 'data/processed/cluster_statistics.csv'
        cluster_stats.to_csv(cluster_stats_path, index=False)
        print(f"📝 Cluster stats saved to: {cluster_stats_path}\n")
        
        logger.info("Clustering complete", num_clusters=len(set(self.cluster_labels)))
        
        return self.cluster_labels
    
    def calculate_risk_scores(self) -> pd.DataFrame:
        """
        Calculate risk scores for all threats
        
        Returns:
            DataFrame with risk scores
        """
        print("-"*70)
        print("STEP 4: RISK SCORING")
        print("-"*70 + "\n")
        
        self.scorer = RiskScorer(self.embedder, self.clusterer)
        
        self.df_scored = self.scorer.score_threats(
            self.df_dedup,
            self.embeddings_dedup,
            self.cluster_labels
        )
        
        # Show top threats
        print("🔥 Top 10 Highest Risk Threats:")
        print("-"*70)
        for idx, row in self.df_scored.head(10).iterrows():
            print(f"{idx + 1}. Risk: {row['risk_score']:.3f} | {row['name'][:60]}")
        print()
        
        logger.info("Risk scoring complete",
                   mean_score=self.df_scored['risk_score'].mean())
        
        return self.df_scored
    
    def save_results(self, output_path: str = 'data/processed/threats_scored.csv'):
        """
        Save final scored threats to CSV
        
        Args:
            output_path: Path to save results
        """
        print("-"*70)
        print("STEP 5: SAVING RESULTS")
        print("-"*70 + "\n")
        
        self.df_scored.to_csv(output_path, index=False)
        
        print(f"✅ Results saved to: {output_path}")
        print(f"   Total threats: {len(self.df_scored)}")
        print(f"   Columns: {list(self.df_scored.columns)}\n")
        
        # Save pipeline artifacts
        artifacts = {
            'embedder': self.embedder,
            'clusterer': self.clusterer,
            'scorer': self.scorer,
            'embeddings': self.embeddings_dedup,
            'cluster_labels': self.cluster_labels,
        }
        
        artifacts_path = 'data/processed/pipeline_artifacts.pkl'
        with open(artifacts_path, 'wb') as f:
            pickle.dump(artifacts, f)
        
        print(f"💾 Pipeline artifacts saved to: {artifacts_path}\n")
        
        logger.info("Results saved", path=output_path)
    
    def run_full_pipeline(self, csv_path: str = 'data/raw/otx_threats_static.csv'):
        """
        Run the complete pipeline end-to-end
        
        Args:
            csv_path: Path to input threat CSV
        """
        start_time = datetime.now()
        
        try:
            # Step 0: Load data
            self.load_data(csv_path)
            
            # Step 1: Generate embeddings
            self.generate_embeddings()
            
            # Step 2: Deduplicate
            self.deduplicate()
            
            # Step 3: Cluster threats
            self.cluster_threats()
            
            # Step 4: Calculate risk scores
            self.calculate_risk_scores()
            
            # Step 5: Save results
            self.save_results()
            
            # Summary
            elapsed = (datetime.now() - start_time).total_seconds()
            
            print("="*70)
            print("✅ PIPELINE COMPLETE!")
            print("="*70)
            print(f"⏱️  Total time: {elapsed:.1f} seconds")
            print(f"📊 Original threats: {len(self.df_raw)}")
            print(f"🔍 After deduplication: {len(self.df_dedup)}")
            print(f"🎯 Mean risk score: {self.df_scored['risk_score'].mean():.3f}")
            print(f"🔥 High-risk threats (score > 0.6): {len(self.df_scored[self.df_scored['risk_score'] > 0.6])}")
            print("="*70 + "\n")
            
            logger.info("Pipeline execution complete", elapsed_seconds=elapsed)
            
            return self.df_scored
            
        except Exception as e:
            logger.error("Pipeline failed", error=str(e))
            print(f"\n❌ Pipeline failed: {str(e)}")
            raise


if __name__ == "__main__":
    # Run the pipeline
    pipeline = ThreatPrioritizationPipeline()
    results = pipeline.run_full_pipeline()
    
    print("🎉 You can now run the dashboard!")
    print("   Command: streamlit run src/dashboard/app.py")