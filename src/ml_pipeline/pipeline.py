import os
import pandas as pd
import numpy as np
import pickle
from datetime import datetime
import structlog
import mlflow
import mlflow.sklearn

from src.ml_pipeline.embeddings import ThreatEmbedder
from src.ml_pipeline.deduplication import ThreatDeduplicator
from src.ml_pipeline.clustering import ThreatClusterer
from src.ml_pipeline.risk_scoring import RiskScorer

logger = structlog.get_logger()

class ThreatPrioritizationPipeline:
    """End-to-end ML pipeline for cyber threat prioritization"""
    
    def __init__(self, experiment_name: str = "threat-prioritization"):
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
        
        # Initialize MLflow
        mlflow.set_experiment(experiment_name)
        
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
        
        # Log to MLflow
        mlflow.log_param("input_data_path", csv_path)
        mlflow.log_metric("raw_threat_count", len(self.df_raw))
        
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
        
        # Log to MLflow
        mlflow.log_param("embedding_model", self.embedder.model_name)
        mlflow.log_param("embedding_dimension", self.embeddings_raw.shape[1])
        mlflow.log_param("batch_size", 32)
        
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
            mlflow.log_artifact(dup_report_path)
        
        logger.info("Deduplication complete", 
                   original=len(self.df_raw),
                   deduplicated=len(self.df_dedup))
        
        # Log to MLflow
        duplicates_removed = len(self.df_raw) - len(self.df_dedup)
        dedup_rate = duplicates_removed / len(self.df_raw) * 100
        
        mlflow.log_metric("deduplicated_threat_count", len(self.df_dedup))
        mlflow.log_metric("duplicates_removed", duplicates_removed)
        mlflow.log_metric("deduplication_rate_percent", dedup_rate)
        mlflow.log_param("similarity_threshold", self.deduplicator.threshold)
        
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
        
        # Log to MLflow
        num_clusters = len(set(self.cluster_labels))
        mlflow.log_param("clustering_algorithm", "HDBSCAN")
        mlflow.log_metric("num_clusters", num_clusters)
        mlflow.log_metric("noise_points", sum(self.cluster_labels == -1))
        mlflow.log_artifact(cluster_stats_path)
        
        # Log cluster size statistics
        cluster_sizes = cluster_stats['size'].values
        mlflow.log_metric("avg_cluster_size", cluster_sizes.mean())
        mlflow.log_metric("max_cluster_size", cluster_sizes.max())
        mlflow.log_metric("min_cluster_size", cluster_sizes.min())
        
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
        
        # Log to MLflow - Risk Score Metrics
        risk_scores = self.df_scored['risk_score']
        mlflow.log_metric("mean_risk_score", risk_scores.mean())
        mlflow.log_metric("median_risk_score", risk_scores.median())
        mlflow.log_metric("std_risk_score", risk_scores.std())
        mlflow.log_metric("max_risk_score", risk_scores.max())
        mlflow.log_metric("min_risk_score", risk_scores.min())
        
        # Risk distribution
        high_risk = len(self.df_scored[self.df_scored['risk_score'] > 0.6])
        medium_risk = len(self.df_scored[(self.df_scored['risk_score'] > 0.4) & 
                                         (self.df_scored['risk_score'] <= 0.6)])
        low_risk = len(self.df_scored[self.df_scored['risk_score'] <= 0.4])
        
        mlflow.log_metric("high_risk_threats", high_risk)
        mlflow.log_metric("medium_risk_threats", medium_risk)
        mlflow.log_metric("low_risk_threats", low_risk)
        
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
        
        # Log artifacts to MLflow
        mlflow.log_artifact(output_path)
        mlflow.log_artifact(artifacts_path)
        mlflow.log_param("output_path", output_path)
    
    def run_full_pipeline(self, csv_path: str = 'data/raw/otx_threats_static.csv'):
        """
        Run the complete pipeline end-to-end
        
        Args:
            csv_path: Path to input threat CSV
        """
        start_time = datetime.now()
        
        # Start MLflow run
        with mlflow.start_run():
            try:
                # Log pipeline metadata
                mlflow.set_tag("pipeline_version", "1.0")
                mlflow.set_tag("run_date", start_time.isoformat())
                
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
                
                # Log final metrics
                mlflow.log_metric("total_execution_time_seconds", elapsed)
                mlflow.set_tag("status", "success")
                
                print("="*70)
                print("✅ PIPELINE COMPLETE!")
                print("="*70)
                print(f"⏱️  Total time: {elapsed:.1f} seconds")
                print(f"📊 Original threats: {len(self.df_raw)}")
                print(f"🔍 After deduplication: {len(self.df_dedup)}")
                print(f"🎯 Mean risk score: {self.df_scored['risk_score'].mean():.3f}")
                print(f"🔥 High-risk threats (score > 0.6): {len(self.df_scored[self.df_scored['risk_score'] > 0.6])}")
                print(f"📈 MLflow tracking URI: {mlflow.get_tracking_uri()}")
                print(f"🔬 MLflow run ID: {mlflow.active_run().info.run_id}")
                print("="*70 + "\n")
                
                logger.info("Pipeline execution complete", elapsed_seconds=elapsed)
                
                return self.df_scored
                
            except Exception as e:
                # Log failure
                mlflow.set_tag("status", "failed")
                mlflow.log_param("error_message", str(e))
                
                logger.error("Pipeline failed", error=str(e))
                print(f"\n❌ Pipeline failed: {str(e)}")
                raise


if __name__ == "__main__":
    # Run the pipeline
    pipeline = ThreatPrioritizationPipeline()
    results = pipeline.run_full_pipeline()
    
    print("🎉 You can now run the dashboard!")
    print("   Command: streamlit run src/dashboard/app.py")
    print("\n📊 View MLflow experiments:")
    print("   Command: mlflow ui")
    print("   Then open: http://localhost:5000")