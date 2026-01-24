"""
Improved Risk Scoring - Better Recall
Run this to re-score threats with improved formula
"""

import pandas as pd
import numpy as np
import pickle

def recalculate_risk_scores(df_path='data/processed/threats_scored.csv',
                            artifacts_path='data/processed/pipeline_artifacts.pkl'):
    """
    Recalculate risk scores with improved weights
    """
    
    print("="*70)
    print("🔄 RECALCULATING RISK SCORES WITH IMPROVED FORMULA")
    print("="*70 + "\n")
    
    # Load data
    df = pd.read_csv(df_path)
    
    with open(artifacts_path, 'rb') as f:
        artifacts = pickle.load(f)
    
    print(f"📊 Loaded {len(df)} threats\n")
    
    # NEW IMPROVED WEIGHTS
    # Reduce novelty weight since it's always 1.0
    # Increase similarity and keyword weights
    SIMILARITY_WEIGHT = 0.50  # Was 0.33
    KEYWORD_WEIGHT = 0.40     # Was 0.33
    NOVELTY_WEIGHT = 0.10     # Was 0.34
    
    print("⚙️  New Scoring Weights:")
    print(f"   Similarity: {SIMILARITY_WEIGHT:.0%}")
    print(f"   Keywords:   {KEYWORD_WEIGHT:.0%}")
    print(f"   Novelty:    {NOVELTY_WEIGHT:.0%}\n")
    
    # Recalculate risk scores
    df['risk_score_new'] = (
        SIMILARITY_WEIGHT * df['similarity_score'] +
        KEYWORD_WEIGHT * df['keyword_score'] +
        NOVELTY_WEIGHT * df['novelty_score']
    )
    
    # Keep old score for comparison
    df['risk_score_old'] = df['risk_score']
    df['risk_score'] = df['risk_score_new']
    
    # Re-sort by new risk score
    df = df.sort_values('risk_score', ascending=False).reset_index(drop=True)
    
    # Compare old vs new
    print("📈 Score Distribution Comparison:")
    print(f"   Old Mean: {df['risk_score_old'].mean():.3f}")
    print(f"   New Mean: {df['risk_score_new'].mean():.3f}")
    print(f"   Old Max:  {df['risk_score_old'].max():.3f}")
    print(f"   New Max:  {df['risk_score_new'].max():.3f}\n")
    
    # Show top 10
    print("🔥 New Top 10 Threats:")
    print("-"*70)
    for idx, row in df.head(10).iterrows():
        print(f"{idx+1:2d}. Score: {row['risk_score']:.3f} (was {row['risk_score_old']:.3f}) | {row['name'][:50]}")
    print()
    
    # Calculate new metrics
    df['is_critical'] = (df['similarity_score'] > 0.55) | (df['num_keywords_matched'] >= 3)
    total_critical = df['is_critical'].sum()
    
    print("📊 Recall at Different Top-K:")
    print("-"*70)
    for k in [10, 20, 50, 100, 150]:
        top_k = df.head(k)
        found = top_k['is_critical'].sum()
        recall = found / total_critical
        precision = found / k
        print(f"   Top-{k:3d}: Precision={precision:5.1%}, Recall={recall:5.1%}, Found={found:3d}/{total_critical}")
    print()
    
    # Save updated scores
    output_path = 'data/processed/threats_scored_improved.csv'
    df.to_csv(output_path, index=False)
    
    print(f"✅ Saved improved scores to: {output_path}")
    print(f"   Use this file for the dashboard!\n")
    
    print("="*70)
    print("✅ RECALCULATION COMPLETE!")
    print("="*70)

if __name__ == "__main__":
    recalculate_risk_scores()