# 🛡️ AI-Powered Cyber Threat Prioritization System

[![Tests](https://github.com/Arithra2006/cyber-threat-prioritization/actions/workflows/tests.yml/badge.svg)](https://github.com/Arithra2006/cyber-threat-prioritization/actions/workflows/tests.yml)
[![Python 3.9](https://img.shields.io/badge/python-3.9-blue.svg)](https://www.python.org/downloads/)


An ML-powered threat intelligence system that helps Security Operations Center (SOC) analysts prioritize cyber threats by ranking them based on similarity to verified critical incidents, MITRE ATT&CK keyword matching, and novelty detection.

**Try Live Demo here**: [https://cyber-threat-prioritization.streamlit.app](https://cyber-threat-prioritization.streamlit.app)

![Dashboard 1 Screenshot](screenshots/dashboard-main-1.png)
![Dashboard 2 Screenshot](screenshots/dashboard-main-2.png)
![Analytics Screenshot](screenshots/analytics.png)
![Analytics Screenshot](screenshots/analytics-2.png)
![metrics Screenshot](screenshots/metrics-tab.png)
![threat-details Screenshot](screenshots/threat-detail.png)

## 🧩 The Problem

Security Operations Centers process *thousands of threat alerts daily*. Existing prioritization methods rely heavily on recency or simple keyword rules, leading to:
- *Alert fatigue* - Analysts overwhelmed by false positives
- *Missed critical threats* - High-impact incidents buried in noise
- *Inefficient triage* - No semantic understanding of threat relationships

This system explores whether *semantic similarity + structured threat knowledge* (MITRE ATT&CK) can improve ranking quality and help analysts focus on what matters most.

## 🎯 Key Features

- *Intelligent Threat Ranking*: Scores threats based on similarity to CISA critical incidents, MITRE ATT&CK patterns, and novelty
- *Pattern Detection*: Unsupervised clustering identifies 10 distinct attack patterns
- *Real-time Dashboard*: Interactive Streamlit interface for threat analysis
- *MLflow Experiment Tracking*: Comprehensive metrics logging and experiment management
- *Structured Logging*: Professional logging with structlog for production monitoring
- *Production-Ready*: Docker containerization, CI/CD pipeline, comprehensive testing
- *Explainable AI*: Transparent risk scoring with component breakdowns

## 📊 Performance Metrics

| Metric | Value |
|--------|-------|
| Precision @150 | *90.7%* |
| Recall @150 | *65.7%* |
| F1-Score | *0.762* |
| Baseline Improvement | *+108%* |
| Processing Speed | 405 threats in 47 seconds |
| Deduplication Rate | 5.4% |

*Why Top-150?* Security analysts typically review 100-150 threats per day. This threshold balances precision (minimizing false alarms) with recall (catching critical threats) for real-world SOC workflows.

## 🚀 Quick Start

### Using Docker (Recommended)

bash
# Clone repository
git clone https://github.com/Arithra2006/cyber-threat-prioritization.git
cd cyber-threat-prioritization

# Run with Docker Compose
docker-compose up

# Access dashboard at http://localhost:8501


### Local Installation

bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env and add your AlienVault OTX API key

# Run data collection
python src/data_collection/fetch_otx_threats.py

# Run ML pipeline
python -m src.ml_pipeline.pipeline

# Launch dashboard
streamlit run src/dashboard/app.py

# View MLflow experiments (optional)
mlflow ui
# Then open http://localhost:5000

### Primary Dataset
- *AlienVault OTX*: 430 high-quality threat pulses (filtered by description length and relevant tags)

### Auxiliary Datasets
- *CISA Critical Incidents*: 12 verified critical advisories (ground truth for similarity scoring)
- *MITRE ATT&CK Framework*: Technique keywords for pattern matching

## System Overview
Architecture
Data Collection → Embedding (384D) → Deduplication → Clustering (k=10) → Risk Scoring
     (OTX)         (MiniLM-L6-v2)    (0.85 sim)      (KMeans)          (Weighted)
Risk Scoring Formula:
Risk Score = 0.50 × Similarity + 0.40 × Keywords + 0.10 × Novelty 

Why these weights?
- Similarity (50%) - Prioritizes threats matching 12 verified CISA critical incidents (highest signal)
- Keywords (40%) - MITRE ATT&CK technique matching indicates established attack patterns
- Novelty (10%) - Distance from cluster centroids flags emerging threats (weighted lower due to higher false positive rate)
- Derived from SOC analyst priority heuristics. Future work includes grid search optimization against historical CISA severity ratings.

Key Technical Decisions
Embedding Model: sentence-transformers/all-MiniLM-L6-v2
- Balances 5ms latency with semantic accuracy for real-time SOC use
- 384D vectors enable efficient similarity computations
- Prioritized speed over larger models (e.g., BGE-large) for production feasibility
Clustering: KMeans (k=10) via Elbow + Silhouette Score
- Identifies distinct attack patterns: ransomware, phishing, supply chain, APT
- Clusters align with known MITRE ATT&CK tactics

Dashboard Features:
- 📊 Threat Rankings - Sorted by risk score with expandable details
- 📈 Analytics - Risk distribution, cluster patterns, timeline
- 🗺️ Similarity Heatmap - Threat relationship visualization
- 🎯 Performance Metrics - Precision/recall curves, baseline comparison

MLflow Tracking:
- Logs all pipeline parameters (model configs, thresholds)
- Tracks 20+ metrics (accuracy, deduplication rate, cluster stats)
- Stores artifacts (models, reports, scored threats)
- Enables experiment comparison and reproducibility


## 📈 Evaluation

The SOC Trade-off
In Security Operations Centers, Recall is typically more important than Precision:
- Low Precision → Analysts review extra false alarms (annoying, but safe)
- Low Recall → Critical threats slip through undetected (catastrophic)
Our approach: At the Top-50 threshold, the system achieves 100% precision, ensuring the initial batch of alerts is fully actionable. However, to capture a wider net of threats and increase Recall to 65.7%, we accept a Precision drop to 90.7% at the Top-150 mark—a trade-off that balances analyst workload with comprehensive threat detection.

Methodology
Ground Truth: 12 CISA critical incidents (KEV catalog entries from 2024-2025)
Validation Approach: Leave-one-out cross-validation to measure ranking effectiveness
Metric Calculation:
- Precision @K: Percentage of top-K threats that match CISA critical incidents
- Recall @K: Percentage of CISA incidents captured in top-K threats
Caveat: Small ground truth (12 incidents) may lead to optimistic precision estimates. Results should be validated against larger incident databases in production deployment.

### Baseline Comparison (Top-50)

| Method | Recall | Precision |
|--------|--------|-----------|
| Random Ranking | 12.1% | ~51% |
| Recency-Only | 11.6% | ~53% |
| *Our System* | *24.2%* | *100%* |
| *Improvement* | *+108%* | *+96%* |

### Precision-Recall Trade-off

| Top-K | Precision | Recall  | F1-Score |
|-------|-----------|-------- |----------|
| 50    | 100.0%    | 24.2%   | 0.389 |
| 100   | 100.0%    | 48.3%   | 0.651 |
| 150   | 90.7%     | 65.7%   | 0.762 |
| 200   | 76.0%     | 73.4%   | 0.747 |

## 🧪 Testing

bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_risk_scoring.py -v


*Test Coverage*: 15+ unit tests covering embeddings, deduplication, clustering, and risk scoring.


## 🛠️ Technology Stack

- *ML/AI*: SentenceTransformers, scikit-learn, NumPy, pandas
- *Dashboard*: Streamlit, Plotly
- *MLOPS*: MLflow(experiment tracking),structlog(logging)
- *Data Sources*: AlienVault OTX, MITRE ATT&CK, CISA Advisories
- *Infrastructure*: Docker, Docker Compose
- *Testing*: pytest, GitHub Actions

## 🎓 Use Cases

- *SOC Threat Triage*: Prioritize daily threat feed review
- *Incident Response*: Identify high-priority threats requiring immediate action
- *Threat Intelligence*: Discover emerging attack patterns
- *Security Research*: Analyze threat landscape trends

## ⚠️ Limitations

- Data Scale
Current Dataset: 430 threats (proof-of-concept scale)
Production Reality: SOCs process 1,000-10,000+ daily threats
Mitigation: Architecture is designed for horizontal scaling; embedding generation and clustering are parallelizable
- Ground Truth Size
Current: Only 12 CISA incidents for similarity scoring
Impact: May lead to overfitting and optimistic precision estimates
Solution Path:
Expand to 100+ incidents from CISA KEV catalog
Incorporate synthetic data generation using LLMs to create diverse critical threat scenarios
Implement analyst feedback loop to refine ground truth continuously
- Temporal Modeling
Gap: Doesn't track threat evolution over time or detect campaign patterns
Future Work: Add temporal embeddings and sequence modeling for APT campaign detection

## 🔮 Future Enhancements

- [ ] Live threat feed integration
- [ ] Analyst feedback loop for weight optimization
- [ ] Expanded ground truth (100+ critical incidents)
- [ ] Multi-model ensemble (combine multiple embeddings)
- [ ] Temporal pattern detection (trend analysis)
- [ ] Custom MITRE ATT&CK mappings per organization

## 📁 Project Structure

cyber-threat-prioritization/
├── src/
│   ├── data_collection/       # OTX API, MITRE, CISA data
│   ├── ml_pipeline/            # Embeddings, clustering, scoring
│   └── dashboard/              # Streamlit interface
├── tests/                      # Unit tests (pytest)
├── data/
│   ├── raw/                    # Raw threat data
│   └── processed/              # Scored threats, models
├── mlruns/                     # MLflow experiment tracking
├── docker-compose.yml          # Container orchestration
├── Dockerfile                  # Container image
├── requirements.txt            # Python dependencies
└── README.md

## 🙏 Acknowledgments

- *AlienVault OTX*: Threat intelligence data
- *MITRE Corporation*: ATT&CK Framework
- *CISA*: Critical incident advisories
- *Hugging Face*: Sentence-Transformers models

## 📧 Contact

*Arithra Mayur* - [arithramayur@gmail.com](mailto:arithramayur@gmail.com)

Project Link: [https://github.com/Arithra2006/cyber-threat-prioritization]

---
