"""
AlienVault OTX Threat Data Collection
Fetches threat intelligence pulses and filters for quality
"""

import os
import requests
import pandas as pd
from datetime import datetime
from typing import List, Dict
from dotenv import load_dotenv
import structlog
from tqdm import tqdm
import time

# Setup logging
logger = structlog.get_logger()

# Load environment variables
load_dotenv()

class OTXThreatCollector:
    """Collects and filters threat data from AlienVault OTX"""
    
    def __init__(self):
        self.api_key = os.getenv('OTX_API_KEY')
        if not self.api_key:
            raise ValueError("OTX_API_KEY not found in .env file!")
        
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {'X-OTX-API-KEY': self.api_key}
        self.min_description_length = int(os.getenv('MIN_DESCRIPTION_LENGTH', 100))
        
        # Quality filter tags
        self.relevant_tags = [
            'malware', 'ransomware', 'phishing', 'apt', 'trojan',
            'backdoor', 'exploit', 'vulnerability', 'botnet',
            'supply chain', 'zero-day', 'threat actor'
        ]
        
        logger.info("OTX Collector initialized", api_key_present=bool(self.api_key))
    
    def fetch_pulses(self, max_pulses: int = 3000) -> List[Dict]:
        """
        Fetch threat pulses from OTX API
        
        Args:
            max_pulses: Maximum number of pulses to fetch
            
        Returns:
            List of pulse dictionaries
        """
        logger.info("Starting pulse collection", max_pulses=max_pulses)
        
        all_pulses = []
        page = 1
        
        with tqdm(total=max_pulses, desc="Fetching OTX pulses") as pbar:
            while len(all_pulses) < max_pulses:
                try:
                    # Fetch one page of pulses
                    url = f"{self.base_url}/pulses/subscribed"
                    params = {'page': page, 'limit': 50}
                    
                    response = requests.get(url, headers=self.headers, params=params, timeout=10)
                    response.raise_for_status()
                    
                    data = response.json()
                    results = data.get('results', [])
                    
                    if not results:
                        logger.info("No more pulses available")
                        break
                    
                    all_pulses.extend(results)
                    pbar.update(len(results))
                    page += 1
                    
                    # Rate limiting
                    time.sleep(0.5)
                    
                except requests.exceptions.RequestException as e:
                    logger.error("API request failed", error=str(e), page=page)
                    break
        
        logger.info("Pulse collection complete", total_fetched=len(all_pulses))
        return all_pulses[:max_pulses]
    
    def filter_quality_threats(self, pulses: List[Dict]) -> pd.DataFrame:
        """
        Filter pulses for quality and relevance
        
        Args:
            pulses: Raw pulse data from API
            
        Returns:
            DataFrame of filtered, quality threats
        """
        logger.info("Starting quality filtering", input_count=len(pulses))
        
        filtered_threats = []
        
        for pulse in tqdm(pulses, desc="Filtering threats"):
            # Extract key fields
            description = pulse.get('description', '').strip()
            name = pulse.get('name', '').strip()
            tags = [tag.lower() for tag in pulse.get('tags', [])]
            created = pulse.get('created', '')
            references = pulse.get('references', [])
            
            # Quality checks
            if len(description) < self.min_description_length:
                continue
            
            if not any(tag in ' '.join(tags) for tag in self.relevant_tags):
                continue
            
            if not name:
                continue
            
            # Build threat record
            threat = {
                'id': pulse.get('id', ''),
                'name': name,
                'description': description,
                'tags': ', '.join(tags),
                'created_date': created,
                'references': ', '.join(references) if references else '',
                'source': 'AlienVault OTX',
                'author': pulse.get('author', {}).get('username', 'Unknown')
            }
            
            filtered_threats.append(threat)
        
        df = pd.DataFrame(filtered_threats)
        logger.info("Quality filtering complete", 
                   output_count=len(df),
                   filter_rate=f"{(1 - len(df)/len(pulses))*100:.1f}%")
        
        return df
    
    def save_dataset(self, df: pd.DataFrame, filename: str = 'otx_threats_static.csv'):
        """Save filtered threats to CSV"""
        output_path = os.path.join('data', 'raw', filename)
        df.to_csv(output_path, index=False)
        logger.info("Dataset saved", path=output_path, records=len(df))
        print(f"\n✅ Saved {len(df)} threats to {output_path}")
        
    def collect_and_save(self, max_pulses: int = 3000):
        """Full collection pipeline"""
        print("🚀 Starting OTX threat collection...")
        print(f"📊 Target: {max_pulses} pulses")
        print(f"🔍 Min description length: {self.min_description_length} chars\n")
        
        # Fetch raw pulses
        pulses = self.fetch_pulses(max_pulses)
        
        if not pulses:
            print("❌ No pulses fetched. Check your API key!")
            return
        
        # Filter for quality
        df = self.filter_quality_threats(pulses)
        
        # Save to CSV
        self.save_dataset(df)
        
        # Print summary
        print(f"\n📈 Collection Summary:")
        print(f"   Raw pulses fetched: {len(pulses)}")
        print(f"   Quality threats: {len(df)}")
        print(f"   Filter rate: {(1 - len(df)/len(pulses))*100:.1f}%")
        print(f"   Date range: {df['created_date'].min()} to {df['created_date'].max()}")
        

if __name__ == "__main__":
    # Run the collector
    collector = OTXThreatCollector()
    collector.collect_and_save(max_pulses=3000)