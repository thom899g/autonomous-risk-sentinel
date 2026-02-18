import requests
from typing import Dict, List, Optional
import logging
from datetime import datetime, timedelta
from .settings import Settings

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """
    A class to gather and process threat intelligence data from various sources.
    Implements error handling and logging for robust operation.
    """

    def __init__(self):
        self.settings = Settings()
        self.headers = {
            'Content-Type': 'application/json',
            'API-Key': self.settings.api_key  # Assuming API key is set in config
        }

    def fetch_attack_data(self) -> Dict:
        """
        Fetches the latest MITRE ATT&CK data.
        Returns a dictionary containing attack patterns and tactics.
        Implements error handling for network issues and parsing errors.
        """
        try:
            response = requests.get(
                self.settings.attack_api_url,
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch attack data: {str(e)}")
            return {}

    def fetch_cve_data(self, cve_id: str) -> Optional[Dict]:
        """
        Fetches CVE details for a specific ID.
        Returns a dictionary with CVE information or None if not found.
        Implements error handling for network issues and invalid IDs.
        """
        try:
            response = requests.get(
                f"{self.settings.cve_api_url}{cve_id}",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch CVE {cve_id}: {str(e)}")
            return None

    def process_indicators(self, data: Dict) -> List[str]:
        """
        Processes threat intelligence data to extract indicators of compromise (IOCs).
        Returns a list of IOCs for further analysis.
        Handles empty or malformed data gracefully.
        """
        if not data:
            logger.warning("Empty threat intelligence data received")
            return []
        
        iocs = []
        try:
            # Example: Extracting domains from attack patterns
            for tactic in data.get('tactics', []):
                for technique in tactic.get('techniques', []):
                    for subtech in technique.get('subtechniques', []):
                        iocs.extend(self._extract_domains(subtech))
            
            return iocs
        except (KeyError, AttributeError) as e:
            logger.error(f"Failed to process threat data: {str(e)}")
            return []

    def _extract_domains(self, subtech: Dict) -> List[str]:
        """
        Helper function to extract domains from a given technique's data.
        Returns a list of domain strings or empty list if none found.
        """
        domains = []
        # Example pattern: "http://example.com/attack"
        for description in [subtech.get('description', '')]:
            # Simple regex to extract domains
            import re
            matches = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|%20|'
                                  r'[:\\?&#;.]|[~])+', description)
            for match in matches:
                domains.append(match.split('://')[-1])
        return domains

def main():
    ti = ThreatIntelligence()
    attack_data = ti.fetch_attack_data()
    cve_id = "CVE-2023-45678"
    cve_details = ti.fetch_cve_data(cve_id)
    
    if attack_data:
        iocs = ti.process_indicators(attack_data)
        logger.info(f"Extracted {len(iocs)} IOCs from MITRE ATT&CK data")
        
    if cve_details:
        logger.info(f"CVE {cve_id} details: {cve_details}")
    
if __name__ == "__main__":
    main()