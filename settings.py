import os
from typing import Dict, Any

class Settings:
    """
    Singleton class to manage application settings and configurations.
    Implements error handling for missing configuration values.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.load_settings()
        return cls._instance

    def load_settings(self):
        """
        Loads settings from environment variables or configuration files.
        Raises ValueError for missing required configurations.
        """
        self.api_key = os.getenv("THREAT_INTELLIGENCE_API_KEY")
        self.attack_api_url = os.getenv("MITRE_ATTACK_API_URL", 
                                      "https://attack.mitre.org/api/v3/techniques/")
        self.cve_api_url = os.getenv("CVE_MIRROR_API_URL", 
                                    "https://cve.mitre.org/data/base/")

        if not self.api_key:
            raise ValueError("THREAT_INTELLIGENCE_API_KEY is required")

    def __str__(self) -> str:
        return f"Settings loaded with API key: {self.api_key}"

    @property
    def as_dict(self) -> Dict[str, Any]:
        """
        Returns settings as a dictionary for easy access.
        """
        return {
            "api_key": self.api_key,
            "attack_api_url": self.attack_api_url,
            "cve_api_url": self.cve_api_url
        }