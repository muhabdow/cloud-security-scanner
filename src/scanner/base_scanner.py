"""
Base scanner class with common functionality
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
import yaml
from pathlib import Path

class BaseScanner(ABC):
    def __init__(self, config_dir: str):
        self.config_dir = Path(config_dir)
        self.checks = self.load_checks()
    
    @abstractmethod
    def get_config_file(self) -> str:
        """Return the config file name for this scanner"""
        pass
    
    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """Perform the security scan"""
        pass
    
    def load_checks(self) -> Dict:
        """Load security checks configuration"""
        config_file = self.config_dir / self.get_config_file()
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        return {}
    
    def create_finding(self, check_id: str, resource_id: str, 
                      resource_type: str, severity: str, 
                      description: str, remediation: str = None,
                      metadata: Dict = None) -> Dict:
        """Create a standardized finding object"""
        return {
            "check_id": check_id,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "severity": severity,
            "description": description,
            "remediation": remediation or "No remediation guidance available",
            "metadata": metadata or {}
        }