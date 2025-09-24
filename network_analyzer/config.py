# Standard library imports
import os
import logging
import yaml
from pathlib import Path
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Config:
    """Configuration manager for the network analyzer."""
    
    DEFAULT_CONFIG = {
        'portscan': {
            'window_seconds': 60,
            'unique_port_threshold': 20,
            'syn_threshold': 10
        },
        'dns': {
            'length_threshold': 45,
            'entropy_threshold': 3.5
        },
        'data_exfil': {
            'ratio_threshold': 3.0,
            'min_out_bytes': 500000,
            'baseline_window': 3600,
            'alert_multiplier': 2.0
        },
        'ports': {
            'uncommon_min_occurrences': 5,
            'top_common': 10
        },
        'memory': {
            'max_port_samples': 1000,
            'cleanup_interval': 10000
        },
        'output': {
            'reports_dir': 'reports',
            'json_report': True,
            'txt_report': True
        }
    }

    def __init__(self, config_path: str = None):
        """Initialize configuration.
        
        Args:
            config_path: Optional path to config YAML file
        """
        self.config = self.DEFAULT_CONFIG.copy()
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
        
        # Ensure reports directory exists
        os.makedirs(self.get(['output', 'reports_dir']), exist_ok=True)

    def _load_config(self, config_path: str) -> None:
        """Load configuration from YAML file.
        
        Args:
            config_path: Path to config YAML file
        """
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    self._update_nested_dict(self.config, user_config)
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
            logger.info("Using default configuration")

    def _update_nested_dict(self, d: Dict, u: Dict) -> None:
        """Recursively update nested dictionary.
        
        Args:
            d: Target dictionary
            u: Source dictionary
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d:
                self._update_nested_dict(d[k], v)
            else:
                d[k] = v

    def get(self, path: list, default: Any = None) -> Any:
        """Get configuration value using path list.
        
        Args:
            path: List of keys forming path to value
            default: Default value if path not found
            
        Returns:
            Configuration value or default
        """
        value = self.config
        try:
            for key in path:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def save(self, config_path: str) -> None:
        """Save current configuration to YAML file.
        
        Args:
            config_path: Path to save config YAML
        """
        try:
            with open(config_path, 'w') as f:
                yaml.safe_dump(self.config, f, default_flow_style=False)
        except Exception as e:
            logger.error(f"Error saving config to {config_path}: {e}")

# Global config instance
config = Config()
