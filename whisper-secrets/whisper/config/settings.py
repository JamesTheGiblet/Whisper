import yaml
from pathlib import Path
from typing import Dict, Any, Optional

# Define the default configuration settings for the application.
# These values are used if they are not specified in the user's config file.
DEFAULT_CONFIG: Dict[str, Any] = {
    "ai": {
        "primary": "ollama",
        "model": "whisper/secrets-detector:latest",
        "confidence_threshold": 0.8,
        "fallback": {
            "enabled": False,
        },
    },
    "rules": {
        "excluded_paths": [
            "**/node_modules/**",
            "**/.git/**",
            "**/vendor/**",
            "**/__pycache__/**",
            "**/*.lock",
        ],
        "max_file_size": "5MB",
        "detectors": {
            "regex": {
                "enabled": True,
                "rules": [
                    r"""(['"]?_?(?:api|key|token|secret|password)_?['"]?\s*[:=]\s*['"](.+?)['"])"""
                ],
            },
            "entropy": {
                "enabled": True,
                "threshold": 4.5,
                "min_length": 20,
            },
            "keyword": {
                "enabled": True,
                "keywords": [
                    "password",
                    "BEGIN RSA PRIVATE KEY",
                ],
            },
            "base64": {
                "enabled": True,
                "min_length": 32,
                "entropy_threshold": 4.5,
            },
            "url": {
                "enabled": True,
                "protocols": ["http", "https", "ftp", "sftp", "mysql", "postgresql"],
            },
        },
    },
}

def deep_merge(source: Dict, destination: Dict) -> Dict:
    """
    Recursively merges source dict into destination dict.
    """
    for key, value in source.items():
        if isinstance(value, dict):
            node = destination.setdefault(key, {})
            deep_merge(value, node)
        else:
            destination[key] = value
    return destination

def find_config_file(start_path: Path) -> Optional[Path]:
    """
    Search for whisper.config.yaml upwards from the start_path.
    This allows running the tool from any subdirectory of a project.
    """
    current_path = start_path.resolve()
    while True:
        config_file = current_path / "whisper.config.yaml"
        if config_file.is_file():
            return config_file
        if current_path.parent == current_path:  # Reached the filesystem root
            return None
        current_path = current_path.parent


def load_config() -> Dict[str, Any]:
    """
    Loads configuration from whisper.config.yaml by searching up from the
    current directory, and merges it with the default configuration.
    """
    config = DEFAULT_CONFIG.copy() # Start with a copy of the defaults
    config_file_path = find_config_file(Path.cwd())

    if config_file_path:
        try:
            with open(config_file_path, "r") as f:
                user_config = yaml.safe_load(f)
            if user_config:
                config = deep_merge(user_config, config)
        except (IOError, yaml.YAMLError) as e:
            print(f"Warning: Could not load or parse {config_file_path}. Using default settings. Error: {e}")

    return config
