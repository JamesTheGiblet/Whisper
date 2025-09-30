import pytest
from unittest.mock import patch
import yaml

from whisper.config.settings import load_config, DEFAULT_CONFIG


@patch('whisper.config.settings.find_config_file')
def test_load_config_with_no_user_file(mock_find_config):
    """Test that default configuration loads correctly when no user file is found."""
    mock_find_config.return_value = None
    config = load_config()
    assert config == DEFAULT_CONFIG


@patch('whisper.config.settings.find_config_file')
def test_load_config_with_user_overrides(mock_find_config, tmp_path):
    """Test that user configuration correctly overrides default settings."""
    # Arrange: Create a custom config file
    user_config_content = {
        "ai": {"model": "custom-model:latest"},
        "rules": {"excluded_paths": ["/test/only/this/path"]},
    }
    config_file = tmp_path / "whisper.config.yaml"
    config_file.write_text(yaml.dump(user_config_content))
    mock_find_config.return_value = config_file

    # Act: Load the configuration
    config = load_config()

    # Assert: Check that the overrides were applied
    assert config["ai"]["model"] == "custom-model:latest"
    assert config["rules"]["excluded_paths"] == ["/test/only/this/path"]
    # Assert that a default value not in the user config is still present
    assert "max_file_size" in config["rules"]