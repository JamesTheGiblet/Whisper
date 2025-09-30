import pytest
from unittest.mock import patch
from pathlib import Path

from whisper.core.scanner import FileScanner

# A sample config that enables all detectors with specific rules for testing.
MOCK_CONFIG = {
    "ai": {
        "primary": "ollama",
        "model": "mock-model",
    },
    "rules": {
        "excluded_paths": [],
        "detectors": {
            "regex": {
                "enabled": True,
                "rules": [
                    # A simple rule to find any key assignment
                    r"key\s*=\s*['\"](.+?)['\"]"
                ],
            },
            "entropy": {
                "enabled": True,
                "threshold": 4.0,  # Lowered for predictable testing
                "min_length": 20,
            },
            "keyword": {
                "enabled": True,
                "keywords": [
                    "BEGIN RSA PRIVATE KEY",
                ],
            },
        },
    },
}

# Test file content designed to trigger each detector once.
TEST_FILE_CONTENT = """
config.key = "a_simple_regex_key"

some_variable = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" # This string is a high-entropy literal

-----BEGIN RSA PRIVATE KEY-----
"""

@patch('whisper.core.scanner.SecretClassifier')
def test_scanner_uses_all_detectors(MockSecretClassifier, tmp_path: Path):
    """
    Verify that FileScanner initializes and uses all three detectors
    based on the provided configuration and reports their names correctly.
    """
    # Arrange:
    # 1. Mock the AI classifier to always return "is_secret: True"
    mock_classifier_instance = MockSecretClassifier.return_value
    mock_classifier_instance.classify.return_value = {
        "is_secret": True,
        "reason": "Mocked AI validation"
    }

    # 2. Create a temporary file with our test content
    test_file = tmp_path / "config.py"
    test_file.write_text(TEST_FILE_CONTENT)

    # Act:
    # 3. Initialize the scanner with the mock config and run it
    scanner = FileScanner(str(test_file), config=MOCK_CONFIG)
    findings = scanner.scan()

    # Assert:
    # 4. Check that we have exactly 3 findings
    assert len(findings) == 3

    # 5. Create a set of (detector_name, secret_value) for easy lookup
    reported_secrets = {(f['detector'], f['secret_value']) for f in findings}

    # 6. Verify that each expected secret was found by the correct detector
    assert ("Regex", "a_simple_regex_key") in reported_secrets
    assert ("Entropy", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4") in reported_secrets
    assert ("Keyword", "BEGIN RSA PRIVATE KEY") in reported_secrets