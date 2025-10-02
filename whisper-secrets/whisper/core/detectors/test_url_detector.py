import pytest

from whisper.core.detectors.url_detector import UrlDetector


def test_url_detector_finds_url_with_credentials():
    """
    Verify the detector finds a standard URL with embedded credentials using default protocols.
    """
    content = 'const db_url = "postgres://user:password123@host.com:5432/db";'
    detector = UrlDetector()  # Uses the new, comprehensive default protocol list
    
    findings = list(detector.detect(content))
    
    assert len(findings) == 1
    finding = findings[0]
    assert finding[0] == "postgres://user:password123@host.com:5432/db"
    assert finding[2] == "UrlDetector"
    assert finding[3] == "URL with Credentials"


def test_url_detector_ignores_url_without_credentials():
    """
    Verify the detector ignores a standard URL that does not contain credentials.
    """
    content = 'const api_endpoint = "https://api.example.com/v1/users";'
    detector = UrlDetector()
    
    findings = list(detector.detect(content))
    
    assert len(findings) == 0


def test_url_detector_respects_custom_protocols():
    """
    Verify the detector only finds URLs with protocols specified in the constructor.
    """
    content = """
    const mysql_conn = "mysql://user:pass@db.internal";
    const redis_conn = "redis://:auth@cache.internal";
    """
    # Initialize the detector to ONLY look for mysql
    detector = UrlDetector(protocols=["mysql"])
    
    findings = list(detector.detect(content))
    
    # It should only find the mysql URL and ignore the redis one.
    assert len(findings) == 1
    assert findings[0][0] == "mysql://user:pass@db.internal"
