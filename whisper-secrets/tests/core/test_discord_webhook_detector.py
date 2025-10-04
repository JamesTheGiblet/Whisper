# whisper/tests/core/detectors/test_discord_webhook_detector.py
import pytest

from whisper.core.detectors.discord_webhook_detector import DiscordWebhookDetector

def test_discord_webhook_detector_finds_webhook():
    """
    Verify the detector finds a standard Discord webhook URL.
    """
    content = 'const webhook_url = "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz";'
    detector = DiscordWebhookDetector()

    findings = list(detector.detect(content))

    assert len(findings) == 1
    finding = findings[0]
    assert finding[0] == "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz"
    assert finding[2] == "DiscordWebhookDetector"
    assert finding[3] == "Discord Webhook URL"


def test_discord_webhook_detector_ignores_invalid_webhook():
    """
    Verify the detector ignores an invalid Discord webhook URL.
    """
    content = 'const invalid_url = "https://example.com/api/webhooks/123/abc";'
    detector = DiscordWebhookDetector()

    findings = list(detector.detect(content))

    assert len(findings) == 0
