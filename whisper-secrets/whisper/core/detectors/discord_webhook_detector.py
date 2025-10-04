# whisper/core/detectors/discord_webhook_detector.py
import re

class DiscordWebhookDetector:
    """
    Detects Discord webhook URLs in the provided content.
    """

    def __init__(self):
        # Define a regex pattern for Discord webhook URLs
        self.pattern = re.compile(
            r"https://(canary\.)?discord\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+",
            re.IGNORECASE,
        )

    def detect(self, content, file_path=None):
        """
        Detects Discord webhook URLs in the given content.

        Args:
            content (str): The content to scan.
            file_path (str, optional): The path to the file being scanned. Defaults to None.

        Yields:
            tuple: A tuple containing the matched secret, its type, and the detector's name.
        """
        for match in self.pattern.finditer(content):
            secret = match.group(0)
            yield (secret, 0.8, "discord_webhook", "DiscordWebhookDetector", "Discord Webhook URL")
