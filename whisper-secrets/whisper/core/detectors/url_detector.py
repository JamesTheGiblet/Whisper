import re
from typing import Iterator, Tuple, List


class UrlDetector:
    """
    Detector for URLs with embedded credentials.
    """

    def __init__(self, protocols: List[str] = None):
        """
        Initialize the URL detector.
        
        Args:
            protocols: List of protocols to detect (e.g., ['http', 'https', 'postgres', 'mysql']).
                     If None, uses a default set of common protocols.
        """
        self.protocols = protocols or [
            "http", "https", "ftp", "sftp", "ws", "wss",
            "postgres", "postgresql", "mysql", "redis", "mongodb"
        ]

    def detect(self, content: str) -> Iterator[Tuple[str, int, str, str]]:
        """
        Detect URLs with credentials in the content.
        
        Yields:
            Tuple of (matched_string, line_number, detector_name, reason)
        """
        # Build regex pattern for the specified protocols
        protocols_pattern = "|".join(re.escape(proto) for proto in self.protocols)
        
        # Improved URL regex that captures the full URL including ports, paths, and query parameters
        pattern = rf"""
            (?:{protocols_pattern})        # Protocol
            ://                           # Separator
            (?:[^:@/\s]+:[^:@/\s]+@)      # username:password@
            [^\s'"`,;]+                   # Rest of the URL (host, port, path, etc.)
        """
        
        regex = re.compile(pattern, re.VERBOSE | re.IGNORECASE)
        
        for line_num, line in enumerate(content.splitlines(), 1):
            for match in regex.finditer(line):
                url = match.group(0)
                yield (url, line_num, "UrlDetector", "URL with Credentials")