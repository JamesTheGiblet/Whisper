import re
import logging
from typing import Iterator, Tuple, List

log = logging.getLogger(__name__)

class RegexDetector:
    """
    A detector that uses a set of regex patterns to find potential secrets.
    """

    def __init__(self, rules: List[str]):
        """
        Initializes the detector with a list of regex patterns.

        Args:
            rules (List[str]): A list of strings, where each string is a regex pattern.
        """
        self.patterns = []
        for pattern_str in rules:
            try:
                self.patterns.append(re.compile(pattern_str))
            except re.error as e:
                log.warning("Skipping invalid regex pattern: '%s'. Error: %s", pattern_str, e)

    def detect(self, content: str) -> Iterator[Tuple[str, int, str, str]]:
        """
        Scans the given content for secrets matching the configured patterns.

        Args:
            content (str): The content of the file to scan.

        Yields:
            A tuple containing (candidate_value, line_number, line_content, detector_name).
        """
        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern in self.patterns:
                for match in pattern.finditer(line):
                    candidate = match.groups()[-1] if match.groups() else match.group(0)
                    if candidate:
                        yield candidate, line_num, line.strip(), "Regex"
