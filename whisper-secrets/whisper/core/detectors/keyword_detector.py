import re
from typing import Iterator, Tuple, List


class KeywordDetector:
    """
    A detector that finds specific hardcoded keywords from a predefined list.
    """

    def __init__(self, keywords: List[str]):
        """
        Initializes the detector with a list of keywords.

        Args:
            keywords (List[str]): A list of strings to search for.
        """
        # For efficiency, we compile a single regex that looks for any of the keywords
        # as whole words (using word boundaries \b) and is case-insensitive.
        # re.escape handles any special characters in the keywords.
        if keywords:
            pattern_str = r'(' + '|'.join(re.escape(k) for k in keywords) + r')'
            self.pattern = re.compile(pattern_str, re.IGNORECASE)
        else:
            self.pattern = None

    def detect(self, content: str) -> Iterator[Tuple[str, int, str, str]]:
        """
        Scans the given content for the configured keywords.

        Yields:
            A tuple containing (candidate_value, line_number, line_content, detector_name).
        """
        if not self.pattern:
            return

        for line_num, line in enumerate(content.splitlines(), 1):
            for match in self.pattern.finditer(line):
                yield match.group(0), line_num, line.strip(), "Keyword"
