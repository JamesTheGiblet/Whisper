import math
import re
from collections import Counter
from typing import Iterator, Tuple


class EntropyDetector:
    """
    A detector that finds high-entropy strings, which are often indicative of secrets.
    """

    def __init__(self, threshold: float = 4.5, min_length: int = 20):
        """
        Initializes the detector.

        Args:
            threshold (float): The Shannon entropy threshold to consider a string a secret.
            min_length (int): The minimum length of a string to check for entropy.
        """
        self.threshold = threshold
        # This regex finds long words/strings containing characters common in keys.
        # It looks for strings that are at least `min_length` long.
        self.word_regex = re.compile(r"['\"]?([a-zA-Z0-9-_.+/=]{%d,})['\"]?" % min_length)

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not data:
            return 0.0

        char_counts = Counter(data)
        data_len = float(len(data))

        return -sum(count / data_len * math.log2(count / data_len) for count in char_counts.values())

    def detect(self, content: str) -> Iterator[Tuple[str, int, str, str]]:
        """
        Scans the given content for high-entropy strings.

        Yields:
            A tuple containing (candidate_value, line_number, line_content, detector_name).
        """
        for line_num, line in enumerate(content.splitlines(), 1):
            for match in self.word_regex.finditer(line):
                # group(1) captures the string without potential surrounding quotes
                candidate = match.group(1)
                if candidate:
                    entropy = self._shannon_entropy(candidate)
                    if entropy >= self.threshold:
                        yield candidate, line_num, line.strip(), "Entropy"
