import re
import base64
import math
from collections import Counter
from typing import Iterator, Tuple


class Base64Detector:
    """
    A detector that finds high-entropy Base64 encoded strings.
    """

    def __init__(self, min_length: int = 32, entropy_threshold: float = 4.5):
        """
        Initializes the detector.

        Args:
            min_length (int): The minimum length of a Base64 string to consider.
            entropy_threshold (float): The Shannon entropy threshold for the decoded string.
        """
        self.min_length = min_length
        self.entropy_threshold = entropy_threshold
        # Regex to find potential Base64 strings inside quotes.
        self.b64_regex = re.compile(r"['\"]([A-Za-z0-9+/=]{%d,})['\"]" % self.min_length)

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculates the Shannon entropy of a byte string."""
        if not data:
            return 0.0
        byte_counts = Counter(data)
        data_len = float(len(data))
        return -sum(count / data_len * math.log2(count / data_len) for count in byte_counts.values())

    def detect(self, content: str) -> Iterator[Tuple[str, int, str, str]]:
        """
        Scans the given content for high-entropy Base64 strings.

        Yields:
            A tuple containing (candidate_value, line_number, line_content, detector_name).
        """
        for line_num, line in enumerate(content.splitlines(), 1):
            for match in self.b64_regex.finditer(line):
                candidate = match.group(1)
                # A valid Base64 string's length must be a multiple of 4.
                if len(candidate) % 4 != 0:
                    continue

                try:
                    decoded_data = base64.b64decode(candidate)
                    entropy = self._shannon_entropy(decoded_data)
                    if entropy >= self.entropy_threshold:
                        yield candidate, line_num, line.strip(), "Base64"
                except (base64.binascii.Error, ValueError):
                    # Not a valid Base64 string, ignore it.
                    continue