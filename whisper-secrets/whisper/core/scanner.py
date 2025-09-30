from pathlib import Path
from typing import List, Dict, Any, Iterator, Tuple, Optional
 
from whisper.ai.classifier import SecretClassifier
from whisper.config.settings import load_config
from whisper.core.detectors.entropy_detector import EntropyDetector
from whisper.core.detectors.keyword_detector import KeywordDetector
from whisper.core.detectors.regex_detector import RegexDetector

class FileScanner:
    """
    Orchestrates the scanning of a given path for secrets.
    """

    def __init__(self, root_path: str, config: Optional[Dict[str, Any]] = None):
        """
        Initializes the scanner.

        Args:
            root_path (str): The root directory or file path to scan.
            config (Optional[Dict[str, Any]]): A configuration dictionary. If not
                                                provided, it will be loaded automatically.
        """
        self.root_path = Path(root_path)
        self.config = config if config is not None else load_config()
        
        # Pass the config to the classifier to ensure it uses the same settings
        self.classifier = SecretClassifier(config=self.config)
 
        # Dynamically initialize detectors based on the configuration
        self.detectors = []
        rules_config = self.config.get("rules", {})
        detectors_config = rules_config.get("detectors", {})
 
        regex_config = detectors_config.get("regex", {})
        if regex_config.get("enabled"):
            self.detectors.append(RegexDetector(rules=regex_config.get("rules", [])))
 
        entropy_config = detectors_config.get("entropy", {})
        if entropy_config.get("enabled"):
            self.detectors.append(
                EntropyDetector(
                    threshold=entropy_config.get("threshold", 4.5),
                    min_length=entropy_config.get("min_length", 20),
                )
            )

        keyword_config = detectors_config.get("keyword", {})
        if keyword_config.get("enabled"):
            self.detectors.append(KeywordDetector(keywords=keyword_config.get("keywords", [])))
 
        self.excluded_paths = self.config.get("rules", {}).get("excluded_paths", [])

    def _is_excluded(self, path: Path) -> bool:
        """Checks if a file or directory should be excluded from the scan."""
        for pattern in self.excluded_paths:
            if path.match(pattern):
                return True
        return False

    def _find_files_to_scan(self) -> Iterator[Path]:
        """Yields all non-excluded files from the root path."""
        if self.root_path.is_file():
            if not self._is_excluded(self.root_path):
                yield self.root_path
            return

        for file_path in self.root_path.rglob("*"):
            if file_path.is_file() and not self._is_excluded(file_path):
                yield file_path

    def _find_candidates_in_file(self, file_path: Path) -> Iterator[Tuple[str, int, str, str]]:
        """
        Finds potential secrets (candidates) in a single file by running detectors.
        """
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
 
            for detector in self.detectors:
                yield from detector.detect(content)

        except (IOError, UnicodeDecodeError):
            # Silently ignore files that can't be opened or read
            pass

    def scan(self) -> List[Dict[str, Any]]:
        """
        Executes the full scan process.

        1. Finds all relevant files.
        2. Finds potential secret candidates in each file.
        3. Uses the AI classifier to validate each candidate.
        4. Collects and returns confirmed secrets.
        """
        findings = []
        confidence_threshold = self.config.get("ai", {}).get("confidence_threshold", 0.8)

        for file_path in self._find_files_to_scan():
            for candidate, line_num, context_line, detector_name in self._find_candidates_in_file(file_path):
                # The context for the AI is the line where the candidate was found
                ai_result = self.classifier.classify(candidate=candidate, context=context_line)

                if ai_result.get("is_secret"):
                    # In a real scenario, the AI would also return a confidence score.
                    # For now, we'll treat any "is_secret" as meeting the threshold.
                    findings.append({
                        "file": str(file_path),
                        "line": line_num,
                        "secret_value": candidate,
                        "reason": ai_result.get("reason", "No reason provided."),
                        "detector": detector_name,
                    })

        return findings