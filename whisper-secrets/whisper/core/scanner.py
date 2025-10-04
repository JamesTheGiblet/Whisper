from pathlib import Path
from typing import List, Dict, Any, Iterator, Tuple, Optional
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.metadata
 
from whisper.ai.classifier import SecretClassifier
from whisper.config.settings import load_config

def _load_detector_registry() -> Dict[str, Any]:
    """
    Dynamically discovers and loads all registered detector plugins.
    """
    registry = {}
    for entry_point in importlib.metadata.entry_points(group="whisper.detectors"):
        registry[entry_point.name] = entry_point.load()
    return registry

def _parse_size(size_str: str) -> int:
    """Parses a size string (e.g., '5MB', '100KB') into bytes."""
    size_str = size_str.upper().strip()
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
    try:
        if size_str[-2:] in units:
            num = int(size_str[:-2])
            unit = size_str[-2:]
            return num * units[unit]
        elif size_str[-1] in units:
            num = int(size_str[:-1])
            unit = size_str[-1]
            return num * units[unit]
    except (ValueError, KeyError):
        pass
    return 0 # Default to 0 if parsing fails

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
 
        # Dynamically initialize detectors discovered via entry points
        self.detectors = []
        detector_registry = _load_detector_registry()
        rules_config = self.config.get("rules", {})
        detectors_config = rules_config.get("detectors", {})
 
        for name, config_block in detectors_config.items():
            if config_block.get("enabled") and name in detector_registry:
                DetectorClass = detector_registry[name]
                # Prepare arguments for the detector's constructor by removing 'enabled'
                kwargs = {k: v for k, v in config_block.items() if k != "enabled"}
                self.detectors.append(DetectorClass(**kwargs))
 
        self.excluded_paths = rules_config.get("excluded_paths", [])
        self.max_file_size = _parse_size(rules_config.get("max_file_size", "0"))

    def _is_excluded(self, path: Path) -> bool:
        """Checks if a file or directory should be excluded from the scan."""
        for pattern in self.excluded_paths:
            if path.match(pattern):
                return True
        
        if self.max_file_size > 0 and path.is_file() and path.stat().st_size > self.max_file_size:
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
            
    def _process_file(self, file_path: Path) -> List[Dict[str, Any]]:    
        """
        Processes a single file: finds candidates and classifies them.
        This method is designed to be run in a separate thread.
        """
        file_findings = []
        confidence_threshold = self.config.get("ai", {}).get("confidence_threshold", 0.8)

        for candidate, confidence, detector_name, detector_type, reason in self._find_candidates_in_file(file_path):
           # Ensure the detector provides a confidence score
            if confidence >= confidence_threshold:
                context_line = reason #context line
                line_num = 1
                if reason:
                    context_line = reason
                else:
                    context_line = ""

                ai_result = self.classifier.classify(candidate=candidate, context=context_line)

                file_findings.append({
                    "file": str(file_path.resolve()),
                    "line": line_num,
                    "secret_value": candidate,
                    "reason": ai_result.get("reason", "No reason provided."),
                    "detector": detector_name,
                })
        return file_findings


    def scan(self, progress: Optional[Progress] = None) -> List[Dict[str, Any]]:
        """
        Executes the full scan process.

        1. Finds all relevant files.
        2. Finds potential secret candidates in each file.
        3. Uses the AI classifier to validate each candidate.
        4. Collects and returns confirmed secrets.

        Args:
            progress (Optional[Progress]): A rich Progress object to update during the scan.
        """
        findings = []
        files_to_scan = list(self._find_files_to_scan())

        task_id = None
        if progress:
            task_id = progress.add_task("Scanning files...", total=len(files_to_scan))

        # Use a ThreadPoolExecutor to process files in parallel.
        # This is effective because the work is I/O-bound (file reads and network requests).
        with ThreadPoolExecutor() as executor:
            # Submit each file to be processed in a separate thread
            future_to_file = {executor.submit(self._process_file, file_path): file_path for file_path in files_to_scan}
            
            for future in as_completed(future_to_file):
                if progress and task_id is not None:
                    progress.update(task_id, advance=1)
                try:
                    findings.extend(future.result())
                except Exception as e:
                    # Optionally log errors for specific files
                    pass

        return findings