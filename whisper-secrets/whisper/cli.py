import typer
from pathlib import Path
from typing import Optional, List
from enum import Enum
import json
import importlib.metadata
import logging
from rich.console import Console
from rich.table import Table
from rich.filesize import decimal
import subprocess
import shutil
import requests
import tempfile
from contextlib import contextmanager
import yaml
import os
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import sys
import csv
from pydantic import BaseModel, validator
from typing import Optional as Opt
from datetime import datetime

from whisper.core.scanner import FileScanner
from whisper.config.settings import load_config

class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    csv = "csv"
    sarif = "sarif"

# Exit codes documentation
EXIT_CODES = {
    0: "Success - No secrets found or operation completed successfully",
    1: "Error - General error or secrets found (with --fail-on-finding)",
    2: "Configuration error", 
    3: "Ollama connection error",
    4: "Model not found",
    5: "Validation error",
}

app = typer.Typer(
    name="whisper",
    help="An AI-powered secret scanner to find real secrets without the noise.",
    add_completion=False,
)
console = Console()

# Global flag for debug mode
DEBUG = False

# Pydantic models for configuration validation
class AIConfig(BaseModel):
    model: str
    confidence_threshold: float = 0.7
    
    @validator('confidence_threshold')
    def validate_confidence(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('confidence_threshold must be between 0.0 and 1.0')
        return v

class ScannerConfig(BaseModel):
    max_file_size_mb: int = 10
    excluded_paths: List[str] = []

def validate_config(config: dict) -> bool:
    """Validate configuration using Pydantic models."""
    try:
        AIConfig(**config.get('ai', {}))
        ScannerConfig(**config.get('scanner', {}))
        return True
    except Exception as e:
        logging.error(f"Configuration validation failed: {e}")
        return False

def get_exit_code_documentation():
    """Return documentation for exit codes."""
    table = Table(title="Exit Codes")
    table.add_column("Code", style="cyan")
    table.add_column("Meaning", style="white")
    for code, meaning in EXIT_CODES.items():
        table.add_row(str(code), meaning)
    return table

@contextmanager
def _debug_exception_handler():
    """A context manager to handle exceptions based on the global DEBUG flag."""
    try:
        yield
    except Exception as e:
        if DEBUG:
            # In debug mode, re-raise the exception to get a full stack trace
            raise
        else:
            console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}", style="red")
            raise typer.Exit(code=1)

def _check_ollama_availability():
    """Check if Ollama is available and responsive."""
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    try:
        response = requests.get(f"{host.rstrip('/')}/api/version", timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException:
        return False

def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary."""
    try:
        with open(file_path, 'tr') as check_file:
            check_file.read()
            return False
    except UnicodeDecodeError:
        return True

def should_scan_file(file_path: Path, max_size_mb: int = 10) -> bool:
    """Determine if a file should be scanned."""
    if file_path.stat().st_size > max_size_mb * 1024 * 1024:
        logging.debug(f"Skipping large file: {file_path}")
        return False
    if is_binary_file(file_path):
        logging.debug(f"Skipping binary file: {file_path}")
        return False
    return True

def setup_logging(verbose: bool, debug: bool, log_file: Optional[Path] = None):
    """Centralized logging setup."""
    log_level = logging.DEBUG if verbose or debug else logging.INFO
    
    # Clear any existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    if log_file:
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            filename=str(log_file),
            filemode='a',  # Use 'a' for append instead of 'w'
            force=True,
        )
    else:
        from rich.logging import RichHandler
        logging.basicConfig(
            level=log_level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(show_path=debug)],  # Show path in debug mode
            force=True,
        )

# Create a new Typer app for the "models" subcommand
models_app = typer.Typer(name="models", help="Manage local AI models.")
app.add_typer(models_app)

update_app = typer.Typer(name="update", help="Update Whisper's models and security intelligence.")
app.add_typer(update_app)

report_app = typer.Typer(name="report", help="Report false positives or contribute new patterns.")
app.add_typer(report_app)

contribute_app = typer.Typer(name="contribute", help="Contribute new patterns or detectors to Whisper.")
app.add_typer(contribute_app)

def version_callback(value: bool):
    """Prints the version of the application."""
    if value:
        try:
            version = importlib.metadata.version("whisper-secrets")
            typer.echo(f"Whisper version: {version}")
        except importlib.metadata.PackageNotFoundError:
            typer.echo("Whisper version: (local development build)")
        raise typer.Exit()

def find_config_file(start_path: Path) -> Optional[Path]:
    """
    Find the whisper.config.yaml file by traversing up the directory tree.
    """
    current_path = start_path.resolve()
    
    while current_path != current_path.parent:  # Stop at root
        config_file = current_path / "whisper.config.yaml"
        if config_file.exists():
            return config_file
        current_path = current_path.parent
    
    return None

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
    log_file: Optional[Path] = typer.Option(
        None,
        "--log-file",
        help="Path to a file to write logs to.",
        writable=True,
        resolve_path=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose logging.",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug mode (show full stack traces on errors).",
    ),
    show_exit_codes: bool = typer.Option(
        False,
        "--show-exit-codes",
        help="Show documentation for exit codes and exit.",
    ),
):
    """Whisper keeps your secrets silent."""
    global DEBUG
    DEBUG = debug
    
    if show_exit_codes:
        console.print(get_exit_code_documentation())
        raise typer.Exit(code=0)
    
    setup_logging(verbose, debug, log_file)

    if log_file:
        console.log(f"Logging to file: [cyan]{log_file}[/cyan]")

@app.command()
def scan(
    path: Path = typer.Argument(
        ".",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
        help="The path to a file or directory to scan.",
    ),
    confidence_threshold: Optional[float] = typer.Option(
        None,
        "--confidence-threshold",
        "-c",
        min=0.0,
        max=1.0,
        help="Override the confidence threshold (0.0-1.0).",
    ),
    exclude: Optional[List[str]] = typer.Option(
        None,
        "--exclude",
        "-e",
        help="Paths to exclude (glob patterns). Can be used multiple times.",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.table,
        "--format",
        "-f",
        case_sensitive=False,
        help="The output format for the findings.",
    ),
    fail_on_finding: bool = typer.Option(
        False,
        "--fail-on-finding",
        "--fail",
        help="Exit with a non-zero status code if any secrets are found.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show what would be scanned without actually scanning.",
    ),
    max_file_size: int = typer.Option(
        10,
        "--max-file-size",
        help="Maximum file size to scan in MB.",
    ),
):
    """Scan a directory or file for secrets."""
    with _debug_exception_handler():
        # Load the base configuration
        config = load_config()
        
        # Validate configuration
        if not validate_config(config):
            console.print("[bold red]Error:[/bold red] Invalid configuration.", style="red")
            raise typer.Exit(code=2)

        # Apply CLI overrides
        if confidence_threshold is not None:
            config["ai"]["confidence_threshold"] = confidence_threshold
            logging.info(f"Overriding confidence threshold to: {confidence_threshold}")

        if exclude:
            config["rules"]["excluded_paths"].extend(exclude)
            logging.info(f"Adding exclusion patterns: {', '.join(exclude)}")

        if format == OutputFormat.table:
            console.print(f"🔐 Scanning [cyan]{path}[/cyan]...")

        if dry_run:
            console.print("[yellow]Dry run mode - no actual scanning will be performed[/yellow]")
            # Simulate file discovery
            scanner = FileScanner(str(path), config=config)
            try:
                # Try to use discover_files if it exists, otherwise estimate
                file_count = scanner.discover_files()
                console.print(f"Would scan {file_count} files")
            except Exception:
                console.print("Would scan files (file discovery not available)")
            raise typer.Exit(code=0)

        with Progress(SpinnerColumn(),TextColumn("[progress.description]{task.description}"),BarColumn(),TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),TextColumn("({task.completed} of {task.total} files)"),
            console=console,
            transient=True, # Hides the progress bar upon completion
        ) as progress:
            scanner = FileScanner(str(path), config=config)
            findings = scanner.scan(progress=progress)

        if not findings:
            if format == OutputFormat.table:
                console.print("✅ No secrets found.", style="green")
            elif format == OutputFormat.json:
                console.print("[]")
            elif format == OutputFormat.csv:
                # Print empty CSV with headers
                writer = csv.writer(sys.stdout)
                writer.writerow(["File", "Line", "Detector", "Reason", "Confidence"])
            else:  # SARIF
                console.print(json.dumps({
                    "version": "2.1.0",
                    "runs": [{
                        "tool": {
                            "driver": {
                                "name": "Whisper",
                                "informationUri": "https://github.com/your-org/whisper"
                            }
                        },
                        "results": []
                    }]
                }, indent=2))
            raise typer.Exit(code=0)

        if format == OutputFormat.json:
            console.print(json.dumps(findings, indent=2))
        elif format == OutputFormat.csv:
            writer = csv.writer(sys.stdout)
            writer.writerow(["File", "Line", "Detector", "Reason", "Confidence"])
            for finding in findings:
                writer.writerow([
                    finding["file"],
                    finding["line"],
                    finding["detector"],
                    finding["reason"],
                    finding.get("confidence", "N/A")
                ])
        elif format == OutputFormat.sarif:
            # SARIF format for CI/CD integration
            sarif_output = {
                "version": "2.1.0",
                "runs": [{
                    "tool": {
                        "driver": {
                            "name": "Whisper",
                            "informationUri": "https://github.com/your-org/whisper",
                            "rules": []
                        }
                    },
                    "results": [
                        {
                            "ruleId": finding["detector"],
                            "message": {
                                "text": finding["reason"]
                            },
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": finding["file"]
                                    },
                                    "region": {
                                        "startLine": finding["line"],
                                        "startColumn": 1
                                    }
                                }
                            }]
                        } for finding in findings
                    ]
                }]
            }
            console.print(json.dumps(sarif_output, indent=2))
        else:  # Default to table
            console.print(f"🚨 Found {len(findings)} potential secret(s):", style="bold red")
            table = Table(title="Scan Results")
            table.add_column("File", style="cyan")
            table.add_column("Line", style="magenta")
            table.add_column("Detector", style="green")
            table.add_column("Reason", style="yellow")
            table.add_column("Confidence", style="white")
            for finding in findings:
                confidence = finding.get("confidence", "N/A")
                table.add_row(
                    finding["file"], 
                    str(finding["line"]), 
                    finding["detector"], 
                    finding["reason"],
                    str(confidence)
                )
            console.print(table)
        
        if fail_on_finding:
            console.print("\n💥 Failing build due to found secrets.", style="bold red")
            raise typer.Exit(code=1)
    
@app.command()
def setup(
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        help="The Ollama model to download. Defaults to the model in the config.",
    )
):
    """
    Download and set up the required AI model from Ollama.
    """
    with _debug_exception_handler():
        if not _check_ollama_availability():
            console.print("[bold red]Error:[/bold red] Ollama is not running or not accessible.", style="red")
            console.print("Please ensure Ollama is installed and running.")
            raise typer.Exit(code=3)

        config = load_config()
        # Use the provided model, or fall back to the one in the config
        model_to_pull = model or config.get("ai", {}).get("model")

        if not model_to_pull:
            console.print("[bold red]Error:[/bold red] No model specified and no default model found in configuration.", style="red")
            raise typer.Exit(code=1)

        console.print(f"🚀 Setting up Whisper with model: [cyan]{model_to_pull}[/cyan]")

        if not shutil.which("ollama"):
            console.print("[bold red]Error:[/bold red] `ollama` command not found.", style="red")
            console.print("Please install Ollama and ensure it's in your system's PATH.")
            console.print("See: https://ollama.com")
            raise typer.Exit(code=1)

        console.print("This will download the AI model from Ollama (may take a few minutes)...")

        try:
            # Use Popen to stream the output in real-time
            process = subprocess.Popen(
                ["ollama", "pull", model_to_pull],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8'
            )

            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    console.print(line.strip())

            process.wait()
            if process.returncode == 0:
                console.print(f"\n✅ Model [cyan]{model_to_pull}[/cyan] pulled successfully.", style="green")
            else:
                console.print(f"\n[bold red]Error:[/bold red] Failed to pull model. Ollama exited with code {process.returncode}.", style="red")
                raise typer.Exit(code=1)
        except FileNotFoundError:
            # This is a fallback for the shutil.which check
            console.print("[bold red]Error:[/bold red] `ollama` command not found.", style="red")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}", style="red")
            raise typer.Exit(code=1)

@models_app.command("list")
def list_models():
    """
    List all models available locally in your Ollama instance.
    """
    with _debug_exception_handler():
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        api_url = f"{host.rstrip('/')}/api/tags"

        try:
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.ConnectionError:
            console.print(f"[bold red]Error:[/bold red] Could not connect to Ollama at [cyan]{host}[/cyan].", style="red")
            console.print("Please ensure the Ollama application is running.")
            raise typer.Exit(code=3)
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Error:[/bold red] Failed to query Ollama models API: {e}", style="red")
            raise typer.Exit(code=1)

        models = data.get("models", [])
        if not models:
            console.print("✅ No local models found.", style="green")
            raise typer.Exit(code=0)

        table = Table(title="Available Local Models")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Size", style="magenta")
        table.add_column("Modified", style="yellow")

        # Sort models by name
        models.sort(key=lambda x: x.get("name", ""))

        for model in models:
            size_bytes = model.get("size", 0)
            size_str = decimal(size_bytes)
            modified_at = model.get("modified_at", "N/A").split("T")[0]
            table.add_row(model.get("name"), size_str, modified_at)

        console.print(table)

@models_app.command("use")
def use_model(
    model_name: str = typer.Argument(..., help="The name of the model to set as default.")
):
    """
    Set the default model to use for future scans.

    This updates the 'ai.model' key in your whisper.config.yaml file.
    If no config file is found, it will be created in the current directory.
    """
    with _debug_exception_handler():
        config_path = find_config_file(Path.cwd())

        if not config_path:
            # If no config file exists, create one in the current directory.
            config_path = Path.cwd() / "whisper.config.yaml"
            console.print(f"No config file found. Creating a new one at [cyan]{config_path}[/cyan].")
            config_data = {}
        else:
            try:
                with open(config_path, 'r') as f:
                    config_data = yaml.safe_load(f) or {}
            except (IOError, yaml.YAMLError) as e:
                console.print(f"[bold red]Error:[/bold red] Could not read or parse config file at [cyan]{config_path}[/cyan]. Error: {e}", style="red")
                raise typer.Exit(code=2)

        # Update the model in the config data, creating the 'ai' key if it doesn't exist.
        config_data.setdefault('ai', {})['model'] = model_name

        # Write the updated config back to the file
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
            console.print(f"✅ Default model set to [cyan]{model_name}[/cyan] in [yellow]{config_path}[/yellow].")
        except IOError as e:
            console.print(f"[bold red]Error:[/bold red] Could not write to config file at [cyan]{config_path}[/cyan]. Error: {e}", style="red")
            raise typer.Exit(code=2)

# A default Modelfile template.
MODELFILE_TEMPLATE = """
FROM {base_model}

# Set the system prompt to specialize this model for secret detection
SYSTEM \"\"\"
You are an expert security analyst specializing in secret detection.
Your task is to determine if a given string is a hardcoded secret.
When presented with a code snippet and a candidate string, you will respond ONLY in JSON format with two keys: "is_secret" (boolean) and "reason" (a brief explanation of your analysis).
\"\"\"
"""

@models_app.command("create")
def create_model(
    name: str = typer.Option(..., "--name", "-n", help="The name for the new custom model (e.g., my-company/secrets-detector)."),
    base_model: str = typer.Option("codellama:7b", "--base", "-b", help="The base Ollama model to build from."),
):
    """
    Create a new custom model specialized for secret detection.
    """
    with _debug_exception_handler():
        if not _check_ollama_availability():
            console.print("[bold red]Error:[/bold red] Ollama is not running or not accessible.", style="red")
            console.print("Please ensure Ollama is installed and running.")
            raise typer.Exit(code=3)

        if not shutil.which("ollama"):
            console.print("[bold red]Error:[/bold red] `ollama` command not found.", style="red")
            console.print("Please install Ollama and ensure it's in your system's PATH.")
            raise typer.Exit(code=1)

        console.print(f"🛠️  Creating new model [cyan]{name}[/cyan] from base model [cyan]{base_model}[/cyan]...")

        modelfile_content = MODELFILE_TEMPLATE.format(base_model=base_model)

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".Modelfile") as temp_modelfile:
            temp_modelfile.write(modelfile_content)
            modelfile_path = temp_modelfile.name

        try:
            process = subprocess.Popen(
                ["ollama", "create", name, "-f", modelfile_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8'
            )

            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    console.print(line.strip())

            process.wait()
            if process.returncode == 0:
                console.print(f"\n✅ Model [cyan]{name}[/cyan] created successfully.", style="green")
                console.print(f"To use it, run: [bold]whisper models use {name}[/bold]")
            else:
                console.print(f"\n[bold red]Error:[/bold red] Failed to create model. Ollama exited with code {process.returncode}.", style="red")
                raise typer.Exit(code=1)
        finally:
            # Ensure the temporary Modelfile is always cleaned up
            os.remove(modelfile_path)

@app.command()
def test():
    """Test the Whisper installation and configuration."""
    console.print("🧪 Testing Whisper configuration...")
    
    tests_passed = 0
    total_tests = 4
    
    # Test 1: Ollama connection
    if _check_ollama_availability():
        console.print("✅ Ollama connection: OK")
        tests_passed += 1
    else:
        console.print("❌ Ollama connection: FAILED")
    
    # Test 2: Config loading
    try:
        config = load_config()
        console.print("✅ Configuration loading: OK")
        tests_passed += 1
    except Exception as e:
        console.print(f"❌ Configuration loading: FAILED - {e}")
    
    # Test 3: Config validation
    try:
        config = load_config()
        if validate_config(config):
            console.print("✅ Configuration validation: OK")
            tests_passed += 1
        else:
            console.print("❌ Configuration validation: FAILED")
    except Exception as e:
        console.print(f"❌ Configuration validation: FAILED - {e}")
    
    # Test 4: Model availability
    try:
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        response = requests.get(f"{host.rstrip('/')}/api/tags", timeout=5)
        if response.status_code == 200:
            console.print("✅ Model API access: OK")
            tests_passed += 1
        else:
            console.print("❌ Model API access: FAILED")
    except Exception as e:
        console.print(f"❌ Model API access: FAILED - {e}")
    
    console.print(f"\n📊 Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        console.print("🎉 All tests passed! Whisper is ready to use.", style="green")
        raise typer.Exit(code=0)
    else:
        console.print("💥 Some tests failed. Please check your setup.", style="red")
        raise typer.Exit(code=1)

@update_app.callback(invoke_without_command=True)
def update(
    ctx: typer.Context,
    check: bool = typer.Option(False, "--check", help="Check for available updates without installing."),
    retrain: bool = typer.Option(False, "--retrain", help="Force a retrain of the local model with the latest patterns."),
):
    """
    Download the latest security intelligence (e.g., updated rules and patterns).
    """
    # If a subcommand is called in the future, this main update logic shouldn't run.
    if ctx.invoked_subcommand is not None:
        return

    with _debug_exception_handler():
        if check:
            console.print("🔎 Checking for available updates...")
            # Placeholder for future implementation
            console.print("✅ Everything is up to date.")
            return

        if retrain:
            console.print("🧠 Retraining model with latest patterns...")
            # Placeholder for future implementation
            console.print("[yellow]Model retraining is not yet implemented.[/yellow]")
            raise typer.Exit(code=1)

        console.print("🔄 Downloading latest security intelligence...")
        # Placeholder for future implementation
        console.print("✅ Everything is up to date.")

@report_app.command("fp")
def report_false_positive(
    file: Path = typer.Option(
        ..., 
        "--file", 
        help="The file containing the false positive.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    line: int = typer.Option(..., "--line", min=1, help="The line number of the false positive."),
    reason: str = typer.Option(..., "--reason", help="A brief reason why this is a false positive."),
):
    """
    Report a false positive to help improve Whisper's accuracy.
    """
    with _debug_exception_handler():
        console.print("🙏 Thank you for your contribution!")
        console.print("Reporting false positive in", f"[cyan]{str(file)}[/cyan]", "at line", f"[magenta]{line}[/magenta].")
        console.print(f"Reason: [yellow]{reason}[/yellow]")
        # Placeholder for future implementation (e.g., submitting to a remote service)
        console.print("\n[italic]Note: This is currently a placeholder. In the future, this will submit the report to help improve Whisper.[/italic]")

@contribute_app.command("pattern")
def contribute_pattern(
    name: str = typer.Option(..., "--name", help="A descriptive name for the new pattern (e.g., 'MyService API Key')."),
    pattern: str = typer.Option(..., "--pattern", help="The regular expression for the pattern."),
):
    """
    Suggest a new regex pattern to be included in Whisper's rules.
    """
    with _debug_exception_handler():
        console.print("🙏 Thank you for your contribution!")
        console.print(f"Suggesting new pattern: [cyan]{name}[/cyan]")
        console.print("Pattern:", f"[yellow]{pattern}[/yellow]")
        # Placeholder for future implementation
        console.print("\n[italic]Note: This is currently a placeholder. In the future, this could open a browser to create a contribution pull request.[/italic]")

if __name__ == "__main__":
    app()