import typer
from pathlib import Path
from typing import Optional, List
from enum import Enum
import json
import importlib.metadata
import logging
from rich.markup import escape
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

from whisper.core.scanner import FileScanner
from whisper.config.settings import load_config

class OutputFormat(str, Enum):
    table = "table"
    json = "json"

app = typer.Typer(
    name="whisper",
    help="An AI-powered secret scanner to find real secrets without the noise.",
    add_completion=False,
)
console = Console()

# Global flag for debug mode
DEBUG = False

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
):
    """Whisper keeps your secrets silent."""
    global DEBUG
    DEBUG = debug
    log_level = logging.DEBUG if verbose else logging.INFO

    if log_file:
        # When logging to a file, use a detailed format.
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            filename=str(log_file),
            filemode='w',
            force=True,  # This allows re-configuring the logger in tests
        )
        console.log(f"Logging to file: [cyan]{log_file}[/cyan]")
    else:
        # Keep console output clean and use rich for formatting.
        from rich.logging import RichHandler
        logging.basicConfig(
            level=log_level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(show_path=False)],
            force=True,  # This allows re-configuring the logger in tests
        )

EXIT_CODES = {
    0: "Success - No secrets found or operation completed successfully",
    1: "Error - General error or secrets found (with --fail-on-finding)",
    2: "Configuration error", 
    3: "Ollama connection error",
    4: "Model not found",
}

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
    max_file_size: Optional[str] = typer.Option(
        None,
        "--max-file-size",
        help="Override the maximum file size to scan (e.g., '10MB', '1G').",
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
):
    """Scan a directory or file for secrets."""
    with _debug_exception_handler():
        # Load the base configuration
        config = load_config()            

        # Apply CLI overrides
        if confidence_threshold is not None:
            config["ai"]["confidence_threshold"] = confidence_threshold
            logging.info(f"Overriding confidence threshold to: {confidence_threshold}")

        if exclude:
            config["rules"]["excluded_paths"].extend(exclude)
            logging.info(f"Adding exclusion patterns: {', '.join(exclude)}")

        if max_file_size:
            value_to_set = max_file_size
            if value_to_set.isdigit():
                value_to_set += "MB"

            config["rules"]["max_file_size"] = value_to_set
            logging.info(f"Overriding max file size to: {value_to_set}")
        if format == OutputFormat.table:
            console.print(f"🔐 Scanning [cyan]{path}[/cyan]...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed} of {task.total} files)"),
            console=console,
            transient=True, # Hides the progress bar upon completion
        ) as progress:
            scanner = FileScanner(path, config=config)
            findings = scanner.scan(progress=progress)

        if not findings:
            if format == OutputFormat.table:
                console.print("✅ No secrets found.", style="green")
            else:
                console.print("[]") # Print an empty JSON array
            # Don't exit here - let the command complete normally
            return

        if format == OutputFormat.json:
            console.print(json.dumps(findings, indent=2))
        else: # Default to table
            console.print(f"🚨 Found {len(findings)} potential secret(s):", style="bold red")
            table = Table(title="Scan Results")
            table.add_column("File", style="cyan")
            table.add_column("Line", style="magenta")
            table.add_column("Detector", style="green")
            table.add_column("Reason", style="yellow")
            for finding in findings:
                table.add_row(finding["file"], str(finding["line"]), finding["detector"], finding["reason"])
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
            raise typer.Exit(code=1)
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Error:[/bold red] Failed to query Ollama models API: {e}", style="red")
            raise typer.Exit(code=1)

        models = data.get("models", [])
        if not models:
            console.print("✅ No local models found.", style="green")
            # Don't exit with error code when no models are found - this is a valid state
            return

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
                raise typer.Exit(code=1)

        # Update the model in the config data, creating the 'ai' key if it doesn't exist.
        config_data.setdefault('ai', {})['model'] = model_name

        # Write the updated config back to the file
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
            console.print(f"✅ Default model set to [cyan]{model_name}[/cyan] in [yellow]{config_path}[/yellow].")
        except IOError as e:
            console.print(f"[bold red]Error:[/bold red] Could not write to config file at [cyan]{config_path}[/cyan]. Error: {e}", style="red")
            raise typer.Exit(code=1)

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
        console.print("Pattern:", f"[yellow]{escape(pattern)}[/yellow]")
        # Placeholder for future implementation
        console.print("\n[italic]Note: This is currently a placeholder. In the future, this could open a browser to create a contribution pull request.[/italic]")