import typer
from pathlib import Path
from typing import Optional, List
import importlib.metadata
from rich.console import Console
from rich.table import Table
import subprocess
import shutil

from whisper.core.scanner import FileScanner
from whisper.config.settings import load_config

app = typer.Typer(
    name="whisper",
    help="An AI-powered secret scanner to find real secrets without the noise.",
    add_completion=False,
)
console = Console()

def version_callback(value: bool):
    """Prints the version of the application."""
    if value:
        try:
            version = importlib.metadata.version("whisper-secrets")
            typer.echo(f"Whisper version: {version}")
        except importlib.metadata.PackageNotFoundError:
            typer.echo("Whisper version: (local development build)")
        raise typer.Exit()

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=version_callback,
        is_eager=True,
    )
):
    """Whisper keeps your secrets silent."""
    pass

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
):
    """Scan a directory or file for secrets."""
    # Load the base configuration
    config = load_config()

    # Apply CLI overrides
    if confidence_threshold is not None:
        config["ai"]["confidence_threshold"] = confidence_threshold
        console.print(f"Overriding confidence threshold to: [yellow]{confidence_threshold}[/yellow]")

    if exclude:
        config["rules"]["excluded_paths"].extend(exclude)
        console.print(f"Adding exclusion patterns: [yellow]{', '.join(exclude)}[/yellow]")

    console.print(f"🔐 Scanning [cyan]{path}[/cyan]...")
    scanner = FileScanner(str(path), config=config)
    findings = scanner.scan()

    if not findings:
        console.print("✅ No secrets found.", style="green")
        raise typer.Exit()

    console.print(f"🚨 Found {len(findings)} potential secret(s):", style="bold red")
    table = Table(title="Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta")
    table.add_column("Detector", style="green")
    table.add_column("Reason", style="yellow")

    for finding in findings:
        table.add_row(finding["file"], str(finding["line"]), finding["detector"], finding["reason"])
    console.print(table)

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