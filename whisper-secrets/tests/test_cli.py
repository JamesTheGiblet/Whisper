from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import json
import requests
from pathlib import Path
import pytest
import yaml

from whisper.cli import importlib
from whisper.cli import logging
from whisper.cli import app

runner = CliRunner()

MOCK_FINDINGS = [
    {
        "file": "/path/to/test.py",
        "line": 10,
        "secret_value": "a-secret-value",
        "reason": "AI says so",
        "detector": "Regex",
    }
]

MOCK_MODELS_RESPONSE = {
    "models": [
        {
            "name": "codellama:7b",
            "size": 4109865159,
            "modified_at": "2024-01-01T19:48:47.9334029Z",
        },
        {
            "name": "llama3:latest",
            "size": 4661224676,
            "modified_at": "2024-02-15T14:18:43.4969353Z",
        },
    ]
}

@patch('whisper.cli.subprocess.Popen')
@patch('whisper.cli.shutil.which', return_value=True)
@patch('whisper.cli.load_config')
@patch('whisper.cli._check_ollama_availability', return_value=True)
def test_setup_command_pulls_model_from_config(mock_ollama_check, mock_load_config, mock_shutil_which, mock_popen):
    """
    Verify the setup command calls `ollama pull` with the model from the config.
    """
    # Arrange: Mock the configuration and the subprocess call
    mock_load_config.return_value = {"ai": {"model": "model-from-config:latest"}}

    # Mock the process to simulate a successful run
    mock_process = MagicMock()
    mock_process.wait.return_value = 0
    mock_process.returncode = 0
    mock_process.stdout.readline.side_effect = ["pulling manifest", "success", ""]
    mock_popen.return_value = mock_process

    # Act: Run the 'setup' command
    result = runner.invoke(app, ["setup"])

    # Assert: Check for success and correct command execution
    assert result.exit_code == 0
    assert "Model model-from-config:latest pulled successfully" in result.stdout
    mock_popen.assert_called_once_with(
        ["ollama", "pull", "model-from-config:latest"],
        stdout=-1, stderr=-2, text=True, encoding='utf-8'
    )


@patch('whisper.cli.subprocess.Popen')
@patch('whisper.cli.shutil.which', return_value=True)
@patch('whisper.cli.load_config')
@patch('whisper.cli._check_ollama_availability', return_value=True)
def test_setup_command_uses_cli_option_override(mock_ollama_check, mock_load_config, mock_shutil_which, mock_popen):
    """
    Verify the setup command uses the --model option to override the config.
    """
    # Arrange: Mock the configuration and the subprocess call
    mock_load_config.return_value = {"ai": {"model": "should-be-ignored:latest"}}
    mock_process = MagicMock()
    mock_process.wait.return_value = 0
    mock_process.returncode = 0
    mock_process.stdout.readline.side_effect = [""]
    mock_popen.return_value = mock_process

    # Act: Run the 'setup' command with the --model flag
    result = runner.invoke(app, ["setup", "--model", "cli-override-model:v1"])

    # Assert: Check for success and correct command execution with the override
    assert result.exit_code == 0
    assert "Model cli-override-model:v1 pulled successfully" in result.stdout
    mock_popen.assert_called_once_with(
        ["ollama", "pull", "cli-override-model:v1"],
        stdout=-1, stderr=-2, text=True, encoding='utf-8'
    )


@patch('whisper.cli.shutil.which', return_value=None)
def test_setup_command_fails_if_ollama_not_found(mock_shutil_which):
    """
    Verify the setup command fails gracefully if the `ollama` executable is not found.
    """
    # Act: Run the 'setup' command
    result = runner.invoke(app, ["setup"])

    # Assert: Check for a non-zero exit code and the correct error message
    assert result.exit_code != 0
    assert "`ollama` command not found" in result.stdout
    assert "Please install Ollama" in result.stdout


@patch('whisper.cli.FileScanner')
def test_scan_command_table_output(mock_file_scanner):
    """
    Verify the scan command produces a table output by default.
    """
    # Arrange
    mock_scanner_instance = mock_file_scanner.return_value
    mock_scanner_instance.scan.return_value = MOCK_FINDINGS

    # Act
    result = runner.invoke(app, ["scan", "."])

    # Assert
    assert result.exit_code == 0
    assert "Scan Results" in result.stdout
    assert "/path/to/test.py" in result.stdout
    assert "AI says so" in result.stdout
    assert "Regex" in result.stdout


@patch('whisper.cli.FileScanner')
def test_scan_command_json_output(mock_file_scanner):
    """
    Verify the scan command produces a valid JSON output when requested.
    """
    # Arrange
    mock_scanner_instance = mock_file_scanner.return_value
    mock_scanner_instance.scan.return_value = MOCK_FINDINGS

    # Act
    result = runner.invoke(app, ["scan", ".", "--format", "json"])

    # Assert
    assert result.exit_code == 0
    # Verify the output is a valid JSON that matches our mock findings
    parsed_output = json.loads(result.stdout)
    assert parsed_output == MOCK_FINDINGS


@patch('whisper.cli.FileScanner')
def test_scan_command_fails_with_fail_on_finding_flag(mock_file_scanner):
    """
    Verify the scan command exits with a non-zero code when findings are present
    and --fail-on-finding is used.
    """
    # Arrange
    mock_scanner_instance = mock_file_scanner.return_value
    mock_scanner_instance.scan.return_value = MOCK_FINDINGS

    # Act
    result = runner.invoke(app, ["scan", ".", "--fail-on-finding"])

    # Assert
    assert result.exit_code == 1
    assert "Failing build due to found secrets" in result.stdout


@patch('whisper.cli.FileScanner')
def test_scan_command_succeeds_with_fail_on_finding_and_no_findings(mock_file_scanner):
    """
    Verify the scan command exits with a zero code when --fail-on-finding is used
    but no secrets are found.
    """
    # Arrange
    mock_scanner_instance = mock_file_scanner.return_value
    mock_scanner_instance.scan.return_value = []  # No findings

    # Act
    result = runner.invoke(app, ["scan", ".", "--fail-on-finding"])

    # Assert
    # The app exits via `typer.Exit()` with no code, which defaults to 0.
    assert result.exit_code == 0
    assert "No secrets found" in result.stdout
    assert "Failing build" not in result.stdout


@patch('whisper.cli.requests.get')
def test_models_list_success(mock_requests_get):
    """
    Verify the `models list` command displays a table of models on success.
    """
    # Arrange
    mock_response = MagicMock()
    mock_response.json.return_value = MOCK_MODELS_RESPONSE
    mock_requests_get.return_value = mock_response

    # Act
    result = runner.invoke(app, ["models", "list"])

    # Assert
    assert result.exit_code == 0
    assert "Available Local Models" in result.stdout
    assert "codellama:7b" in result.stdout
    assert "llama3:latest" in result.stdout
    # Note: The exact size format might vary based on rich.filesize implementation
    # Just check that some size representation is present
    assert "GB" in result.stdout or "MB" in result.stdout or "B" in result.stdout


@patch('whisper.cli.requests.get')
def test_models_list_no_models(mock_requests_get):
    """
    Verify the `models list` command shows a message when no models are found.
    """
    # Arrange
    mock_response = MagicMock()
    mock_response.json.return_value = {"models": []}
    mock_requests_get.return_value = mock_response

    # Act
    result = runner.invoke(app, ["models", "list"])

    # Assert
    assert result.exit_code == 0
    assert "No local models found" in result.stdout


@patch('whisper.cli.requests.get', side_effect=requests.exceptions.ConnectionError)
def test_models_list_connection_error(mock_requests_get):
    """
    Verify the `models list` command fails gracefully on a connection error.
    """
    # Act
    result = runner.invoke(app, ["models", "list"])

    # Assert
    assert result.exit_code != 0
    assert "Could not connect to Ollama" in result.stdout


@patch('whisper.cli.FileScanner')
def test_scan_command_creates_log_file(mock_file_scanner, tmp_path):
    """
    Verify that using --log-file creates a log file with the correct content.
    """
    # Arrange
    mock_scanner_instance = mock_file_scanner.return_value
    mock_scanner_instance.scan.return_value = []
    log_file = tmp_path / "test.log"

    # Act
    # Note: Global options like --log-file must come before the command.
    result = runner.invoke(app, ["--log-file", str(log_file), "scan", ".", "--confidence-threshold", "0.9"])

    # Assert
    assert result.exit_code == 0
    assert log_file.exists()
    
    log_content = log_file.read_text()
    assert "INFO" in log_content
    assert "Overriding confidence threshold to: 0.9" in log_content


@patch('whisper.cli.logging.basicConfig')
def test_verbose_flag_sets_debug_level(mock_basic_config):
    """
    Verify that the --verbose flag sets the logging level to DEBUG.
    """
    # Act
    runner.invoke(app, ["--verbose", "scan", "."])

    # Assert
    # Check that logging.basicConfig was called with level=logging.DEBUG
    mock_basic_config.assert_called()
    call_args = mock_basic_config.call_args
    # The level could be passed as positional or keyword argument
    assert call_args[1].get("level") == logging.DEBUG or (call_args[0] and call_args[0][0] == logging.DEBUG)


def test_scan_command_no_log_file_by_default(tmp_path):
    """
    Verify that no log file is created by default.
    """
    # Use isolated_filesystem to ensure we have a clean directory.
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        result = runner.invoke(app, ["scan", "."])
        assert result.exit_code == 0
        assert not list(Path(td).glob("*.log"))


def test_models_use_creates_new_config(tmp_path):
    """
    Verify `models use` creates a new config file if one doesn't exist.
    """
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        # Arrange: We are in an empty directory
        config_path = Path(td) / "whisper.config.yaml"
        assert not config_path.exists()

        # Act
        result = runner.invoke(app, ["models", "use", "new-model:latest"])

        # Assert
        assert result.exit_code == 0
        assert "Creating a new one" in result.stdout
        assert config_path.exists()

        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        assert config_data == {"ai": {"model": "new-model:latest"}}


def test_models_use_updates_existing_config(tmp_path):
    """
    Verify `models use` updates the model in an existing config file.
    """
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        # Arrange: Create a pre-existing config file
        config_path = Path(td) / "whisper.config.yaml"
        initial_config = {"ai": {"model": "old-model:v1"}, "rules": {"max_file_size": "1MB"}}
        with open(config_path, 'w') as f:
            yaml.dump(initial_config, f)

        # Act
        result = runner.invoke(app, ["models", "use", "updated-model:v2"])

        # Assert
        assert result.exit_code == 0
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        assert config_data["ai"]["model"] == "updated-model:v2"
        assert config_data["rules"]["max_file_size"] == "1MB" # Verify other keys are preserved


@patch('whisper.cli.FileScanner', side_effect=ValueError("A test error occurred"))
def test_debug_flag_raises_exception(mock_file_scanner):
    """
    Verify that with --debug, an exception is re-raised for a full stack trace.
    """
    # Act
    result = runner.invoke(app, ["--debug", "scan", "."])

    # Assert
    assert result.exit_code != 0
    assert isinstance(result.exception, ValueError)
    assert "A test error occurred" in str(result.exception)


@patch('whisper.cli.FileScanner', side_effect=ValueError("A test error occurred"))
def test_no_debug_flag_shows_clean_error(mock_file_scanner):
    """
    Verify that without --debug, a clean error message is shown.
    """
    # Act
    result = runner.invoke(app, ["scan", "."])

    # Assert
    assert result.exit_code == 1
    # In Typer with our custom error handler, we get a clean error message
    assert "An unexpected error occurred: A test error occurred" in result.stdout


@patch('whisper.cli.FileScanner')
@patch('whisper.cli.Progress')
def test_scan_command_uses_progress_bar(mock_progress_class, mock_file_scanner):
    """
    Verify that the scan command creates a Progress object and passes it to the scanner.
    """
    # Arrange
    # Mock the scanner instance and the progress context manager
    mock_scanner_instance = mock_file_scanner.return_value
    mock_progress_instance = mock_progress_class.return_value.__enter__.return_value

    # Act
    result = runner.invoke(app, ["scan", "."])

    # Assert
    assert result.exit_code == 0
    # Verify that a Progress object was created
    mock_progress_class.assert_called_once()
    # Verify that the scanner's scan method was called with the progress instance
    mock_scanner_instance.scan.assert_called_once_with(progress=mock_progress_instance)


@patch('whisper.cli.os.remove')
@patch('whisper.cli.tempfile.NamedTemporaryFile')
@patch('whisper.cli.subprocess.Popen')
@patch('whisper.cli.shutil.which', return_value=True)
@patch('whisper.cli._check_ollama_availability', return_value=True)
def test_models_create_success(mock_ollama_check, mock_shutil_which, mock_popen, mock_tempfile, mock_os_remove):
    """
    Verify the `models create` command correctly generates a Modelfile
    and calls `ollama create`.
    """
    # Arrange
    # Mock for subprocess.Popen
    mock_process = MagicMock()
    mock_process.wait.return_value = 0
    mock_process.returncode = 0
    mock_process.stdout.readline.side_effect = [""]
    mock_popen.return_value = mock_process

    # Mock for tempfile.NamedTemporaryFile to control the file path and check writes
    mock_file_handle = MagicMock()
    mock_file_handle.name = "/tmp/fake-modelfile"
    mock_tempfile.return_value.__enter__.return_value = mock_file_handle

    # Act
    result = runner.invoke(app, ["models", "create", "--name", "my-test-model", "--base", "test-base:latest"])

    # Assert
    assert result.exit_code == 0
    assert "Model my-test-model created successfully" in result.stdout

    # Verify the Modelfile was written with the correct content
    mock_file_handle.write.assert_called_once()
    written_content = mock_file_handle.write.call_args[0][0]
    assert "FROM test-base:latest" in written_content
    assert "You are an expert security analyst" in written_content

    # Verify that `ollama create` was called correctly
    mock_popen.assert_called_once_with(
        ["ollama", "create", "my-test-model", "-f", "/tmp/fake-modelfile"],
        stdout=-1, stderr=-2, text=True, encoding='utf-8'
    )

    # Verify the temporary file was cleaned up
    mock_os_remove.assert_called_once_with("/tmp/fake-modelfile")


def test_update_command_default_behavior():
    """
    Verify the default `update` command shows the correct placeholder message.
    """
    # Act
    result = runner.invoke(app, ["update"])

    # Assert
    assert result.exit_code == 0
    assert "Downloading latest security intelligence" in result.stdout
    assert "Everything is up to date" in result.stdout


def test_update_command_with_check_flag():
    """
    Verify the `update --check` command shows the correct placeholder message.
    """
    # Act
    result = runner.invoke(app, ["update", "--check"])

    # Assert
    assert result.exit_code == 0
    assert "Checking for available updates" in result.stdout


def test_update_command_with_retrain_flag():
    """
    Verify the `update --retrain` command shows the correct placeholder message
    and exits with a non-zero code as it is not yet implemented.
    """
    # Act
    result = runner.invoke(app, ["update", "--retrain"])

    # Assert
    assert result.exit_code == 1
    assert "Model retraining is not yet implemented" in result.stdout


@patch('whisper.cli.importlib.metadata.version')
def test_version_flag_success(mock_metadata_version):
    """
    Verify the --version flag prints the correct version when the package is installed.
    """
    # Arrange
    mock_metadata_version.return_value = "1.2.3"

    # Act
    result = runner.invoke(app, ["--version"])

    # Assert
    assert result.exit_code == 0
    assert "Whisper version: 1.2.3" in result.stdout


@patch('whisper.cli.importlib.metadata.version', side_effect=importlib.metadata.PackageNotFoundError)
def test_version_flag_local_build(mock_metadata_version):
    """
    Verify the --version flag shows the local build message when the package is not found.
    """
    # Act
    result = runner.invoke(app, ["--version"])

    # Assert
    assert result.exit_code == 0
    assert "Whisper version: (local development build)" in result.stdout


def test_report_fp_command_success(tmp_path):
    """
    Verify the `report fp` command works correctly with valid arguments.
    """
    # Arrange
    dummy_file = tmp_path / "test.py"
    dummy_file.write_text("some content")

    # Act
    result = runner.invoke(
        app,
        [
            "report",
            "fp",
            "--file",
            str(dummy_file),
            "--line",
            "42",
            "--reason",
            "This is a test fixture",
        ],
    )

    # Assert
    assert result.exit_code == 0
    # Rich console output can wrap, so check for parts of the path or flatten output
    assert "Thank you for your contribution!" in result.stdout
    # Replace newlines to handle potential wrapping of the long path by rich
    assert str(dummy_file) in result.stdout.replace("\n", "")
    assert "at line 42" in result.stdout
    assert "This is a test fixture" in result.stdout


def test_report_fp_command_fails_on_missing_file():
    """
    Verify the `report fp` command fails if the specified file does not exist.
    """
    # Act
    result = runner.invoke(app, ["report", "fp", "--file", "nonexistent.py", "--line", "1", "--reason", "test"])

    # Assert
    assert result.exit_code != 0
    # Typer typically shows file validation errors in stdout, not stderr
    assert "File 'nonexistent.py' does not exist" in result.stdout or "No such file or directory" in result.stdout


def test_contribute_pattern_command_success():
    """Verify the `contribute pattern` command works correctly with valid arguments."""
    # Act
    result = runner.invoke(
        app,
        [
            "contribute", "pattern", 
            "--name", "My Test Pattern",
            "--pattern", "test_[a-z]{10}",
        ],
    )

    # Assert
    assert result.exit_code == 0
    assert "Suggesting new pattern: My Test Pattern" in result.stdout
    # The pattern might be displayed differently now - check for partial match
    assert "test_[a-z]{10}" in result.stdout


def test_contribute_pattern_command_fails_on_missing_option():
    """Verify the `contribute pattern` command fails if a required option is missing."""
    # Act
    result = runner.invoke(app, ["contribute", "pattern", "--name", "Incomplete Pattern"])

    # Assert
    assert result.exit_code != 0
    # Typer shows missing option errors in stdout
    assert "Missing option '--pattern'" in result.stdout


def test_show_exit_codes_command():
    """Verify the --show-exit-codes flag displays exit code documentation."""
    # Act
    result = runner.invoke(app, ["--show-exit-codes"])

    # Assert
    assert result.exit_code == 0
    assert "Exit Codes" in result.stdout
    assert "Success - No secrets found" in result.stdout


@patch('whisper.cli.FileScanner')
def test_scan_command_csv_output(mock_file_scanner):
    """
    Verify the scan command produces CSV output when requested.
    """
    # Arrange
    mock_scanner_instance = mock_file_scanner.return_value
    mock_scanner_instance.scan.return_value = MOCK_FINDINGS

    # Act
    result = runner.invoke(app, ["scan", ".", "--format", "csv"])

    # Assert
    assert result.exit_code == 0
    assert "File,Line,Detector,Reason,Confidence" in result.stdout
    assert "/path/to/test.py" in result.stdout
    assert "Regex" in result.stdout


@patch('whisper.cli.FileScanner')
def test_scan_dry_run_mode(mock_file_scanner):
    """
    Verify the scan command dry run mode works correctly.
    """
    # Arrange
    mock_scanner_instance = mock_file_scanner.return_value
    mock_scanner_instance.discover_files.return_value = 42  # Mock file count

    # Act
    result = runner.invoke(app, ["scan", ".", "--dry-run"])

    # Assert
    assert result.exit_code == 0
    assert "Dry run mode" in result.stdout
    assert "Would scan 42 files" in result.stdout
    # Verify scan was not actually called
    mock_scanner_instance.scan.assert_not_called()


@patch('whisper.cli._check_ollama_availability', return_value=False)
def test_setup_command_fails_if_ollama_not_running(mock_ollama_check):
    """
    Verify the setup command fails if Ollama is not running.
    """
    # Act
    result = runner.invoke(app, ["setup"])

    # Assert
    assert result.exit_code == 3  # Our custom exit code for Ollama connection error
    assert "Ollama is not running or not accessible" in result.stdout


def test_test_command_success():
    """Verify the test command runs successfully with mocked dependencies."""
    with patch('whisper.cli._check_ollama_availability', return_value=True), \
         patch('whisper.cli.load_config', return_value={"ai": {"model": "test-model"}}), \
         patch('whisper.cli.validate_config', return_value=True), \
         patch('whisper.cli.requests.get') as mock_get:
        
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Act
        result = runner.invoke(app, ["test"])

        # Assert
        assert result.exit_code == 0
        assert "All tests passed! Whisper is ready to use." in result.stdout