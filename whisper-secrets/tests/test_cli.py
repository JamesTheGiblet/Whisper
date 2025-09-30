from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from whisper.cli import app

runner = CliRunner()


@patch('whisper.cli.subprocess.Popen')
@patch('whisper.cli.shutil.which', return_value=True)
@patch('whisper.cli.load_config')
def test_setup_command_pulls_model_from_config(mock_load_config, mock_shutil_which, mock_popen):
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
def test_setup_command_uses_cli_option_override(mock_load_config, mock_shutil_which, mock_popen):
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