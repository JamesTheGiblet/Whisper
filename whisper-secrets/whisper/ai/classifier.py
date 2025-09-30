from typing import Dict, Any

from whisper.ai.ollama_client import OllamaClient
from whisper.config.settings import load_config


class SecretClassifier:
    """
    Uses an AI client to classify if a given candidate is a secret.
    This class orchestrates the call to the underlying AI model.
    """

    def __init__(self):
        """
        Initializes the classifier by loading the application configuration
        and setting up the appropriate AI client based on that config.
        """
        self.config = load_config()
        ai_config = self.config.get("ai", {})

        # This is where logic could be added to switch between different AI providers
        # (e.g., a cloud fallback). For now, it's hardcoded to Ollama.
        if ai_config.get("primary") == "ollama":
            self.ai_client = OllamaClient(model=ai_config.get("model"))
        else:
            # In the future, this could raise an error or initialize a different client.
            raise ValueError(f"Unsupported AI provider: {ai_config.get('primary')}")

    def classify(self, candidate: str, context: str) -> Dict[str, Any]:
        """
        Passes a candidate and its context to the configured AI client for analysis.

        Args:
            candidate (str): The potential secret string to analyze.
            context (str): The surrounding code or content for context.

        Returns:
            A dictionary containing the AI model's analysis, including whether
            it's a secret and the reasoning.
        """
        return self.ai_client.classify_candidate(candidate, context)