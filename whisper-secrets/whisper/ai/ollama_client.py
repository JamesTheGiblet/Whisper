import requests
import json
import os
from typing import Dict, Any, Optional

class OllamaClient:
    """
    A client to interact with a local Ollama instance for secret classification.
    """

    def __init__(self, model: str, host: Optional[str] = None):
        """
        Initializes the OllamaClient.

        Args:
            model (str): The name of the model to use for classification.
            host (Optional[str]): The URL of the Ollama host. Defaults to the
                                  OLLAMA_HOST environment variable or "http://localhost:11434".
        """
        if host is None:
            host = os.getenv("OLLAMA_HOST", "http://localhost:11434")

        self.api_url = f"{host.rstrip('/')}/api/generate"
        self.model = model

    def _build_prompt(self, candidate: str, context: str) -> str:
        """Constructs the prompt for the AI model."""
        # This prompt is crucial. It instructs the model to act as a security expert.
        # It asks for a JSON response with a boolean `is_secret` and a `reason`.
        return f"""
        You are an expert security analyst specializing in secret detection.
        Your task is to determine if a given string is a hardcoded secret.
        Analyze the following code snippet and the highlighted candidate string.

        Code Context:
        ```
        {context}
        ```

        Candidate Secret: "{candidate}"

        Is the candidate string a real, hardcoded secret, or is it a placeholder,
        example, or test data? Provide your answer in JSON format with two keys:
        "is_secret" (boolean) and "reason" (a brief explanation).
        """

    def classify_candidate(self, candidate: str, context: str) -> Dict[str, Any]:
        """
        Asks the Ollama model to classify if a candidate string is a secret
        based on its surrounding code context.

        Args:
            candidate (str): The potential secret string.
            context (str): The surrounding code or file content.

        Returns:
            A dictionary containing the model's analysis (e.g., {"is_secret": True, "reason": "..."}).
            Returns a default error dictionary if the request fails.
        """
        prompt = self._build_prompt(candidate, context)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",  # Ollama can directly output JSON
        }

        try:
            response = requests.post(self.api_url, json=payload, timeout=30)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

            # The model's JSON output is a string inside the 'response' key
            response_data = response.json()
            model_output = json.loads(response_data.get("response", "{}"))

            return {
                "is_secret": model_output.get("is_secret", False),
                "reason": model_output.get("reason", "Failed to parse model output."),
            }
        except requests.exceptions.RequestException as e:
            return {"is_secret": False, "reason": f"Ollama API request failed: {e}"}
        except json.JSONDecodeError:
            return {"is_secret": False, "reason": "Failed to decode JSON response from model."}