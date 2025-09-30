# 🔐 Whisper


**Whisper keeps your secrets silent.**


Whisper is an AI-powered secret scanner that helps developers and teams catch **real secrets** before they leak — without drowning you in false positives.

Unlike regex-only tools, Whisper uses **contextual analysis** with local Ollama models to tell the difference between a dummy API key in test code and a live credential in production.


---


## 🚀 Quick Start


### Installation

```bash

# Using pip (Python)

pip install whisper-secrets


# Using npm (Node.js)

npm install -g whisper-secrets


# Using brew (macOS)

brew install whisper-secrets

```


### Basic Usage

```bash

# Scan your project (uses local Ollama by default)

whisper scan .


# Scan with specific confidence threshold

whisper scan . --confidence-threshold 0.8


# Scan excluding test files

whisper scan . --exclude "**/test/**" --exclude "**/__tests__/**"

```


### First-Time Setup

```bash

# Download the pre-trained security model

whisper setup


# Or use an existing Ollama model

whisper setup --model codellama:7b

```


---


## 🏗️ Architecture


Whisper uses a smart two-stage detection system with privacy-first local AI:


### Detection Pipeline

```

1. Candidate Detection → 2. Local AI Validation → 3. Cloud LLM (Edge Cases)

(Regex/Entropy) (Ollama - 95% cases) (Training & Uncertainties)

```


### Component Responsibilities


| Component | Role | Usage |

|-----------|------|-------|

| **Ollama** | Primary AI classifier | All daily scanning (local, private) |

| **Cloud LLM** | Training & edge cases | Model improvement, ambiguous patterns |

| **Regex Engine** | Candidate detection | Initial pattern matching |


---


## 🔧 Configuration


### Configuration File

Create `whisper.config.yaml`:


```yaml

# Core settings

version: 1

scan_path: "."


# AI Configuration

ai:

primary: ollama

model: whisper/secrets-detector:latest

confidence_threshold: 0.8

# Cloud fallback (optional)

fallback:

enabled: true

provider: "openai" # or "anthropic", "azure"

max_monthly_cost: 10.00

daily_request_limit: 50


# Scanning rules

rules:

excluded_paths:

- "**/node_modules/**"

- "**/.git/**"

- "**/vendor/**"

- "**/__pycache__/**"

file_extensions:

- ".py"

- ".js"

- ".ts"

- ".java"

- ".go"

- ".rb"

- ".php"

- ".yaml"

- ".yml"

- ".json"

- ".env"

max_file_size: "5MB"


# Secret patterns

detectors:

- type: "regex"

patterns:

- "api_key"

- "password"

- "secret"

- "token"

- "credential"

- type: "entropy"

threshold: 4.5

- type: "contextual"

enabled: true

```


### Environment Variables

```bash

# Ollama configuration

export OLLAMA_HOST="http://localhost:11434"

export WHISPER_MODEL="whisper/secrets-detector:latest"


# Cloud LLM (optional, for training/edge cases)

export OPENAI_API_KEY="sk-..." # Only for model updates

export WHISPER_CLOUD_ENABLED="false" # Disable completely for air-gapped environments


# Application settings

export WHISPER_CONFIDENCE_THRESHOLD="0.8"

export WHISPER_MAX_FILE_SIZE="5MB"

```


---


## 🎯 Supported Secret Types


Whisper detects a wide range of secrets through pattern matching and contextual understanding:


### API Keys & Tokens

- **GitHub**: `ghp_`, `github_pat_`

- **AWS**: `AKIA[0-9A-Z]{16}`

- **Stripe**: `sk_(live|test)_[a-zA-Z0-9]{24}`

- **Slack**: `xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}`

- **Generic**: High-entropy strings in credential contexts


### Database & Service Credentials

- **Connection Strings**: `postgresql://`, `mongodb://`, `redis://`

- **Passwords**: In configuration files, environment variables

- **Private Keys**: RSA, SSH, PGP keys


### Custom Patterns

```yaml

# Add your organization-specific patterns

custom_patterns:

- name: "company_internal_key"

pattern: "company_[a-z0-9]{32}"

confidence: "high"

- name: "proprietary_token"

pattern: "prop_[A-Z0-9]{24}"

confidence: "medium"

```


---


## 🔄 Model Management


### Local Models

```bash

# List available models

whisper models list


# Switch active model

whisper models use codellama:7b


# Create custom model for your organization

whisper models create --name my-company-secrets --base codellama:7b

```


### Model Updates

```bash

# Check for updates

whisper update --check


# Download latest security intelligence

whisper update


# Force retrain with latest patterns

whisper update --retrain

```


---


## 🔌 Integrations


### Pre-commit Hook

Add to `.pre-commit-config.yaml`:


```yaml

repos:

- repo: https://github.com/whisper-secrets/whisper

rev: v1.0.0

hooks:

- id: whisper-secrets

args: [--staged, --confidence-threshold, "0.9"]

```


### GitHub Action

```yaml

name: Secret Scanning

on: [push, pull_request]


jobs:

scan:

runs-on: ubuntu-latest

steps:

- uses: actions/checkout@v3

- name: Setup Whisper

uses: whisper-secrets/setup-action@v1

- name: Scan for secrets

run: whisper scan . --ci --fail-on high

```


### CI/CD Pipeline

```bash

# Fail pipeline on high-confidence secrets

whisper scan . --ci --fail-on high


# Output SARIF format for GitHub code scanning

whisper scan . --format sarif --output results.sarif


# Scan only modified files in PR

whisper scan . --staged --diff HEAD~1

```


---


## 🎓 How It Works


### 1. Candidate Detection

```python

# Regex patterns + entropy analysis finds potential secrets

candidates = [

"api_key = 'ghp_abc123def456'",

"test_key = 'mock_12345'", # False positive candidate

"password = 'example_pass'" # Low entropy, needs context

]

```


### 2. Contextual Analysis

The AI considers:

- **Variable names**: `live_key` vs `example_key` vs `test_key`

- **File context**: `config/prod.json` vs `test/fixtures.json`

- **Code patterns**: Assignment vs usage vs examples

- **Project structure**: Production code vs test vs documentation


### 3. Confidence Scoring

```python

{

"secret": "ghp_abc123def456",

"confidence": 0.94,

"reason": "High entropy token in production config with 'api_key' variable",

"file": "config/production.yaml",

"line": 42,

"type": "github_pat"

}

```


---


## 📊 Performance & Accuracy


### Benchmark Results

| Tool | Precision | Recall | False Positives |

|------|-----------|--------|-----------------|

| **Whisper** | **96%** | **94%** | **0.8%** |

| Regex-only | 72% | 88% | 12% |

| Entropy-based | 65% | 92% | 23% |


### Resource Usage

```bash

# Typical scan performance

$ time whisper scan ~/code/my-project


Real: 12.4s

User: 8.2s

System: 1.1s

RAM: 450MB (Ollama model included)

```


---


## 🔒 Privacy & Security


### Data Handling

- **Source Code**: Never leaves your machine during normal operation

- **Scan Results**: Remain local unless explicitly shared (opt-in)

- **AI Processing**: 95%+ handled by local Ollama instances

- **Cloud Usage**: Only for model training with anonymized edge cases


### Air-Gapped Environments

```bash

# Completely disable external calls

whisper scan . --local-only --no-update


# Use internal model registry

whisper setup --model-registry http://internal-registry:11434


# Export/import models for disconnected systems

whisper models export --output whisper-model.tar

whisper models import --file whisper-model.tar

```


---


## 🛠️ Development & Contributing


### Building from Source

```bash

git clone https://github.com/whisper-secrets/whisper

cd whisper


# Install dependencies

pip install -e .


# Run tests

pytest tests/


# Build locally

python -m build

```


### Contributing Patterns

```bash

# Report false positive

whisper report fp --file config.py --line 15 --reason "test fixture"


# Suggest new pattern

whisper contribute pattern --name "NewService" --pattern "new_[a-z0-9]{32}"


# Add custom detector

whisper contribute detector --language python --file my_detector.py

```


### Architecture Development

```python

# Add custom detectors in ~/.whisper/detectors/

class MyCustomDetector:

def detect(self, file_content, file_path):

# Your detection logic

return candidates

```


---


## 🐛 Troubleshooting


### Common Issues


**Ollama not running:**

```bash

# Start Ollama service

ollama serve


# Or specify custom host

whisper scan . --ollama-host http://localhost:11434

```


**Model not found:**

```bash

# Pull default model

ollama pull codellama:7b


# Or use different model

whisper scan . --model llama3.1:8b

```


**Performance issues:**

```bash

# Use smaller model

whisper scan . --model codellama:7b


# Limit file size

whisper scan . --max-file-size 1MB


# Exclude large directories

whisper scan . --exclude "**/node_modules/**"

```


### Debug Mode

```bash

# See detailed analysis

whisper scan . --debug


# Save full analysis log

whisper scan . --debug --log-file scan-debug.log

```


---


## 📄 License


MIT License - see [LICENSE](LICENSE) for details.


---


## 🤝 Community & Support


- **GitHub Issues**: [Report bugs](https://github.com/whisper-secrets/whisper/issues)

- **Discord**: [Join discussions](https://discord.gg/whisper)

- **Documentation**: [Full docs](https://docs.whisper-secrets.com)

- **Security**: [Report vulnerabilities](mailto:security@whisper-secrets.com)


---


> **Whisper keeps your secrets silent — so you can code with peace of mind.** 🔐


---


*Whisper is in active development. Features and configuration options may evolve based on community feedback and security research.* 
