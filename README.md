# 🛡️ Open-Source LLM Security Scanner

A powerful and easy-to-use script to scan your local Ollama Large Language Models (LLMs) for security vulnerabilities and potential risks. Get instant insights to ensure your models are safe and secure.

---

## ✨ Core Features

* **📦 Model Verification**: Checks model integrity, layers, and provenance.
* **🐍 Malicious Code Detection**: Scans for dangerous code patterns and suspicious file types.
* **💉 Prompt Injection Testing**: Actively tests models against common prompt injection attacks.
* **🌐 Network & Resource Monitoring**: Monitors network connections and system resource usage (CPU, Memory) for anomalies.
* **📄 Comprehensive Reporting**: Generates a detailed report with risk levels (**HIGH**, **MEDIUM**, **LOW**) and clear recommendations.
* **🧠 General Risk Awareness**: Educates on inherent LLM risks like hallucinations, bias, and data privacy.

---

## 🚀 Getting Started

### 1. Installation

You'll need `python-magic` and its underlying library.

```bash
# Install Python dependencies
pip install python-magic numpy psutil

# On macOS, you also need to install libmagic
brew install libmagic

### 2. Usage

Run the scanner by pointing it to the model you want to check.

# List all available models
python openllmscan.py --list

# Scan a specific model
python openllmscan.py --model llama3

```

