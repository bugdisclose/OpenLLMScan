# Open-Source LLM Security Scanner

A quick scan script to gather security insights for your locally running LLMs.

## Features

### 1. Model Verification
- Config file integrity checks
- Layer-by-layer verification
- Model size analysis
- Inference testing
- Digital signature verification
- Model provenance tracking

### 2. Security Checks
- Malicious code pattern detection
- File signature analysis
- Network isolation monitoring
- Resource usage tracking (CPU, Memory, Disk)
- File permissions and ownership validation
- Input validation against common attack vectors
- Model manifest inspection

### 3. Network Security
- Connection monitoring
- Port usage analysis
- Network isolation verification
- Unauthorized connection detection

### 4. Resource Monitoring
- Real-time memory usage tracking
- CPU utilization monitoring
- Disk I/O analysis
- Resource limit enforcement

## Installation

```bash
pip install python-magic numpy psutil
```

For macOS, also install:
```bash
brew install libmagic
```

## Usage

Basic usage:
```bash
python scanner.py --model <model-name>
```

Example:
```bash
python scanner.py --model deepseek-r1:14b
```

## Security Report

The scanner generates a comprehensive security report including:
- Model verification status
- Security alerts (Low/Medium/High risk)
- Network activity analysis
- Resource usage statistics
- Dependency vulnerabilities
- Recommended actions

## Requirements

- Python 3.8+
- Ollama
- python-magic
- numpy
- psutil

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License

## Security

For security issues, raise queries in issue tracker.
