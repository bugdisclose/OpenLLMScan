import os
import json
import hashlib
import psutil
import requests
import subprocess
import tempfile
import re
import sys
import traceback
import argparse
import time
import threading
from typing import Dict, List, Set, Tuple, Optional
import yaml
import socket
import ssl
from datetime import datetime
import logging
import numpy as np
from dataclasses import dataclass
from enum import Enum

try:
    import magic
except ImportError:
    print("Installing python-magic...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-magic"])
    import magic

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
OLLAMA_MODEL_PATH = os.path.expanduser("~/.ollama/models")
VENV_PATH = "/Users/satyendrak/Desktop/rag/venv/bin/activate"
IGNORED_FILES = {'.DS_Store', '.gitignore', 'README.md'}
SAFE_COMMANDS = {
    'pip list': True,
    'ollama list': True,
    'ollama run': True
}

class SecurityRisk(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class SecurityAlert:
    risk_level: SecurityRisk
    description: str
    recommendation: str

class ModelMonitor:
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.monitoring = False
        self.stats: Dict = {
            'start_time': None,
            'memory_usage': [],
            'cpu_usage': [],
            'network_connections': set(),
            'suspicious_activities': []
        }
        
    def start_monitoring(self):
        """Start monitoring the model's runtime behavior."""
        self.monitoring = True
        self.stats['start_time'] = datetime.now()
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop monitoring and return collected stats."""
        self.monitoring = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=2)
        return self.stats
        
    def _monitor_loop(self):
        """Monitor system resources and activities."""
        while self.monitoring:
            try:
                # Monitor Ollama process
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if 'ollama' in proc.name().lower():
                            # Memory usage
                            mem_info = proc.memory_info()
                            self.stats['memory_usage'].append(mem_info.rss / 1024 / 1024)  # MB
                            
                            # CPU usage
                            cpu_percent = proc.cpu_percent()
                            self.stats['cpu_usage'].append(cpu_percent)
                            
                            # Network connections
                            connections = proc.connections()
                            for conn in connections:
                                if conn.status == 'ESTABLISHED':
                                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                                    self.stats['network_connections'].add(remote_addr)
                                    
                            # Check for suspicious activities
                            if cpu_percent > 90:
                                self.stats['suspicious_activities'].append(
                                    f"High CPU usage detected: {cpu_percent}%"
                                )
                            if len(connections) > 10:
                                self.stats['suspicious_activities'].append(
                                    f"High number of network connections: {len(connections)}"
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
            except Exception as e:
                print(f"[WARNING] Monitoring error: {e}")
            
            time.sleep(1)  # Monitor every second

class ModelSecurityScanner:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.alerts: List[SecurityAlert] = []
        self.known_vulnerabilities_db = self._load_known_vulnerabilities()
        
    def _load_known_vulnerabilities(self) -> Dict:
        """Load known vulnerabilities database"""
        # TODO: Implement loading from a maintained database
        return {}

    def scan_for_malicious_code(self, content: bytes) -> List[SecurityAlert]:
        """Scan for potential malicious code patterns in model files"""
        alerts = []
        try:
            # Known malicious patterns (example patterns, should be expanded)
            malicious_patterns = [
                rb"eval\(.*\)",
                rb"exec\(.*\)",
                rb"os\.system\(.*\)",
                rb"subprocess\..*\(.*\)",
                rb"import socket;.*connect\("
            ]
            
            for pattern in malicious_patterns:
                if re.search(pattern, content):
                    alerts.append(SecurityAlert(
                        SecurityRisk.HIGH,
                        f"Potentially malicious code pattern detected: {pattern}",
                        "Review model source and verify code safety"
                    ))
        except Exception as e:
            logger.error(f"Error scanning for malicious code: {str(e)}")
            logger.debug(traceback.format_exc())
        return alerts

    def check_file_signatures(self, file_path: str) -> List[SecurityAlert]:
        """Verify file signatures and check for known malware signatures"""
        alerts = []
        try:
            if not os.path.exists(file_path):
                alerts.append(SecurityAlert(
                    SecurityRisk.HIGH,
                    f"File not found: {file_path}",
                    "Verify file path and permissions"
                ))
                return alerts

            # Get file type using magic
            try:
                file_type = magic.from_file(file_path)
            except Exception as e:
                logger.error(f"Error getting file type: {str(e)}")
                file_type = "unknown"
            
            # Check for suspicious file types
            suspicious_types = ['executable', 'script', 'PE32']
            if any(t in str(file_type).lower() for t in suspicious_types):
                alerts.append(SecurityAlert(
                    SecurityRisk.HIGH,
                    f"Suspicious file type detected: {file_type}",
                    "Review file content and verify its legitimacy"
                ))
                
            # Calculate file entropy for detecting encrypted/packed content
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                    entropy = self._calculate_entropy(data)
                    if entropy > 7.5:  # High entropy threshold
                        alerts.append(SecurityAlert(
                            SecurityRisk.MEDIUM,
                            f"High entropy content detected ({entropy:.2f})",
                            "Check for encrypted/packed malicious content"
                        ))
            except Exception as e:
                logger.error(f"Error calculating entropy: {str(e)}")
                
        except Exception as e:
            logger.error(f"Failed to check file signatures: {str(e)}")
            logger.debug(traceback.format_exc())
            alerts.append(SecurityAlert(
                SecurityRisk.HIGH,
                f"Failed to check file signatures: {str(e)}",
                "Ensure file is accessible and not corrupted"
            ))
        return alerts

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0.0
            entropy = 0
            for x in range(256):
                p_x = data.count(x)/len(data)
                if p_x > 0:
                    entropy += -p_x*np.log2(p_x)
            return entropy
        except Exception as e:
            logger.error(f"Error calculating entropy: {str(e)}")
            return 0.0

    def check_network_isolation(self) -> List[SecurityAlert]:
        """Check for proper network isolation and unauthorized connections"""
        alerts = []
        try:
            # Get all network connections
            connections = psutil.net_connections()
            
            # Check for suspicious ports
            suspicious_ports = {80, 443, 8080, 22}  # Example suspicious ports
            for conn in connections:
                try:
                    if conn.laddr and hasattr(conn.laddr, 'port') and conn.laddr.port in suspicious_ports:
                        alerts.append(SecurityAlert(
                            SecurityRisk.MEDIUM,
                            f"Suspicious network connection on port {conn.laddr.port}",
                            "Review and restrict network access if unnecessary"
                        ))
                except Exception as e:
                    logger.error(f"Error processing connection {conn}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error checking network isolation: {str(e)}")
            logger.debug(traceback.format_exc())
        return alerts

    def verify_model_provenance(self, manifest_path: str) -> List[SecurityAlert]:
        """Verify model origin and authenticity"""
        alerts = []
        try:
            if not os.path.exists(manifest_path):
                alerts.append(SecurityAlert(
                    SecurityRisk.MEDIUM,
                    f"Manifest file not found: {manifest_path}",
                    "Ensure manifest file exists and is accessible"
                ))
                return alerts
                
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
                
            # Check for required provenance information
            required_fields = ['author', 'source', 'created', 'signature']
            missing_fields = [field for field in required_fields if field not in manifest]
            
            if missing_fields:
                alerts.append(SecurityAlert(
                    SecurityRisk.MEDIUM,
                    f"Missing provenance information: {', '.join(missing_fields)}",
                    "Ensure model includes complete provenance metadata"
                ))
                
            # Verify digital signatures if present
            if 'signature' in manifest:
                if not self._verify_signature(manifest):
                    alerts.append(SecurityAlert(
                        SecurityRisk.HIGH,
                        "Invalid model signature detected",
                        "Model may have been tampered with or corrupted"
                    ))
                    
        except Exception as e:
            logger.error(f"Failed to verify model provenance: {str(e)}")
            logger.debug(traceback.format_exc())
            alerts.append(SecurityAlert(
                SecurityRisk.HIGH,
                f"Failed to verify model provenance: {str(e)}",
                "Ensure manifest file is valid and accessible"
            ))
        return alerts

    def check_model_permissions(self) -> List[SecurityAlert]:
        """Check for proper file permissions and ownership"""
        alerts = []
        try:
            if not os.path.exists(self.model_path):
                alerts.append(SecurityAlert(
                    SecurityRisk.HIGH,
                    f"Model path not found: {self.model_path}",
                    "Verify model path and permissions"
                ))
                return alerts
                
            for root, dirs, files in os.walk(self.model_path):
                for item in dirs + files:
                    path = os.path.join(root, item)
                    try:
                        stats = os.stat(path)
                        
                        # Check for world-writable permissions
                        if stats.st_mode & 0o002:
                            alerts.append(SecurityAlert(
                                SecurityRisk.HIGH,
                                f"World-writable permissions detected: {path}",
                                "Remove world-writable permissions"
                            ))
                            
                        # Check for proper ownership
                        if stats.st_uid == 0:  # Root ownership
                            alerts.append(SecurityAlert(
                                SecurityRisk.MEDIUM,
                                f"Root-owned file detected: {path}",
                                "Review file ownership"
                            ))
                            
                    except Exception as e:
                        logger.error(f"Failed to check permissions for {path}: {str(e)}")
                        alerts.append(SecurityAlert(
                            SecurityRisk.MEDIUM,
                            f"Failed to check permissions for {path}: {str(e)}",
                            "Ensure proper file access"
                        ))
                    
        except Exception as e:
            logger.error(f"Error checking model permissions: {str(e)}")
            logger.debug(traceback.format_exc())
        return alerts

    def check_resource_limits(self) -> List[SecurityAlert]:
        """Check and enforce resource usage limits"""
        alerts = []
        try:
            # Memory usage check
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                alerts.append(SecurityAlert(
                    SecurityRisk.HIGH,
                    f"High memory usage detected: {memory.percent}%",
                    "Implement memory limits and monitoring"
                ))
                
            # CPU usage check
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                alerts.append(SecurityAlert(
                    SecurityRisk.MEDIUM,
                    f"High CPU usage detected: {cpu_percent}%",
                    "Implement CPU throttling if necessary"
                ))
                
            # Disk usage check
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                alerts.append(SecurityAlert(
                    SecurityRisk.MEDIUM,
                    f"Low disk space: {disk.percent}% used",
                    "Clean up unnecessary files or expand storage"
                ))
                
        except Exception as e:
            logger.error(f"Error checking resource limits: {str(e)}")
            logger.debug(traceback.format_exc())
        return alerts

    def scan_for_vulnerabilities(self) -> List[SecurityAlert]:
        """Comprehensive security scan of the model"""
        all_alerts = []
        
        try:
            # 1. Check file signatures and malware
            logger.info("Checking file signatures...")
            all_alerts.extend(self.check_file_signatures(self.model_path))
            
            # 2. Verify network isolation
            logger.info("Checking network isolation...")
            all_alerts.extend(self.check_network_isolation())
            
            # 3. Verify model provenance
            logger.info("Verifying model provenance...")
            manifest_path = os.path.join(self.model_path, "manifest.json")
            if os.path.exists(manifest_path):
                all_alerts.extend(self.verify_model_provenance(manifest_path))
            
            # 4. Check permissions
            logger.info("Checking file permissions...")
            all_alerts.extend(self.check_model_permissions())
            
            # 5. Check resource usage
            logger.info("Checking resource usage...")
            all_alerts.extend(self.check_resource_limits())
            
        except Exception as e:
            logger.error(f"Error during vulnerability scan: {str(e)}")
            logger.debug(traceback.format_exc())
            all_alerts.append(SecurityAlert(
                SecurityRisk.HIGH,
                f"Scan failed: {str(e)}",
                "Review logs for detailed error information"
            ))
            
        return all_alerts

    def generate_security_report(self) -> str:
        """Generate a detailed security report"""
        try:
            alerts = self.scan_for_vulnerabilities()
            
            report = ["=== Model Security Scan Report ===\n"]
            report.append(f"Scan Time: {datetime.now()}\n")
            report.append(f"Model Path: {self.model_path}\n\n")
            
            # Group alerts by risk level
            risk_groups = {
                SecurityRisk.HIGH: [],
                SecurityRisk.MEDIUM: [],
                SecurityRisk.LOW: []
            }
            
            for alert in alerts:
                risk_groups[alert.risk_level].append(alert)
                
            # Add alerts to report
            for risk_level in SecurityRisk:
                alerts = risk_groups[risk_level]
                if alerts:
                    report.append(f"\n{risk_level.value} Risk Alerts:")
                    for idx, alert in enumerate(alerts, 1):
                        report.append(f"\n{idx}. {alert.description}")
                        report.append(f"   Recommendation: {alert.recommendation}")
                        
            return "\n".join(report)
            
        except Exception as e:
            logger.error(f"Error generating security report: {str(e)}")
            logger.debug(traceback.format_exc())
            return f"Failed to generate security report: {str(e)}"

class SecurityMonitor:
    """Monitor and control execution of system commands."""
    
    @staticmethod
    def is_safe_command(cmd_args):
        """Check if a command is in the safe list."""
        if isinstance(cmd_args, (list, tuple)):
            cmd = ' '.join(cmd_args)
        else:
            cmd = str(cmd_args)
        
        return any(safe_cmd in cmd for safe_cmd in SAFE_COMMANDS)

def run_safe_command(cmd_args, **kwargs):
    """Run a command only if it's in the safe list."""
    if SecurityMonitor.is_safe_command(cmd_args):
        return subprocess.run(cmd_args, **kwargs)
    else:
        print(f"[ALERT] Blocked unsafe command: {cmd_args}")
        return None

def list_available_models() -> List[str]:
    """List all available Ollama models."""
    models = []
    manifests_dir = os.path.join(OLLAMA_MODEL_PATH, "manifests")
    
    if not os.path.exists(manifests_dir):
        print(f"[ERROR] Ollama manifests directory not found at {manifests_dir}")
        return models

    try:
        # First try using ollama list command
        result = run_safe_command(["ollama", "list"], capture_output=True, text=True)
        if result and result.returncode == 0:
            lines = result.stdout.strip().split('\n')[1:]  # Skip header line
            for line in lines:
                if line.strip():
                    model_name = line.split()[0]
                    models.append(model_name)
        else:
            raise Exception("ollama list command failed")
    except Exception:
        # Fallback to reading manifests directory
        registry_dir = os.path.join(manifests_dir, "registry.ollama.ai")
        if os.path.exists(registry_dir):
            for namespace in os.listdir(registry_dir):
                namespace_path = os.path.join(registry_dir, namespace)
                if os.path.isdir(namespace_path):
                    for model_dir in os.listdir(namespace_path):
                        if namespace == "library":
                            models.append(model_dir)
                        else:
                            models.append(f"{namespace}/{model_dir}")
    
    return sorted(models)

def verify_model_integrity(model_path):
    """Verify if the model file has been tampered with by checking its SHA256 hash."""
    sha256 = hashlib.sha256()
    try:
        with open(model_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        print(f"[INFO] Model SHA256: {file_hash}")
    except Exception as e:
        print(f"[ERROR] Failed to read model file: {e}")

def inspect_model_metadata(model_path):
    """Inspect model metadata for suspicious configurations."""
    try:
        with open(model_path, 'r') as f:
            manifest = json.load(f)
            print("[INFO] Model manifest found:")
            print(f"- Name: {manifest.get('name', 'unknown')}")
            print(f"- Format: {manifest.get('format', 'unknown')}")
            print(f"- Architecture: {manifest.get('architecture', 'unknown')}")
            print(f"- License: {manifest.get('license', 'unknown')}")
            
            # Check for suspicious configurations
            if 'config' in manifest:
                config = manifest['config']
                if 'Entrypoint' in config or 'Cmd' in config:
                    print("[ALERT] Model contains executable commands in configuration!")
                    print(f"- Entrypoint: {config.get('Entrypoint', 'None')}")
                    print(f"- Command: {config.get('Cmd', 'None')}")
    except Exception as e:
        print(f"[WARNING] Could not read model metadata: {e}")

def check_suspicious_files(model_dir):
    """Check for suspicious or unexpected files in the model directory."""
    suspicious_extensions = {'.exe', '.sh', '.py', '.js', '.php'}
    for root, _, files in os.walk(model_dir):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in suspicious_extensions:
                print(f"[ALERT] Suspicious file found: {os.path.join(root, file)}")

def audit_dependencies():
    """Check installed Python dependencies for known vulnerabilities."""
    print("[INFO] Auditing Python dependencies for potential security issues...")
    try:
        # Use the virtual environment's pip
        result = run_safe_command([sys.executable, "-m", "pip", "list", "--format=freeze"], 
                                capture_output=True, text=True)
        if not result:
            print("[WARNING] Skipping dependency audit - command blocked")
            return
            
        if result.returncode != 0:
            print(f"[ERROR] Failed to list dependencies: {result.stderr}")
            return
            
        packages = result.stdout.split('\n')
        for package in packages:
            if package:
                pkg_name = package.split("==")[0]
                try:
                    response = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=5)
                    if response.status_code == 200:
                        latest_version = response.json().get("info", {}).get("version", "unknown")
                        current_version = package.split("==")[-1]
                        if latest_version != current_version:
                            print(f"[WARNING] {pkg_name} {current_version} is outdated! Latest: {latest_version}")
                except requests.exceptions.RequestException:
                    print(f"[WARNING] Could not check version for {pkg_name}")
    except Exception as e:
        print(f"[ERROR] Failed to audit dependencies: {e}")

def verify_model_files(model_name: str) -> bool:
    """Verify if all required model files are present and intact."""
    # Split model name and tag
    if ':' in model_name:
        base_name, tag = model_name.split(':', 1)
    else:
        base_name = model_name
        tag = 'latest'
    
    manifests_dir = os.path.join(OLLAMA_MODEL_PATH, "manifests", "registry.ollama.ai")
    blobs_dir = os.path.join(OLLAMA_MODEL_PATH, "blobs")
    
    # Check model path
    if "/" in base_name:
        namespace, name = base_name.split("/", 1)
    else:
        namespace = "library"
        name = base_name
        
    manifest_file = os.path.join(manifests_dir, namespace, name, tag)
    
    if not os.path.exists(manifest_file):
        print(f"[ERROR] Model manifest not found: {manifest_file}")
        return False
        
    # Verify manifest
    try:
        with open(manifest_file, 'r') as f:
            manifest = json.load(f)
            print(f"\n[INFO] Model Details:")
            print(f"- Name: {name}")
            print(f"- Tag: {tag}")
            print(f"- Schema Version: {manifest.get('schemaVersion', 'unknown')}")
            print(f"- Media Type: {manifest.get('mediaType', 'unknown')}")
            print(f"- Model Path: {manifest_file}")
            
            # Calculate manifest file hash
            sha256_hash = hashlib.sha256()
            with open(manifest_file, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            print(f"- Manifest SHA256: {sha256_hash.hexdigest()}")
            
            # Verify config
            if 'config' in manifest:
                config_hash = manifest['config']['digest'].split(':')[1]
                config_path = os.path.join(blobs_dir, f"sha256-{config_hash}")
                if os.path.exists(config_path):
                    print(f"✓ Config file verified ({os.path.getsize(config_path)} bytes)")
                else:
                    print(f"✗ Config file missing: {config_path}")
                    return False
            
            # Verify all required blobs exist
            if 'layers' in manifest:
                print("\n[INFO] Verifying model layers...")
                total_size = 0
                for idx, layer in enumerate(manifest['layers']):
                    if 'digest' in layer:
                        # Extract the hash part from sha256:hash format
                        blob_hash = layer['digest'].split(':')[1]
                        blob_path = os.path.join(blobs_dir, f"sha256-{blob_hash}")
                        
                        if os.path.exists(blob_path):
                            size_mb = os.path.getsize(blob_path) / (1024 * 1024)
                            total_size += size_mb
                            
                            # Calculate blob hash
                            sha256_hash = hashlib.sha256()
                            with open(blob_path, "rb") as f:
                                for byte_block in iter(lambda: f.read(4096), b""):
                                    sha256_hash.update(byte_block)
                            actual_digest = sha256_hash.hexdigest()
                            
                            # Verify blob integrity
                            if actual_digest == blob_hash:
                                print(f"  ✓ Layer {idx + 1}: {layer['mediaType']} ({size_mb:.1f} MB) [Verified]")
                            else:
                                print(f"  ⚠️ Layer {idx + 1}: {layer['mediaType']} ({size_mb:.1f} MB) [Hash Mismatch!]")
                                print(f"    Expected: {blob_hash}")
                                print(f"    Actual:   {actual_digest}")
                                return False
                        else:
                            print(f"  ✗ Layer {idx + 1}: {layer['mediaType']} (Missing)")
                            print(f"    Expected Path: {blob_path}")
                            return False
                print(f"\nTotal model size: {total_size/1024:.2f} GB")
    except Exception as e:
        print(f"[ERROR] Failed to verify model files: {e}")
        return False
        
    return True

def test_model_inference(model_name: str, monitor: ModelMonitor):
    """Test model inference with a simple prompt."""
    print("\n[INFO] Testing model inference...")
    
    test_prompt = "Respond with exactly 3 words: Hello, I'm working."
    try:
        monitor.start_monitoring()
        
        # Run model inference
        cmd = ["ollama", "run", model_name, test_prompt]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("[INFO] Model inference test successful")
            print(f"Response: {result.stdout.strip()}")
        else:
            print(f"[ERROR] Model inference test failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[ERROR] Model inference test timed out")
    except Exception as e:
        print(f"[ERROR] Model inference test failed: {e}")
    finally:
        stats = monitor.stop_monitoring()
        
        # Report monitoring results
        print("\n[INFO] Runtime Monitoring Results:")
        if stats['memory_usage']:
            avg_mem = sum(stats['memory_usage']) / len(stats['memory_usage'])
            print(f"- Average Memory Usage: {avg_mem:.1f} MB")
        if stats['cpu_usage']:
            avg_cpu = sum(stats['cpu_usage']) / len(stats['cpu_usage'])
            print(f"- Average CPU Usage: {avg_cpu:.1f}%")
        if stats['network_connections']:
            print(f"- Network Connections: {len(stats['network_connections'])}")
            for conn in stats['network_connections']:
                print(f"  - {conn}")
        if stats['suspicious_activities']:
            print("\n[ALERT] Suspicious Activities Detected:")
            for activity in stats['suspicious_activities']:
                print(f"  - {activity}")

def scan_ollama_models(model_name: Optional[str] = None):
    """Scan specified or all models in the Ollama model directory."""
    print("\n🔍 Starting Ollama model security scan...\n")
    
    available_models = list_available_models()
    
    if not available_models:
        print("[ERROR] No Ollama models found")
        return
        
    if model_name:
        if model_name not in available_models:
            print(f"[ERROR] Model '{model_name}' not found. Available models:")
            for model in available_models:
                print(f"  - {model}")
            return
        models_to_scan = [model_name]
    else:
        models_to_scan = available_models
        print("Available models:")
        for model in available_models:
            print(f"  - {model}")
        print("\nScanning all models...\n")

    for model in models_to_scan:
        print(f"\n[INFO] Scanning model: {model}")
        
        # Verify model files
        if not verify_model_files(model):
            print(f"[ERROR] Model verification failed for {model}")
            continue
            
        # Create model monitor
        monitor = ModelMonitor(model)
        
        # Test model inference
        test_model_inference(model, monitor)
        
        # Check for suspicious files
        if "/" in model:
            namespace, name = model.split("/", 1)
        else:
            namespace = "library"
            name = model
            
        model_path = os.path.join(OLLAMA_MODEL_PATH, "manifests", "registry.ollama.ai", namespace, name)
        check_suspicious_files(model_path)
        
        # Perform additional security checks
        scanner = ModelSecurityScanner(model_path)
        report = scanner.generate_security_report()
        print(report)

    # Run dependency audit at the end
    audit_dependencies()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Ollama Model Security Scanner')
    parser.add_argument('-l', '--list', action='store_true',
                      help='List available Ollama models')
    parser.add_argument('-m', '--model',
                      help='Specify a model to scan. If not provided, all models will be scanned.')
    return parser.parse_args()

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    try:
        # Activate virtual environment
        activate_script = VENV_PATH
        if not os.path.exists(activate_script):
            print(f"[ERROR] Virtual environment not found at {activate_script}")
            sys.exit(1)
            
        args = parse_arguments()
        
        if args.list:
            print("\nAvailable Ollama models:")
            for model in list_available_models():
                print(f"  - {model}")
        else:
            scan_ollama_models(args.model)
            print("\n✅ Security scan completed. Please review the alerts and warnings.")
    except Exception as e:
        print(f"\n❌ Scan failed with error: {e}")
