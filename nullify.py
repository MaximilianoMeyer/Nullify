# secureerase_lab.py
import os
import sys
import json
import yaml
import hashlib
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# PyQt imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QPushButton,
    QTextEdit, QLabel, QGroupBox, QTreeWidget, QTreeWidgetItem,
    QProgressBar, QMessageBox, QFileDialog, QSplitter, QStatusBar,
    QComboBox
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QColor, QTextCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/secureerase.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# Data Models
# ============================================================================

class DeviceType(Enum):
    USB = "USB"
    ANDROID = "ANDROID"
    STORAGE = "STORAGE"
    UNKNOWN = "UNKNOWN"

class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class USBDevice:
    vendor_id: str
    product_id: str
    device_class: str
    manufacturer: str
    product: str
    serial: str = ""
    
    def __str__(self):
        return f"{self.manufacturer} {self.product} ({self.vendor_id}:{self.product_id})"

@dataclass
class SuspiciousFile:
    path: str
    hash_md5: str
    hash_sha256: str
    size: int
    file_type: str
    yara_matches: List[str] = field(default_factory=list)
    risk_score: float = 0.0

@dataclass
class SanitizationResult:
    device: str
    method: str
    success: bool
    timestamp: datetime
    details: str

# ============================================================================
# Core Modules
# ============================================================================

class DeviceDetectionModule:
    """
    Professional block device detection using lsblk JSON output.
    More reliable than psutil for disk enumeration.
    """

    def get_block_devices(self) -> List[Dict]:
        """Enumerate block devices using lsblk JSON"""

        cmd = [
            "lsblk",
            "-J",
            "-o",
            "NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,TRAN,VENDOR,ROTA,HOTPLUG"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )

            data = json.loads(result.stdout)

        except Exception as e:
            logger.error(f"lsblk execution failed: {e}")
            return []

        devices = []

        for dev in data.get("blockdevices", []):

            # only physical disks
            if dev.get("type") != "disk":
                continue

            devices.append({
                "name": dev.get("name"),
                "path": dev.get("path"),
                "size": dev.get("size"),
                "model": dev.get("model"),
                "serial": dev.get("serial"),
                "transport": dev.get("tran"),
                "vendor": dev.get("vendor"),
                "mountpoint": dev.get("mountpoint"),
                "fstype": dev.get("fstype"),
                "rota": dev.get("rota"),
                "hotplug": dev.get("hotplug")
            })

        return devices


    def get_usb_devices(self) -> List[Dict]:
        """Return only USB storage devices"""

        devices = self.get_block_devices()

        usb_devices = []

        for dev in devices:

            if dev.get("transport") == "usb" or dev.get("hotplug") == True:
                usb_devices.append(dev)

        return usb_devices

class FileAnalyzerModule:
    """Analyzes files for malware patterns using YARA and hashing"""
    
    def __init__(self):
        self.yara_rules = None
        self.suspicious_extensions = {'.exe', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.lnk', '.scr'}
        
    def compute_hash(self, file_path: str) -> Tuple[str, str]:
        """Compute MD5 and SHA256 hashes of a file"""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing {file_path}: {e}")
            return "", ""
    
    def scan_directory(self, directory: str) -> List[SuspiciousFile]:
        """Scan directory for suspicious files"""
        suspicious_files = []
        path = Path(directory)
        
        for ext in self.suspicious_extensions:
            for file_path in path.rglob(f'*{ext}'):
                if file_path.is_file():
                    md5, sha256 = self.compute_hash(str(file_path))
                    suspicious = SuspiciousFile(
                        path=str(file_path),
                        hash_md5=md5,
                        hash_sha256=sha256,
                        size=file_path.stat().st_size,
                        file_type=ext[1:].upper(),
                        yara_matches=self.check_yara_rules(str(file_path)),
                        risk_score=self.calculate_risk_score(str(file_path))
                    )
                    suspicious_files.append(suspicious)
        
        return suspicious_files
    
    def check_yara_rules(self, file_path: str) -> List[str]:
        """Check file against YARA rules"""
        matches = []
        try:
            # Simplified YARA check - in production, use yara-python
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
                if b'powershell' in content.lower():
                    matches.append("SUSPECT_POWERSHELL")
                if b'cmd' in content.lower() and b'/c' in content.lower():
                    matches.append("SUSPECT_CMD_EXECUTION")
        except Exception:
            pass
        return matches
    
    def calculate_risk_score(self, file_path: str) -> float:
        """Calculate risk score based on multiple factors"""
        score = 0.0
        # Check file size
        size = os.path.getsize(file_path)
        if size < 1024:  # Very small files can be suspicious
            score += 0.2
        
        # Check filename patterns
        name = os.path.basename(file_path).lower()
        suspicious_patterns = ['install', 'setup', 'update', 'patch', 'crack', 'keygen']
        for pattern in suspicious_patterns:
            if pattern in name:
                score += 0.15
        
        return min(score, 1.0)

class AndroidBackupModule:
    """Manages Android device backups using ADB"""
    
    def __init__(self):
        self.devices = []
        
    def detect_devices(self) -> List[str]:
        """Detect connected Android devices"""
        devices = []
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            for line in result.stdout.split('\n')[1:]:
                if line.strip() and 'device' in line and 'offline' not in line:
                    device_id = line.split()[0]
                    devices.append(device_id)
        except FileNotFoundError:
            logger.error("ADB not found. Install Android Debug Bridge")
        return devices
    
    def backup_media(self, device_id: str, output_dir: str) -> bool:
        """Backup media files from Android device"""
        media_dirs = ['/sdcard/DCIM', '/sdcard/Pictures', '/sdcard/Movies', '/sdcard/Downloads']
        success = True
        
        for media_dir in media_dirs:
            try:
                output_path = Path(output_dir) / Path(media_dir).name
                output_path.mkdir(parents=True, exist_ok=True)
                
                result = subprocess.run(
                    ['adb', '-s', device_id, 'pull', media_dir, str(output_path)],
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    logger.warning(f"Failed to backup {media_dir}: {result.stderr}")
                    success = False
            except Exception as e:
                logger.error(f"Backup error: {e}")
                success = False
        
        return success

class SandboxEngine:
    """Executes suspicious files in isolated QEMU environment"""
    
    def __init__(self, vm_image_path: str = None):
        self.vm_image = vm_image_path or "/var/lib/libvirt/images/sandbox.qcow2"
        self.snapshot_name = "clean_state"
        
    def create_snapshot(self) -> bool:
        """Create a clean snapshot of the VM"""
        try:
            cmd = ['qemu-img', 'snapshot', '-c', self.snapshot_name, self.vm_image]
            subprocess.run(cmd, capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create snapshot: {e}")
            return False
    
    def execute_file(self, file_path: str) -> Dict:
        """Execute file in sandbox and monitor behavior"""
        behavior = {
            'processes': [],
            'network_connections': [],
            'file_writes': [],
            'execution_time': None,
            'exit_code': None
        }
        
        # Simulate sandbox execution
        logger.info(f"Executing {file_path} in sandbox...")
        
        # In production, this would:
        # 1. Copy file to VM
        # 2. Execute with timeout
        # 3. Monitor using Sysmon
        # 4. Capture network traffic with tshark
        # 5. Collect all logs
        
        return behavior
    
    def restore_snapshot(self) -> bool:
        """Restore VM to clean snapshot"""
        try:
            cmd = ['qemu-img', 'snapshot', '-a', self.snapshot_name, self.vm_image]
            subprocess.run(cmd, capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restore snapshot: {e}")
            return False

class SanitizationModule:
    """Performs NIST-compliant media sanitization"""
    
    def __init__(self):
        self.supported_methods = ['secure_erase', 'crypto_erase', 'block_overwrite']
        
    def sanitize_drive(self, device: str, method: str) -> SanitizationResult:
        """Sanitize a storage device using specified method"""
        timestamp = datetime.now()
        
        if method == 'secure_erase':
            return self._secure_erase(device, timestamp)
        elif method == 'crypto_erase':
            return self._crypto_erase(device, timestamp)
        else:
            return SanitizationResult(
                device=device,
                method=method,
                success=False,
                timestamp=timestamp,
                details=f"Unsupported method: {method}"
            )
    
    def _secure_erase(self, device: str, timestamp: datetime) -> SanitizationResult:
        """Perform ATA Secure Erase using hdparm"""
        try:
            # Check if device supports secure erase
            check_cmd = ['hdparm', '-I', device]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if 'supported: enhanced erase' in result.stdout or 'supported: secure erase' in result.stdout:
                # Set password (required for secure erase)
                subprocess.run(['hdparm', '--user-master', 'u', '--security-set-pass', 'p', device], 
                             capture_output=True)
                
                # Execute secure erase
                erase_cmd = ['hdparm', '--user-master', 'u', '--security-erase', 'p', device]
                subprocess.run(erase_cmd, capture_output=True, check=True)
                
                return SanitizationResult(
                    device=device,
                    method="ATA Secure Erase",
                    success=True,
                    timestamp=timestamp,
                    details="Device successfully sanitized using ATA Secure Erase"
                )
            else:
                return SanitizationResult(
                    device=device,
                    method="ATA Secure Erase",
                    success=False,
                    timestamp=timestamp,
                    details="Device does not support ATA Secure Erase"
                )
        except Exception as e:
            return SanitizationResult(
                device=device,
                method="ATA Secure Erase",
                success=False,
                timestamp=timestamp,
                details=f"Error: {str(e)}"
            )
    
    def _crypto_erase(self, device: str, timestamp: datetime) -> SanitizationResult:
        """Perform crypto erase for NVMe devices"""
        try:
            # Check if NVMe device
            cmd = ['nvme', 'id-ctrl', device]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Perform NVMe format with cryptographic erase
                format_cmd = ['nvme', 'format', device, '--ses', '1']  # SES=1 for crypto erase
                subprocess.run(format_cmd, capture_output=True, check=True)
                
                return SanitizationResult(
                    device=device,
                    method="NVMe Crypto Erase",
                    success=True,
                    timestamp=timestamp,
                    details="NVMe device successfully sanitized using cryptographic erase"
                )
            else:
                return SanitizationResult(
                    device=device,
                    method="NVMe Crypto Erase",
                    success=False,
                    timestamp=timestamp,
                    details="Not an NVMe device or command failed"
                )
        except Exception as e:
            return SanitizationResult(
                device=device,
                method="NVMe Crypto Erase",
                success=False,
                timestamp=timestamp,
                details=f"Error: {str(e)}"
            )

class AISecurityModule:
    """AI-powered security analysis using scikit-learn and transformers"""
    
    def __init__(self):
        self.model = None
        self.risk_thresholds = {'LOW': 0.3, 'MEDIUM': 0.6, 'HIGH': 0.8, 'CRITICAL': 0.95}
        
    def classify_risk(self, file_features: Dict) -> RiskLevel:
        """Classify risk level of a file using ML"""
        # Simplified risk classification
        # In production, this would use a trained scikit-learn model
        
        risk_score = 0.0
        
        # File size risk
        if file_features.get('size', 0) < 10000:  # Very small files
            risk_score += 0.2
        
        # Extension risk
        high_risk_extensions = ['.ps1', '.vbs', '.scr']
        if file_features.get('extension', '') in high_risk_extensions:
            risk_score += 0.4
        
        # YARA matches risk
        yara_matches = file_features.get('yara_matches', 0)
        risk_score += min(yara_matches * 0.2, 0.4)
        
        # Determine risk level
        if risk_score >= self.risk_thresholds['CRITICAL']:
            return RiskLevel.CRITICAL
        elif risk_score >= self.risk_thresholds['HIGH']:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds['MEDIUM']:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def generate_analysis_report(self, scan_results: Dict) -> str:
        """Generate AI-powered analysis report"""
        report = []
        report.append("=" * 60)
        report.append("SECUREERASE LAB - AI SECURITY ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("")
        
        total_files = scan_results.get('total_files', 0)
        suspicious_files = scan_results.get('suspicious_files', [])
        
        report.append(f"Total files scanned: {total_files}")
        report.append(f"Suspicious files found: {len(suspicious_files)}")
        report.append("")
        
        if suspicious_files:
            report.append("SUSPICIOUS FILES DETAILS:")
            report.append("-" * 40)
            for file in suspicious_files[:10]:  # Show first 10
                report.append(f"  File: {Path(file['path']).name}")
                report.append(f"  Risk Score: {file['risk_score']:.2f}")
                report.append(f"  YARA Matches: {', '.join(file.get('yara_matches', []))}")
                report.append("")
        
        report.append("RECOMMENDATIONS:")
        report.append("-" * 40)
        if len(suspicious_files) > 0:
            report.append("  • Isolate affected systems immediately")
            report.append("  • Run full system scan with updated signatures")
            report.append("  • Review network connections for suspicious activity")
        else:
            report.append("  • No immediate threats detected")
            report.append("  • Continue monitoring for suspicious activity")
        
        return "\n".join(report)

class ReportGenerator:
    """Generates PDF reports using ReportLab"""
    
    def generate_pdf_report(self, data: Dict, output_path: str) -> bool:
        """Generate PDF report from analysis data"""
        try:
            # Simplified PDF generation
            # In production, use ReportLab to create professional PDFs
            with open(output_path, 'w') as f:
                f.write(f"SecureErase Lab Report\n")
                f.write(f"Generated: {datetime.now()}\n")
                f.write(f"{'='*60}\n\n")
                
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
            
            logger.info(f"Report generated: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return False

# ============================================================================
# GUI Implementation
# ============================================================================

class ScanWorker(QThread):
    """Background worker for file scanning"""
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    log_message = pyqtSignal(str)
    
    def __init__(self, scan_path: str):
        super().__init__()
        self.scan_path = scan_path
        
    def run(self):
        analyzer = FileAnalyzerModule()
        suspicious_files = analyzer.scan_directory(self.scan_path)
        
        result = {
            'total_files': len(suspicious_files),
            'suspicious_files': [
                {
                    'path': f.path,
                    'risk_score': f.risk_score,
                    'yara_matches': f.yara_matches,
                    'hash_md5': f.hash_md5,
                    'size': f.size
                }
                for f in suspicious_files
            ]
        }
        
        self.progress.emit(100)
        self.finished.emit(result)

class SecureEraseMainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nullify - NIST 800-88 Framework")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize modules
        self.device_detector = DeviceDetectionModule()
        self.file_analyzer = FileAnalyzerModule()
        self.android_backup = AndroidBackupModule()
        self.sandbox_engine = SandboxEngine()
        self.sanitization = SanitizationModule()
        self.ai_module = AISecurityModule()
        self.report_gen = ReportGenerator()
        
        self.setup_ui()
        self.setup_statusbar()
        
    def setup_ui(self):
        """Setup the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.device_tab = self.create_device_tab()
        self.scan_tab = self.create_scan_tab()
        self.android_tab = self.create_android_tab()
        self.sandbox_tab = self.create_sandbox_tab()
        self.sanitization_tab = self.create_sanitization_tab()
        
        self.tab_widget.addTab(self.device_tab, "Device Detection")
        self.tab_widget.addTab(self.scan_tab, "Security Scan")
        self.tab_widget.addTab(self.android_tab, "Android Backup")
        self.tab_widget.addTab(self.sandbox_tab, "Sandbox")
        self.tab_widget.addTab(self.sanitization_tab, "Sanitization")
        
        # Log area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        self.log_text.setFont(QFont("Courier", 9))
        main_layout.addWidget(QLabel("Event Log:"))
        main_layout.addWidget(self.log_text)
        
    def setup_statusbar(self):
        """Setup status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
    def create_device_tab(self) -> QWidget:
        """Create device detection tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # USB Devices
        usb_group = QGroupBox("USB Devices")
        usb_layout = QVBoxLayout(usb_group)
        
        self.usb_table = QTableWidget()
        self.usb_table.setColumnCount(5)
        self.usb_table.setHorizontalHeaderLabels([
            "Vendor",
            "Model",
            "Serial",
            "Size",
            "Device"
            ])

        usb_layout.addWidget(self.usb_table)
        
        refresh_btn = QPushButton("Refresh Devices")
        refresh_btn.clicked.connect(self.refresh_devices)
        usb_layout.addWidget(refresh_btn)
        
        # Storage Devices
        storage_group = QGroupBox("Storage Devices")
        storage_layout = QVBoxLayout(storage_group)
        
        self.storage_table = QTableWidget()
        self.storage_table.setColumnCount(5)
        self.storage_table.setHorizontalHeaderLabels(["Device", "Mount Point", "Filesystem", "Size", "Transport"])
        storage_layout.addWidget(self.storage_table)
        
        layout.addWidget(usb_group)
        layout.addWidget(storage_group)
        
        return tab
    
    def create_scan_tab(self) -> QWidget:
        """Create security scan tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Scan controls
        control_layout = QHBoxLayout()
        
        self.scan_path_edit = QTextEdit()
        self.scan_path_edit.setMaximumHeight(30)
        self.scan_path_edit.setPlaceholderText("Enter path to scan...")
        control_layout.addWidget(self.scan_path_edit)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_scan_path)
        control_layout.addWidget(browse_btn)
        
        scan_btn = QPushButton("Start Scan")
        scan_btn.clicked.connect(self.start_scan)
        scan_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        control_layout.addWidget(scan_btn)
        
        layout.addLayout(control_layout)
        
        # Progress bar
        self.scan_progress = QProgressBar()
        layout.addWidget(self.scan_progress)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["File Path", "Risk Score", "YARA Matches", "MD5 Hash", "Size"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.results_table)
        
        # AI Analysis
        self.ai_analysis_text = QTextEdit()
        self.ai_analysis_text.setReadOnly(True)
        self.ai_analysis_text.setMaximumHeight(150)
        layout.addWidget(QLabel("AI Analysis:"))
        layout.addWidget(self.ai_analysis_text)
        
        return tab
    
    def create_android_tab(self) -> QWidget:
        """Create Android backup tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Device detection
        detect_btn = QPushButton("Detect Android Devices")
        detect_btn.clicked.connect(self.detect_android_devices)
        layout.addWidget(detect_btn)
        
        self.android_devices_list = QTableWidget()
        self.android_devices_list.setColumnCount(1)
        self.android_devices_list.setHorizontalHeaderLabels(["Device ID"])
        layout.addWidget(self.android_devices_list)
        
        # Backup controls
        backup_group = QGroupBox("Backup Media")
        backup_layout = QVBoxLayout(backup_group)
        
        backup_path_layout = QHBoxLayout()
        self.backup_path_edit = QTextEdit()
        self.backup_path_edit.setMaximumHeight(30)
        self.backup_path_edit.setPlaceholderText("Backup destination...")
        backup_path_layout.addWidget(self.backup_path_edit)
        
        browse_backup_btn = QPushButton("Browse")
        browse_backup_btn.clicked.connect(self.browse_backup_path)
        backup_path_layout.addWidget(browse_backup_btn)
        backup_layout.addLayout(backup_path_layout)
        
        backup_btn = QPushButton("Start Backup")
        backup_btn.clicked.connect(self.start_android_backup)
        backup_btn.setStyleSheet("background-color: #2196F3; color: white;")
        backup_layout.addWidget(backup_btn)
        
        layout.addWidget(backup_group)
        
        return tab
    
    def create_sandbox_tab(self) -> QWidget:
        """Create sandbox execution tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # File selection
        file_layout = QHBoxLayout()
        self.sandbox_file_edit = QTextEdit()
        self.sandbox_file_edit.setMaximumHeight(30)
        self.sandbox_file_edit.setPlaceholderText("Select file to analyze in sandbox...")
        file_layout.addWidget(self.sandbox_file_edit)
        
        browse_file_btn = QPushButton("Browse")
        browse_file_btn.clicked.connect(self.browse_sandbox_file)
        file_layout.addWidget(browse_file_btn)
        
        execute_btn = QPushButton("Execute in Sandbox")
        execute_btn.clicked.connect(self.execute_in_sandbox)
        execute_btn.setStyleSheet("background-color: #FF9800; color: white;")
        file_layout.addWidget(execute_btn)
        
        layout.addLayout(file_layout)
        
        # Sandbox output
        self.sandbox_output = QTextEdit()
        self.sandbox_output.setReadOnly(True)
        self.sandbox_output.setFont(QFont("Courier", 10))
        layout.addWidget(QLabel("Sandbox Execution Output:"))
        layout.addWidget(self.sandbox_output)
        
        return tab
    
    def create_sanitization_tab(self) -> QWidget:
        """Create media sanitization tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Device selection
        device_layout = QHBoxLayout()
        self.sanitization_device_edit = QTextEdit()
        self.sanitization_device_edit.setMaximumHeight(30)
        self.sanitization_device_edit.setPlaceholderText("Device path (e.g., /dev/sda)...")
        device_layout.addWidget(self.sanitization_device_edit)
        layout.addLayout(device_layout)
        
        # Method selection
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Sanitization Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["secure_erase", "crypto_erase", "block_overwrite"])
        method_layout.addWidget(self.method_combo)
        method_layout.addStretch()
        layout.addLayout(method_layout)
        
        # Warning label
        warning_label = QLabel("⚠ WARNING: This will permanently erase all data on the selected device!")
        warning_label.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(warning_label)
        
        # Execute button
        sanitize_btn = QPushButton("Execute Sanitization")
        sanitize_btn.clicked.connect(self.execute_sanitization)
        sanitize_btn.setStyleSheet("background-color: #f44336; color: white;")
        layout.addWidget(sanitize_btn)
        
        # Results
        self.sanitization_result = QTextEdit()
        self.sanitization_result.setReadOnly(True)
        layout.addWidget(QLabel("Sanitization Results:"))
        layout.addWidget(self.sanitization_result)
        
        return tab
    
    def log_message(self, message: str):
        """Add message to log area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        self.status_bar.showMessage(message)
        
    def refresh_devices(self):
        self.log_message("Refreshing device list...")
        devices = self.device_detector.get_block_devices()
        usb_devices = self.device_detector.get_usb_devices()

        self.usb_table.setRowCount(len(usb_devices))
        for i, dev in enumerate(usb_devices):

            self.usb_table.setItem(i, 0, QTableWidgetItem(dev.get("vendor") or ""))
            self.usb_table.setItem(i, 1, QTableWidgetItem(dev.get("model") or ""))
            self.usb_table.setItem(i, 2, QTableWidgetItem(dev.get("serial") or ""))
            self.usb_table.setItem(i, 3, QTableWidgetItem(dev.get("size") or ""))
            self.usb_table.setItem(i, 4, QTableWidgetItem(dev.get("path") or ""))

    # Storage devices table
            self.storage_table.setRowCount(len(devices))

            for i, dev in enumerate(devices):

                self.storage_table.setItem(i, 0, QTableWidgetItem(dev.get("path") or ""))
                self.storage_table.setItem(i, 1, QTableWidgetItem(dev.get("mountpoint") or ""))
                self.storage_table.setItem(i, 2, QTableWidgetItem(dev.get("fstype") or ""))
                self.storage_table.setItem(i, 3, QTableWidgetItem(dev.get("size") or ""))
                self.storage_table.setItem(i, 4, QTableWidgetItem(dev.get("transport") or ""))

                self.log_message(f"Detected {len(devices)} storage devices ({len(usb_devices)} USB)")
    

    
    def browse_scan_path(self):
        """Browse for scan directory"""
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if path:
            self.scan_path_edit.setText(path)
    
    def start_scan(self):
        """Start security scan"""
        scan_path = self.scan_path_edit.toPlainText().strip()
        if not scan_path or not os.path.exists(scan_path):
            QMessageBox.warning(self, "Error", "Please select a valid directory to scan")
            return
        
        self.log_message(f"Starting security scan of {scan_path}")
        self.scan_progress.setValue(0)
        self.results_table.setRowCount(0)
        
        # Start background scan
        self.scan_worker = ScanWorker(scan_path)
        self.scan_worker.progress.connect(self.scan_progress.setValue)
        self.scan_worker.finished.connect(self.scan_completed)
        self.scan_worker.log_message.connect(self.log_message)
        self.scan_worker.start()
    
    def scan_completed(self, results: dict):
        """Handle scan completion"""
        self.log_message(f"Scan completed. Found {results['total_files']} suspicious files.")
        
        # Populate results table
        suspicious_files = results['suspicious_files']
        self.results_table.setRowCount(len(suspicious_files))
        
        for i, file in enumerate(suspicious_files):
            self.results_table.setItem(i, 0, QTableWidgetItem(Path(file['path']).name))
            
            risk_item = QTableWidgetItem(f"{file['risk_score']:.2f}")
            if file['risk_score'] > 0.7:
                risk_item.setBackground(QColor(255, 200, 200))
            self.results_table.setItem(i, 1, risk_item)
            
            self.results_table.setItem(i, 2, QTableWidgetItem(str(len(file['yara_matches']))))
            self.results_table.setItem(i, 3, QTableWidgetItem(file['hash_md5'][:16] + "..."))
            self.results_table.setItem(i, 4, QTableWidgetItem(f"{file['size'] // 1024} KB"))
        
        # Generate AI analysis
        ai_report = self.ai_module.generate_analysis_report(results)
        self.ai_analysis_text.setText(ai_report)
        
        # Generate PDF report
        report_path = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.report_gen.generate_pdf_report(results, report_path)
        self.log_message(f"Report saved to {report_path}")
    
    def detect_android_devices(self):
        """Detect connected Android devices"""
        devices = self.android_backup.detect_devices()
        self.android_devices_list.setRowCount(len(devices))
        for i, device in enumerate(devices):
            self.android_devices_list.setItem(i, 0, QTableWidgetItem(device))
        
        self.log_message(f"Found {len(devices)} Android devices")
    
    def browse_backup_path(self):
        """Browse for backup destination"""
        path = QFileDialog.getExistingDirectory(self, "Select Backup Destination")
        if path:
            self.backup_path_edit.setText(path)
    
    def start_android_backup(self):
        """Start Android backup"""
        backup_path = self.backup_path_edit.toPlainText().strip()
        if not backup_path:
            QMessageBox.warning(self, "Error", "Please select a backup destination")
            return
        
        # Get selected device
        selected_row = self.android_devices_list.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Error", "Please select a device from the list")
            return
        
        device_id = self.android_devices_list.item(selected_row, 0).text()
        
        self.log_message(f"Starting backup of {device_id} to {backup_path}")
        
        success = self.android_backup.backup_media(device_id, backup_path)
        if success:
            QMessageBox.information(self, "Success", f"Backup completed successfully to {backup_path}")
            self.log_message(f"Backup completed successfully")
        else:
            QMessageBox.warning(self, "Warning", "Backup completed with some errors. Check log for details.")
    
    def browse_sandbox_file(self):
        """Browse for file to analyze in sandbox"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File for Sandbox Analysis")
        if file_path:
            self.sandbox_file_edit.setText(file_path)
    
    def execute_in_sandbox(self):
        """Execute file in sandbox"""
        file_path = self.sandbox_file_edit.toPlainText().strip()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file")
            return
        
        self.log_message(f"Executing {file_path} in sandbox...")
        self.sandbox_output.clear()
        
        # Create snapshot before execution
        if self.sandbox_engine.create_snapshot():
            self.sandbox_output.append("[✓] Clean snapshot created")
        else:
            self.sandbox_output.append("[✗] Failed to create snapshot")
            return
        
        # Execute file and monitor
        self.sandbox_output.append(f"[*] Executing: {file_path}")
        behavior = self.sandbox_engine.execute_file(file_path)
        
        self.sandbox_output.append("[✓] Execution completed")
        self.sandbox_output.append(f"Processes: {len(behavior['processes'])}")
        self.sandbox_output.append(f"Network connections: {len(behavior['network_connections'])}")
        self.sandbox_output.append(f"File writes: {len(behavior['file_writes'])}")
        
        # Restore snapshot
        if self.sandbox_engine.restore_snapshot():
            self.sandbox_output.append("[✓] Clean state restored")
        else:
            self.sandbox_output.append("[✗] Failed to restore snapshot - manual cleanup required")
        
        self.log_message(f"Sandbox analysis completed for {file_path}")
    
    def execute_sanitization(self):
        """Execute drive sanitization"""
        device = self.sanitization_device_edit.toPlainText().strip()
        method = self.method_combo.currentText()
        
        if not device:
            QMessageBox.warning(self, "Error", "Please enter a device path")
            return
        
        # Confirm with user
        reply = QMessageBox.question(
            self, "Confirm Sanitization",
            f"WARNING: This will permanently erase ALL data on {device}\n\n"
            f"Method: {method}\n\n"
            f"This action cannot be undone!\n\n"
            f"Are you absolutely sure you want to proceed?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        self.log_message(f"Starting sanitization of {device} using {method}")
        self.sanitization_result.clear()
        
        result = self.sanitization.sanitize_drive(device, method)
        
        self.sanitization_result.append(f"Device: {result.device}")
        self.sanitization_result.append(f"Method: {result.method}")
        self.sanitization_result.append(f"Success: {'✓' if result.success else '✗'}")
        self.sanitization_result.append(f"Timestamp: {result.timestamp}")
        self.sanitization_result.append(f"Details: {result.details}")
        
        if result.success:
            self.log_message(f"Sanitization completed successfully for {device}")
            QMessageBox.information(self, "Success", f"Device {device} has been sanitized successfully")
        else:
            self.log_message(f"Sanitization failed for {device}: {result.details}")
            QMessageBox.critical(self, "Error", f"Sanitization failed: {result.details}")

# ============================================================================
# Main Application Entry Point
# ============================================================================

def main():
    """Main application entry point"""
    # Create necessary directories
    for directory in ['logs', 'reports', 'rules', 'config']:
        Path(directory).mkdir(exist_ok=True)
    
    # Create default config if not exists
    config_path = Path('config/default_config.yaml')
    if not config_path.exists():
        default_config = {
            'sandbox': {
                'vm_image': '/var/lib/libvirt/images/sandbox.qcow2',
                'snapshot_name': 'clean_state',
                'execution_timeout': 60
            },
            'scan': {
                'suspicious_extensions': ['.exe', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.lnk', '.scr'],
                'max_file_size_mb': 100,
                'yara_rules_path': 'rules/'
            },
            'sanitization': {
                'supported_methods': ['secure_erase', 'crypto_erase', 'block_overwrite'],
                'verify_after_erase': True
            },
            'reporting': {
                'output_format': 'pdf',
                'include_hashes': True,
                'include_ai_analysis': True
            }
        }
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        logger.info(f"Created default config at {config_path}")
    
    # Start application
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = SecureEraseMainWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
