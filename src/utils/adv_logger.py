# Advanced Logger Module - Halil Berkay Şahin
import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class LogLevel(Enum):
    """Log severity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    VULNERABILITY = "VULNERABILITY"
    SUCCESS = "SUCCESS"


class VulnerabilityType(Enum):
    """Types of vulnerabilities."""

    XSS = "XSS"
    SQLI = "SQL_INJECTION"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    INSECURE_HEADERS = "INSECURE_HEADERS"
    SENSITIVE_FILE = "SENSITIVE_FILE"
    FORM_DISCOVERY = "FORM_DISCOVERY"
    API_ENDPOINT = "API_ENDPOINT"
    WEAK_AUTHENTICATION = "WEAK_AUTHENTICATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    OTHER = "OTHER"


@dataclass
class VulnerabilityRecord:
    """Structure for vulnerability records."""

    id: str
    timestamp: str
    url: str
    vulnerability_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    title: str
    description: str
    payload: str = ""
    response_code: int = 0
    response_time: float = 0.0
    module: str = ""
    confidence: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    false_positive_risk: str = "MEDIUM"
    exploitation_difficulty: str = "MEDIUM"  # EASY, MEDIUM, HARD
    business_impact: str = "MEDIUM"
    remediation: str = ""
    references: list[str] = None
    additional_data: dict = None

    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.additional_data is None:
            self.additional_data = {}


@dataclass
class ScanRecord:
    """Structure for scan session records."""

    session_id: str
    start_time: str
    end_time: str = ""
    target_url: str = ""
    modules_used: list[str] = None
    total_requests: int = 0
    total_vulnerabilities: int = 0
    scan_duration: float = 0.0
    user_agent: str = ""
    scan_options: dict = None
    status: str = "RUNNING"  # RUNNING, COMPLETED, FAILED, CANCELLED

    def __post_init__(self):
        if self.modules_used is None:
            self.modules_used = []
        if self.scan_options is None:
            self.scan_options = {}


class AdvancedLogger:
    """Advanced logging system with structured vulnerability tracking."""

    def __init__(
        self,
        base_dir: str = "logs",
        session_name: str = None,
        enable_console: bool = True,
        enable_file: bool = True,
        enable_json: bool = True,
        log_level: LogLevel = LogLevel.INFO,
    ):
        """
        Initialize advanced logger.

        Args:
            base_dir: Base directory for log files
            session_name: Custom session name (auto-generated if None)
            enable_console: Enable console logging
            enable_file: Enable file logging
            enable_json: Enable JSON structured logging
            log_level: Minimum log level
        """
        self.base_dir = Path(base_dir)
        self.session_id = str(uuid.uuid4())
        self.session_name = session_name or datetime.now().strftime("scan_%Y%m%d_%H%M%S")
        self.enable_console = enable_console
        self.enable_file = enable_file
        self.enable_json = enable_json
        self.log_level = log_level

        # Create directories
        self._create_directories()

        # Initialize loggers
        self._setup_loggers()

        # Data storage
        self.vulnerabilities: list[VulnerabilityRecord] = []
        self.scan_record = ScanRecord(session_id=self.session_id, start_time=self._get_timestamp())

        # Thread safety
        self._lock = threading.Lock()

        # Performance tracking
        self.request_times = []
        self.module_stats = {}

        self.info(
            "Advanced logger initialized",
            {"session_id": self.session_id, "session_name": self.session_name, "log_directory": str(self.base_dir)},
        )

    def _create_directories(self):
        """Create necessary directories."""
        directories = [
            self.base_dir,
            self.base_dir / "sessions",
            self.base_dir / "vulnerabilities",
            self.base_dir / "reports",
            self.base_dir / "debug",
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def _setup_loggers(self):
        """Setup logging configuration."""
        # Main logger
        self.logger = logging.getLogger(f"scanner_{self.session_id}")
        self.logger.setLevel(logging.DEBUG)

        # Clear existing handlers
        self.logger.handlers.clear()

        # Console handler
        if self.enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self._get_logging_level())
            console_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)

        # File handler
        if self.enable_file:
            log_file = self.base_dir / "sessions" / f"{self.session_name}.log"
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

        # JSON file path
        if self.enable_json:
            self.json_log_file = self.base_dir / "sessions" / f"{self.session_name}.json"

    def _get_logging_level(self):
        """Convert LogLevel to logging level."""
        mapping = {
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ERROR: logging.ERROR,
            LogLevel.CRITICAL: logging.CRITICAL,
            LogLevel.VULNERABILITY: logging.WARNING,
            LogLevel.SUCCESS: logging.INFO,
        }
        return mapping.get(self.log_level, logging.INFO)

    def _get_timestamp(self) -> str:
        """Get ISO timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def _log_to_json(self, level: LogLevel, message: str, data: dict = None):
        """Log to JSON file."""
        if not self.enable_json:
            return

        log_entry = {
            "timestamp": self._get_timestamp(),
            "session_id": self.session_id,
            "level": level.value,
            "message": message,
            "data": data or {},
        }

        with self._lock:
            try:
                with open(self.json_log_file, "a", encoding="utf-8") as f:
                    json.dump(log_entry, f, ensure_ascii=False)
                    f.write("\n")
            except Exception as e:
                print(f"Failed to write to JSON log: {e}")

    def debug(self, message: str, data: dict = None):
        """Log debug message."""
        self.logger.debug(message)
        self._log_to_json(LogLevel.DEBUG, message, data)

    def info(self, message: str, data: dict = None):
        """Log info message."""
        self.logger.info(message)
        self._log_to_json(LogLevel.INFO, message, data)

    def warning(self, message: str, data: dict = None):
        """Log warning message."""
        self.logger.warning(message)
        self._log_to_json(LogLevel.WARNING, message, data)

    def error(self, message: str, data: dict = None):
        """Log error message."""
        self.logger.error(message)
        self._log_to_json(LogLevel.ERROR, message, data)

    def critical(self, message: str, data: dict = None):
        """Log critical message."""
        self.logger.critical(message)
        self._log_to_json(LogLevel.CRITICAL, message, data)

    def success(self, message: str, data: dict = None):
        """Log success message."""
        self.logger.info(f"SUCCESS: {message}")
        self._log_to_json(LogLevel.SUCCESS, message, data)

    def start_scan(self, target_url: str, modules: list[str], options: dict = None):
        """Log scan start."""
        self.scan_record.target_url = target_url
        self.scan_record.modules_used = modules
        self.scan_record.scan_options = options or {}

        self.info("Scan started", {"target_url": target_url, "modules": modules, "options": options})

    def end_scan(self, status: str = "COMPLETED"):
        """Log scan end."""
        self.scan_record.end_time = self._get_timestamp()
        self.scan_record.status = status
        self.scan_record.total_vulnerabilities = len(self.vulnerabilities)

        # Calculate duration
        start_time = datetime.fromisoformat(self.scan_record.start_time.replace("Z", "+00:00"))
        end_time = datetime.fromisoformat(self.scan_record.end_time.replace("Z", "+00:00"))
        self.scan_record.scan_duration = (end_time - start_time).total_seconds()

        self.info(
            f"Scan ended with status: {status}",
            {
                "duration": self.scan_record.scan_duration,
                "total_vulnerabilities": self.scan_record.total_vulnerabilities,
                "total_requests": self.scan_record.total_requests,
            },
        )

        # Save scan record
        self._save_scan_record()

    def log_vulnerability(
        self,
        vuln_type: VulnerabilityType,
        url: str,
        title: str,
        description: str,
        severity: str = "MEDIUM",
        payload: str = "",
        response_code: int = 0,
        response_time: float = 0.0,
        module: str = "",
        confidence: str = "MEDIUM",
        remediation: str = "",
        additional_data: dict = None,
    ) -> str:
        """
        Log a vulnerability finding.

        Returns:
            Vulnerability ID
        """
        vuln_id = str(uuid.uuid4())

        vulnerability = VulnerabilityRecord(
            id=vuln_id,
            timestamp=self._get_timestamp(),
            url=url,
            vulnerability_type=vuln_type.value,
            severity=severity.upper(),
            title=title,
            description=description,
            payload=payload,
            response_code=response_code,
            response_time=response_time,
            module=module,
            confidence=confidence.upper(),
            remediation=remediation,
            additional_data=additional_data or {},
        )

        with self._lock:
            self.vulnerabilities.append(vulnerability)

        # Log to standard logger
        self.logger.warning(f"VULNERABILITY: {title} - {url}")
        self._log_to_json(LogLevel.VULNERABILITY, f"Vulnerability found: {title}", asdict(vulnerability))

        # Save individual vulnerability record
        self._save_vulnerability_record(vulnerability)

        return vuln_id

    def log_request(
        self,
        url: str,
        method: str = "GET",
        response_code: int = 0,
        response_time: float = 0.0,
        module: str = "",
        payload: str = "",
    ):
        """Log HTTP request details."""
        with self._lock:
            self.scan_record.total_requests += 1
            self.request_times.append(response_time)

            # Update module stats
            if module:
                if module not in self.module_stats:
                    self.module_stats[module] = {"requests": 0, "total_time": 0.0, "errors": 0}
                self.module_stats[module]["requests"] += 1
                self.module_stats[module]["total_time"] += response_time
                if response_code >= 400:
                    self.module_stats[module]["errors"] += 1

        self.debug(
            f"Request: {method} {url}",
            {
                "method": method,
                "url": url,
                "response_code": response_code,
                "response_time": response_time,
                "module": module,
                "payload": payload[:100] if payload else "",  # Truncate long payloads
            },
        )

    def _save_vulnerability_record(self, vulnerability: VulnerabilityRecord):
        """Save individual vulnerability to file."""
        vuln_file = self.base_dir / "vulnerabilities" / f"{vulnerability.id}.json"
        try:
            with open(vuln_file, "w", encoding="utf-8") as f:
                json.dump(asdict(vulnerability), f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.error(f"Failed to save vulnerability record: {e}")

    def _save_scan_record(self):
        """Save scan session record."""
        scan_file = self.base_dir / "sessions" / f"{self.session_name}_summary.json"
        try:
            scan_data = asdict(self.scan_record)
            scan_data["vulnerabilities"] = [asdict(v) for v in self.vulnerabilities]
            scan_data["module_stats"] = self.module_stats
            scan_data["performance"] = {
                "average_response_time": sum(self.request_times) / len(self.request_times) if self.request_times else 0,
                "total_requests": len(self.request_times),
                "requests_per_second": (
                    len(self.request_times) / self.scan_record.scan_duration
                    if self.scan_record.scan_duration > 0
                    else 0
                ),
            }

            with open(scan_file, "w", encoding="utf-8") as f:
                json.dump(scan_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.error(f"Failed to save scan record: {e}")

    def get_vulnerability_summary(self) -> dict:
        """Get vulnerability summary statistics."""
        if not self.vulnerabilities:
            return {"total": 0, "by_severity": {}, "by_type": {}}

        by_severity = {}
        by_type = {}

        for vuln in self.vulnerabilities:
            # Count by severity
            severity = vuln.severity
            by_severity[severity] = by_severity.get(severity, 0) + 1

            # Count by type
            vuln_type = vuln.vulnerability_type
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

        return {
            "total": len(self.vulnerabilities),
            "by_severity": by_severity,
            "by_type": by_type,
            "high_confidence": len([v for v in self.vulnerabilities if v.confidence == "HIGH"]),
            "critical_severity": len([v for v in self.vulnerabilities if v.severity == "CRITICAL"]),
        }

    def generate_detailed_report(self) -> str:
        """Generate detailed vulnerability report."""
        report_file = self.base_dir / "reports" / f"{self.session_name}_detailed_report.json"

        report_data = {
            "scan_session": asdict(self.scan_record),
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "summary": self.get_vulnerability_summary(),
            "module_performance": self.module_stats,
            "generated_at": self._get_timestamp(),
            "report_version": "1.0",
        }

        try:
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            self.success(f"Detailed report generated: {report_file}")
            return str(report_file)
        except Exception as e:
            self.error(f"Failed to generate detailed report: {e}")
            return ""

    def export_vulnerabilities_csv(self) -> str:
        """Export vulnerabilities to CSV format."""
        csv_file = self.base_dir / "reports" / f"{self.session_name}_vulnerabilities.csv"

        try:
            import csv

            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                if not self.vulnerabilities:
                    return str(csv_file)

                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "id",
                        "timestamp",
                        "url",
                        "vulnerability_type",
                        "severity",
                        "title",
                        "description",
                        "confidence",
                        "module",
                    ],
                )
                writer.writeheader()

                for vuln in self.vulnerabilities:
                    writer.writerow(
                        {
                            "id": vuln.id,
                            "timestamp": vuln.timestamp,
                            "url": vuln.url,
                            "vulnerability_type": vuln.vulnerability_type,
                            "severity": vuln.severity,
                            "title": vuln.title,
                            "description": vuln.description,
                            "confidence": vuln.confidence,
                            "module": vuln.module,
                        }
                    )

            self.success(f"CSV export completed: {csv_file}")
            return str(csv_file)
        except Exception as e:
            self.error(f"Failed to export CSV: {e}")
            return ""

    def cleanup(self):
        """Cleanup logger resources."""
        try:
            # Close file handlers
            for handler in self.logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    handler.close()

            # Save final scan record
            self._save_scan_record()

            self.info("Logger cleanup completed")
        except Exception as e:
            print(f"Error during logger cleanup: {e}")


# Convenience functions
def create_advanced_logger(session_name: str = None, base_dir: str = "logs") -> AdvancedLogger:
    """Create an advanced logger instance."""
    return AdvancedLogger(base_dir=base_dir, session_name=session_name)


def quick_vulnerability_log(
    logger: AdvancedLogger, vuln_type: str, url: str, title: str, description: str, severity: str = "MEDIUM"
) -> str:
    """Quick vulnerability logging function."""
    vuln_type_enum = (
        VulnerabilityType(vuln_type) if vuln_type in [vt.value for vt in VulnerabilityType] else VulnerabilityType.OTHER
    )
    return logger.log_vulnerability(
        vuln_type=vuln_type_enum, url=url, title=title, description=description, severity=severity
    )
