"""
Data models for Cyber Secret Scanner Pro.

Contains classes for representing individual findings, file metadata, scan statistics,
and aggregated scan results, complete with serialization support.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any

@dataclass
class Finding:
    """
    Represents a single sensitive finding (exposed secret) detected during a scan.
    """
    file_path: str
    line_number: int
    secret_type: str
    matched_text: str
    hashed_secret: str
    severity: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the finding to a dictionary suitable for JSON.

        Returns:
            Dict[str, Any]: Serialized finding representation.
        """
        return asdict(self)

@dataclass
class FileMetadata:
    """
    Represents metadata gathered for a scanned file.
    """
    file_path: str
    file_size_bytes: int
    sha256_hash: str
    line_count: int
    extension: str
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the file metadata to a dictionary.

        Returns:
            Dict[str, Any]: Serialized file metadata.
        """
        return asdict(self)

@dataclass
class ScanStats:
    """
    Statistical aggregates for a single scan execution.
    """
    start_time: str
    end_time: str = ""
    duration_seconds: float = 0.0
    files_scanned: int = 0
    folders_scanned: int = 0
    files_ignored: int = 0
    total_findings: int = 0
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    })

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the scan statistics to a dictionary.

        Returns:
            Dict[str, Any]: Serialized scan stats.
        """
        return asdict(self)

@dataclass
class ScanResult:
    """
    Aggregates findings, file metadata, and statistics of a full scan.
    """
    stats: ScanStats
    findings: List[Finding] = field(default_factory=list)
    scanned_files: List[FileMetadata] = field(default_factory=list)
    security_score: int = 100
    risk_rating: str = "Excellent"

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the entire scan result to a dictionary.

        Returns:
            Dict[str, Any]: Full serialized scan result.
        """
        return {
            "stats": self.stats.to_dict(),
            "security_score": self.security_score,
            "risk_rating": self.risk_rating,
            "findings": [f.to_dict() for f in self.findings],
            "scanned_files": [f.to_dict() for f in self.scanned_files]
        }
