"""
Configuration module for Cyber Secret Scanner Pro.

This module contains configuration classes and defaults used throughout the application,
including supported file extensions, ignored directories, risk scoring weights, and
entropy thresholds for cryptographic key and token detection.
"""
from typing import Set, Dict

class ScannerConfig:
    """
    Configuration settings for the Secret Scanner.

    Provides configuration parameters such as lists of ignored directories,
    supported file extensions, severity-based risk score deduct values,
    and threshold parameters for Shannon entropy verification.
    """
    
    # Version of the tool
    VERSION: str = "1.0.0"
    
    # Supported file extensions for scanning
    SUPPORTED_EXTENSIONS: Set[str] = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go", 
        ".rb", ".cs", ".cpp", ".c", ".env", ".ini", ".cfg", ".conf", 
        ".json", ".yaml", ".yml", ".xml", ".sql", ".txt", ".md"
    }

    # Directories that should be recursively skipped during the walk
    IGNORED_DIRS: Set[str] = {
        ".git", "node_modules", "venv", ".venv", ".idea", ".vscode", 
        "dist", "build", "__pycache__", "reports"
    }

    # Minimum entropy threshold for detecting potentially random/cryptographic keys (Shannon Entropy)
    DEFAULT_ENTROPY_THRESHOLD: float = 4.5

    # File size limits (to prevent reading huge files like database dumps in memory)
    # Default is 10 MB (10 * 1024 * 1024 bytes)
    MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024

    # Point deductions for risk score calculation (out of 100)
    SEVERITY_DEDUCT_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 5,
        "LOW": 1
    }

    # Minimum score possible
    MIN_SCORE: int = 0
    
    # Maximum starting score
    MAX_SCORE: int = 100

    @classmethod
    def get_risk_rating(cls, score: int) -> str:
        """
        Map a numerical score (0-100) to a qualitative risk level.

        Args:
            score (int): Calculated security score.

        Returns:
            str: Risk rating category ('Excellent', 'Good', 'Moderate', 'Poor', 'Critical').
        """
        if score >= 90:
            return "Excellent"
        elif score >= 70:
            return "Good"
        elif score >= 50:
            return "Moderate"
        elif score >= 30:
            return "Poor"
        else:
            return "Critical"
