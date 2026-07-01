"""
Core scanning engine for Cyber Secret Scanner Pro.

Traverses directories recursively, filters target files, parses line content
against regex signatures and Shannon entropy thresholds, and collects findings.
"""
import os
import sys
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Set, Any, Tuple
from tqdm import tqdm

from config import ScannerConfig
from logger import setup_logger
from models import Finding, FileMetadata, ScanStats, ScanResult
from patterns import SECRET_PATTERNS
from utils import calculate_entropy, calculate_sha256, is_binary

class SecretScanner:
    """
    Scanning engine that orchestrates traversing, parsing, and analysis of files.
    """
    def __init__(self, target_dir: Path, config: ScannerConfig = None, log_file: Path = None):
        """
        Initializes the SecretScanner instance.

        Args:
            target_dir (Path): Path to the target directory to scan.
            config (ScannerConfig, optional): Scanner configuration parameters.
            log_file (Path, optional): Path to log audit file.
        """
        self.target_dir = Path(target_dir).resolve()
        self.config = config or ScannerConfig()
        self.logger = setup_logger("SecretScanner", log_file=log_file)
        
        # Keep track of unique findings to prevent duplicate reporting (using file + line + secret hash)
        self.seen_findings: Set[str] = set()

    def scan(self) -> ScanResult:
        """
        Runs the complete scan pipeline on the target directory.

        Returns:
            ScanResult: Contains findings, file metadata, and statistics.
        """
        start_time = datetime.now(timezone.utc)
        stats = ScanStats(start_time=start_time.isoformat().replace("+00:00", "Z"))
        findings: List[Finding] = []
        scanned_files: List[FileMetadata] = []

        self.logger.info(f"Starting security scan on: {self.target_dir}")

        # Gather list of all files to scan first (to initialize progress bar correctly)
        files_to_scan = self._collect_files(stats)
        
        self.logger.info(f"Collected {len(files_to_scan)} files for scanning ({stats.folders_scanned} folders searched).")

        # Scan files with progress bar
        with tqdm(files_to_scan, desc="Scanning files", unit="file", file=sys.stdout, leave=True) as pbar:
            for file_path in pbar:
                pbar.set_postfix_str(file_path.name[:20], refresh=True)
                
                # Check file size
                try:
                    file_size = file_path.stat().st_size
                except Exception as e:
                    self.logger.warning(f"Unable to read file metadata for {file_path}: {e}")
                    stats.files_ignored += 1
                    continue

                if file_size > self.config.MAX_FILE_SIZE_BYTES:
                    self.logger.warning(f"Skipping large file: {file_path} ({file_size} bytes)")
                    stats.files_ignored += 1
                    continue

                # Calculate SHA-256 and scan file
                sha256_hash = calculate_sha256(file_path)
                file_findings, line_count = self._scan_file(file_path)
                
                # Record file metadata
                scanned_files.append(FileMetadata(
                    file_path=str(file_path.relative_to(self.target_dir)),
                    file_size_bytes=file_size,
                    sha256_hash=sha256_hash,
                    line_count=line_count,
                    extension=file_path.suffix
                ))
                
                # Add findings
                for f in file_findings:
                    findings.append(f)
                    stats.severity_counts[f.severity] += 1
                    stats.total_findings += 1
                
                stats.files_scanned += 1

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()
        stats.end_time = end_time.isoformat().replace("+00:00", "Z")
        stats.duration_seconds = round(duration, 3)

        # Calculate final risk score
        security_score = self._calculate_risk_score(stats.severity_counts)
        risk_rating = self.config.get_risk_rating(security_score)

        self.logger.info("Scan completed.")
        self.logger.info(f"Scan Duration: {stats.duration_seconds}s | Files Scanned: {stats.files_scanned} | Secrets Found: {stats.total_findings}")
        self.logger.info(f"Risk Score: {security_score}/100 ({risk_rating})")

        return ScanResult(
            stats=stats,
            findings=findings,
            scanned_files=scanned_files,
            security_score=security_score,
            risk_rating=risk_rating
        )

    def _collect_files(self, stats: ScanStats) -> List[Path]:
        """
        Traverses directories recursively, applying filter rules for ignored
        directories and supported extensions.

        Args:
            stats (ScanStats): Stats counter to increment folder searches.

        Returns:
            List[Path]: Screened list of files to scan.
        """
        collected = []
        for root, dirs, files in os.walk(self.target_dir):
            # In-place modify dirs to skip ignored directories
            dirs[:] = [d for d in dirs if d not in self.config.IGNORED_DIRS and not d.startswith(".")]
            stats.folders_scanned += 1
            
            for file in files:
                file_path = Path(root) / file
                
                # Ignore dot files (e.g., .gitignore) unless it is explicitly an env file like .env
                if file.startswith(".") and not file.endswith(".env"):
                    stats.files_ignored += 1
                    continue
                
                # Check supported extensions
                ext = file_path.suffix.lower()
                # .env might not have suffix (e.g. sample.env vs .env)
                if ext not in self.config.SUPPORTED_EXTENSIONS and file != ".env" and not file.endswith(".env"):
                    stats.files_ignored += 1
                    continue

                # Skip binaries
                if is_binary(file_path):
                    stats.files_ignored += 1
                    continue

                collected.append(file_path)
        return collected

    def _scan_file(self, file_path: Path) -> Tuple[List[Finding], int]:
        """
        Reads file contents line-by-line using fallback encodings, scans
        lines against signatures and high-entropy variable checks.

        Args:
            file_path (Path): Absolute file path.

        Returns:
            Tuple[List[Finding], int]: (Detected findings list, total line count).
        """
        findings: List[Finding] = []
        encodings = ["utf-8", "utf-16", "latin-1", "cp1252"]
        content_lines: List[str] = []
        
        # Safely read file lines with encoding fallback
        read_success = False
        for encoding in encodings:
            try:
                with open(file_path, "r", encoding=encoding, errors="replace") as f:
                    content_lines = f.readlines()
                read_success = True
                break
            except Exception:
                continue

        if not read_success:
            self.logger.warning(f"Failed to read file contents for: {file_path}")
            return [], 0

        line_count = len(content_lines)
        rel_path = str(file_path.relative_to(self.target_dir))

        for idx, line in enumerate(content_lines, start=1):
            stripped_line = line.strip()
            if not stripped_line:
                continue

            # 1. Regex Signature Scanning
            for pattern_dict in SECRET_PATTERNS:
                matches = pattern_dict["regex"].findall(stripped_line)
                for match in matches:
                    # Handle group matches if regex has groups
                    matched_value = match[0] if isinstance(match, tuple) else match
                    if not matched_value:
                        continue
                    
                    # For safety, clean value
                    matched_value = matched_value.strip().strip("'\"")
                    if len(matched_value) < 4:  # Avoid too short false positives
                        continue

                    # Masking secret for logs and privacy protection
                    masked_secret = self._mask_secret(matched_value)
                    hashed_secret = hashlib.sha256(matched_value.encode("utf-8")).hexdigest()

                    # Deduplication check
                    dup_key = f"{rel_path}:{idx}:{hashed_secret}"
                    if dup_key in self.seen_findings:
                        continue
                    
                    self.seen_findings.add(dup_key)

                    findings.append(Finding(
                        file_path=rel_path,
                        line_number=idx,
                        secret_type=pattern_dict["name"],
                        matched_text=masked_secret,
                        hashed_secret=hashed_secret,
                        severity=pattern_dict["severity"],
                        description=pattern_dict["description"]
                    ))

            # 2. Entropy-based Custom Secret Detection (Bonus Feature)
            # Scan for generic assignments with high entropy value: key = "value"
            # Matches words like key, password, token, credential, cert, private, secret
            entropy_assignment_regex = re.compile(
                r"(?i)\b(key|pass|token|secret|credential|auth|cipher)\b\s*[:=]\s*['\"]([^'\"]{16,128})['\"]"
            )
            entropy_matches = entropy_assignment_regex.findall(stripped_line)
            for var_name, secret_val in entropy_matches:
                secret_val = secret_val.strip()
                entropy_val = calculate_entropy(secret_val)
                
                # Flag if entropy is above threshold and not already detected
                if entropy_val >= self.config.DEFAULT_ENTROPY_THRESHOLD:
                    masked_secret = self._mask_secret(secret_val)
                    hashed_secret = hashlib.sha256(secret_val.encode("utf-8")).hexdigest()
                    
                    dup_key = f"{rel_path}:{idx}:{hashed_secret}"
                    if dup_key in self.seen_findings:
                        continue
                    
                    self.seen_findings.add(dup_key)
                    
                    findings.append(Finding(
                        file_path=rel_path,
                        line_number=idx,
                        secret_type="High Entropy Secret (Heuristic)",
                        matched_text=masked_secret,
                        hashed_secret=hashed_secret,
                        severity="MEDIUM",
                        description=f"Variable '{var_name}' assigned a high-entropy string ({entropy_val:.2f} bits), suggesting hardcoded credential/key."
                    ))

        return findings, line_count

    def _mask_secret(self, secret: str) -> str:
        """
        Masks the sensitive part of a secret to safely output it in reports.
        For example: "AKIAIOSFODNN7EXAMPLE" -> "AKIA************MPLE"

        Args:
            secret (str): Raw secret.

        Returns:
            str: Masked secret.
        """
        if len(secret) <= 8:
            return "*" * len(secret)
        
        # Show first 4 and last 4 characters
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """
        Calculates risk score out of 100 based on severity counts and weights.

        Args:
            severity_counts (Dict[str, int]): Count of found severities.

        Returns:
            int: Security score from 0-100.
        """
        deductions = 0
        for severity, count in severity_counts.items():
            weight = self.config.SEVERITY_DEDUCT_WEIGHTS.get(severity, 0)
            deductions += weight * count

        score = self.config.MAX_SCORE - deductions
        return max(self.config.MIN_SCORE, min(score, self.config.MAX_SCORE))

def main():
    """
    Main entry point for Cyber Secret Scanner Pro.
    Parses arguments, executes scan, and outputs report files.
    """
    import argparse
    from report import ReportGenerator
    
    # Custom Banner
    banner = f"""
================================================================================
  ______     __                  ____                      __  ____            
 / ___/_  __/ /_  ___  ________ / __/___  _________ ___   / /_/ __ \\________ _ 
/ /__ / // / __ \\/ _ \\/ ___/ _ \\\\ \\ / _ \\/ ___/ __ `__ \\ / __/ /_/ / ___/ __ `/ 
/ /___/ // / /_/ /  __/ /  /  __/__/ /  __/ /__/ / / / / // /_/ ____/ /  / /_/ /  
\\___/ \\_, /_.___/\\___/_/   \\___/____/\\___/\\___/_/ /_/ /_/ \\__/_/   /_/   \\__,_/   
     /___/                                                                     
                       SECRET EXPOSURE AUDIT TOOL v{ScannerConfig.VERSION}
                 Developed by Meera V Nair (https://github.com/meeravnair)
================================================================================
"""
    print(banner)

    parser = argparse.ArgumentParser(description="Cyber Secret Scanner Pro: Recursively scan directories for exposed secrets.")
    parser.add_argument("target", nargs="?", default=".", help="Directory path to scan recursively (default: current directory)")
    parser.add_argument("-o", "--output-dir", default="reports", help="Directory where reports are stored (default: reports)")
    parser.add_argument("-l", "--log-file", default="scanner.log", help="Path to write execution log file")
    parser.add_argument("--entropy", type=float, help="Override default Shannon Entropy threshold (default: 4.5)")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-json", action="store_true", help="Skip JSON report generation")
    parser.add_argument("--no-csv", action="store_true", help="Skip CSV report generation")
    
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: Target path '{args.target}' does not exist.")
        sys.exit(1)

    # Initialize configuration overrides
    config = ScannerConfig()
    if args.entropy is not None:
        config.DEFAULT_ENTROPY_THRESHOLD = args.entropy

    log_path = Path(args.log_file).resolve()
    
    # Run scanning process
    scanner = SecretScanner(target_dir=target_path, config=config, log_file=log_path)
    result = scanner.scan()

    # Generate Reports
    reports_dir = Path(args.output_dir).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    generator = ReportGenerator(scan_result=result, reports_dir=reports_dir)

    print("\n[+] Generating Audit Reports...")
    if not args.no_html:
        html_path = generator.generate_html()
        print(f"    - HTML Dashboard: {html_path}")
    if not args.no_json:
        json_path = generator.generate_json()
        print(f"    - JSON Database:  {json_path}")
    if not args.no_csv:
        csv_path = generator.generate_csv()
        print(f"    - CSV Logfile:    {csv_path}")

    # Summary table to CLI
    from colorama import Fore, Style
    print(f"\n{Fore.GREEN}================== SCAN REPORT SUMMARY =================={Style.RESET_ALL}")
    print(f"  Target Scanned:    {target_path}")
    print(f"  Files Scanned:     {result.stats.files_scanned}")
    print(f"  Folders Scanned:   {result.stats.folders_scanned}")
    print(f"  Ignored/Skipped:   {result.stats.files_ignored}")
    print(f"  Scan Duration:     {result.stats.duration_seconds} seconds")
    print(f"  Total Findings:    {result.stats.total_findings}")
    print(f"  Risk Index:        {result.security_score}/100 ({result.risk_rating})")
    print(f"{Fore.GREEN}========================================================={Style.RESET_ALL}")
    
    if result.stats.total_findings > 0:
        print(f"\n{Fore.YELLOW}[!] WARNING: exposed credentials detected. Review the HTML dashboard report immediately.{Style.RESET_ALL}")
        sys.exit(1)
    else:
        print(f"\n{Fore.CYAN}[+] SUCCESS: No exposed secrets detected. Security posture is excellent.{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()

