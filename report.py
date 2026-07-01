"""
Report generation module for Cyber Secret Scanner Pro.

Provides export capabilities for scan results to JSON, CSV, and HTML formats,
storing output files inside the designated reports directory.
"""
import csv
import json
import base64
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from models import ScanResult

class ReportGenerator:
    """
    Handles serializing ScanResult structures into JSON, CSV, and premium HTML dashboard templates.
    """
    def __init__(self, scan_result: ScanResult, reports_dir: Path, templates_dir: Path = None, static_dir: Path = None):
        """
        Initializes ReportGenerator.

        Args:
            scan_result (ScanResult): Aggregate results of the file scan.
            reports_dir (Path): Destination folder for output reports.
            templates_dir (Path, optional): Directory containing HTML templates.
            static_dir (Path, optional): Directory containing stylesheets and logos.
        """
        self.result = scan_result
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Paths for templates and static files (defaults to current project structure)
        current_dir = Path(__file__).parent.resolve()
        self.templates_dir = Path(templates_dir) if templates_dir else current_dir / "templates"
        self.static_dir = Path(static_dir) if static_dir else current_dir / "static"

    def generate_json(self, filename: str = "scan_report.json") -> Path:
        """
        Saves findings and stats as a JSON file.

        Args:
            filename (str): Name of output JSON file.

        Returns:
            Path: Absolute path of written JSON report.
        """
        file_path = self.reports_dir / filename
        data = self.result.to_dict()
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return file_path
        except Exception as e:
            raise IOError(f"Failed to generate JSON report at {file_path}: {e}")

    def generate_csv(self, filename: str = "scan_report.csv") -> Path:
        """
        Saves findings list as a CSV file.

        Args:
            filename (str): Name of output CSV file.

        Returns:
            Path: Absolute path of written CSV report.
        """
        file_path = self.reports_dir / filename
        try:
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                # Header row
                writer.writerow([
                    "File Path", "Line Number", "Secret Type", "Matched Text (Masked)",
                    "Severity", "Description", "Timestamp"
                ])
                # Data rows
                for finding in self.result.findings:
                    writer.writerow([
                        finding.file_path,
                        finding.line_number,
                        finding.secret_type,
                        finding.matched_text,
                        finding.severity,
                        finding.description,
                        finding.timestamp
                    ])
            return file_path
        except Exception as e:
            raise IOError(f"Failed to generate CSV report at {file_path}: {e}")

    def generate_html(self, filename: str = "scan_report.html") -> Path:
        """
        Renders the interactive HTML dashboard report using Jinja2 templates.

        Args:
            filename (str): Name of output HTML file.

        Returns:
            Path: Absolute path of written HTML report.
        """
        file_path = self.reports_dir / filename
        
        # Setup Jinja environment
        if not self.templates_dir.exists():
            raise FileNotFoundError(f"Templates directory not found: {self.templates_dir}")

        env = Environment(loader=FileSystemLoader(self.templates_dir))
        try:
            template = env.get_template("report.html")
        except Exception as e:
            raise FileNotFoundError(f"Failed to load report.html from template directory: {e}")

        # Gather CSS code to embed in HTML for self-containment
        css_content = ""
        css_file = self.static_dir / "style.css"
        if css_file.exists():
            try:
                with open(css_file, "r", encoding="utf-8") as f:
                    css_content = f.read()
            except Exception:
                pass

        # Check if there is a logo.png image and read it as base64 to embed directly (for portability)
        logo_base64 = ""
        logo_file = self.static_dir / "logo.png"
        if logo_file.exists():
            try:
                with open(logo_file, "rb") as f:
                    logo_base64 = base64.b64encode(f.read()).decode("utf-8")
            except Exception:
                pass

        # Context parameters for the template rendering
        context = {
            "stats": self.result.stats,
            "findings": self.result.findings,
            "scanned_files": self.result.scanned_files,
            "security_score": self.result.security_score,
            "risk_rating": self.result.risk_rating,
            "css_content": css_content,
            "logo_base64": logo_base64,
            "version": "1.0.0"
        }

        try:
            rendered_html = template.render(context)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(rendered_html)
            return file_path
        except Exception as e:
            raise IOError(f"Failed to generate HTML report at {file_path}: {e}")
