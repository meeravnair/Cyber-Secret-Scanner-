"""
Logging configuration for Cyber Secret Scanner Pro.

Provides colored console logging using colorama and handles file-based logging
for historical audit trails.
"""
import logging
import sys
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color console output
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """
    Custom logging formatter that adds color based on log levels.
    """
    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT
    }

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with colors matching the logging level.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The colorized formatted log string.
        """
        color = self.LEVEL_COLORS.get(record.levelno, "")
        message = super().format(record)
        if color:
            return f"{color}{message}{Style.RESET_ALL}"
        return message

def setup_logger(name: str = "CyberSecretScanner", log_file: Path = None, level: int = logging.INFO) -> logging.Logger:
    """
    Configures and returns a custom logger with both stream and file handlers.

    Args:
        name (str): Name of the logger.
        log_file (Path, optional): Path to log file. If provided, file logging is enabled.
        level (int): Logging level.

    Returns:
        logging.Logger: The configured Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers if logger already set up
    if logger.handlers:
        return logger

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S")
    colored_formatter = ColoredFormatter()
    colored_formatter._fmt = console_format._fmt
    colored_formatter.datefmt = console_format.datefmt
    console_handler.setFormatter(colored_formatter)
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(level)
            file_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
            file_handler.setFormatter(file_format)
            logger.addHandler(file_handler)
        except Exception:
            # Fallback if log file cannot be created
            pass

    return logger
