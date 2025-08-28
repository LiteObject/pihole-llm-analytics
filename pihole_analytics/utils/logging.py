"""
Logging utility for Pi-hole Analytics.

Provides structured logging with configurable output formats and levels.
"""

import logging
import logging.handlers
import json
from datetime import datetime
from typing import Any, Dict, Optional

from .config import get_config


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        for key, value in record.__dict__.items():
            if key not in ["name", "msg", "args", "levelname", "levelno", "pathname",
                           "filename", "module", "exc_info", "exc_text", "stack_info",
                           "lineno", "funcName", "created", "msecs", "relativeCreated",
                           "thread", "threadName", "processName", "process", "getMessage"]:
                log_entry[key] = value

        return json.dumps(log_entry)


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up logging configuration."""
    config = get_config()

    # Create logger
    logger = logging.getLogger("pihole_analytics")

    # Set log level based on verbose flag or config
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(getattr(logging, config.logging.log_level.upper()))

    # Clear any existing handlers
    logger.handlers.clear()

    # Create console handler
    console_handler = logging.StreamHandler()

    # Set up formatter
    if config.logging.enable_json_logging:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(config.logging.log_format)

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Add file handler if specified
    if config.logging.log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            config.logging.log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a specific module."""
    return logging.getLogger(f"pihole_analytics.{name}")


class LoggerMixin:
    """Mixin class to add logging capabilities to other classes."""

    @property
    def logger(self) -> logging.Logger:
        """Get logger for this class."""
        return get_logger(self.__class__.__name__.lower())

    def log_method_call(self, method_name: str, **kwargs) -> None:
        """Log method call with parameters."""
        if kwargs:
            self.logger.debug("Calling %s with params: %s",
                              method_name, kwargs)
        else:
            self.logger.debug("Calling %s", method_name)

    def log_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
        """Log error with context."""
        extra = {"error_type": type(error).__name__}
        if context:
            extra.update(context)

        self.logger.error(
            "Error occurred: %s", error, extra=extra, exc_info=True)
