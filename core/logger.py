"""Application logging setup with console and rotating file handlers."""

import logging
import os
from logging.handlers import RotatingFileHandler

from config import Config

_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


def setup_logging() -> logging.Logger:
    """Configure root logging for both console and a rotating application log.

    Calling this function more than once does not duplicate handlers.
    """
    level = getattr(logging, str(Config.LOG_LEVEL).upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    formatter = logging.Formatter(_LOG_FORMAT)

    log_dir = os.path.dirname(Config.LOG_FILE)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        Config.LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(formatter)

    existing = {
        (type(handler), getattr(handler, "baseFilename", None))
        for handler in root.handlers
    }
    if (logging.StreamHandler, None) not in existing:
        root.addHandler(console_handler)
    if (RotatingFileHandler, os.path.abspath(Config.LOG_FILE)) not in existing:
        root.addHandler(file_handler)

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    return root
