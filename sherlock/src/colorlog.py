# src/colorlog.py
from __future__ import annotations
import logging
import os
import sys
from typing import Dict, Any, Optional

# Optional: enable ANSI colors on Windows if colorama is present.
try:
    import colorama  # type: ignore
    colorama.just_fix_windows_console()
except Exception:
    pass

ANSI_CODES = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "underline": "\x1b[4m",
    "black": "\x1b[30m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",
    "bg_black": "\x1b[40m",
    "bg_red": "\x1b[41m",
    "bg_green": "\x1b[42m",
    "bg_yellow": "\x1b[43m",
    "bg_blue": "\x1b[44m",
    "bg_magenta": "\x1b[45m",
    "bg_cyan": "\x1b[46m",
    "bg_white": "\x1b[47m",
}

LEVEL_COLORS = {
    logging.DEBUG:  ("blue", None, False),
    logging.INFO:   ("green", None, False),
    logging.WARNING:("yellow", None, True),
    logging.ERROR:  ("red", None, True),
    logging.CRITICAL:("white", "bg_red", True),
}

def supports_color(stream) -> bool:
    try:
        # Only color when writing to a real TTY
        return hasattr(stream, "isatty") and stream.isatty()
    except Exception:
        return False

def c(text: str, *, fg: Optional[str]=None, bg: Optional[str]=None, bold: bool=False, underline: bool=False, dim: bool=False) -> str:
    """
    Manually colorize a substring. Use in your message like:
      logger.info("hello %s", c("world", fg="cyan", bold=True))
    """
    parts = []
    if bold: parts.append(ANSI_CODES["bold"])
    if dim: parts.append(ANSI_CODES["dim"])
    if underline: parts.append(ANSI_CODES["underline"])
    if fg and fg in ANSI_CODES: parts.append(ANSI_CODES[fg])
    if bg and bg in ANSI_CODES: parts.append(ANSI_CODES[bg])
    start = "".join(parts)
    end = ANSI_CODES["reset"] if parts else ""
    return f"{start}{text}{end}"

class ConsoleColoredFormatter(logging.Formatter):
    """
    Colors console output. File logs should use a plain formatter.

    How to color specific lines:
      logger.info("Message", extra={"msg_color":"cyan","msg_bold":True,"msg_underline":False,"msg_bg":"bg_black"})
    If not provided, it colors level name based on LEVEL_COLORS and leaves message plain.
    """
    def __init__(self, fmt: str, datefmt: str | None = None, *, colorize: bool = True, color_levelnames: bool = True):
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.colorize = colorize
        self.color_levelnames = color_levelnames

    def format(self, record: logging.LogRecord) -> str:
        # Save originals
        orig_levelname = record.levelname
        orig_msg = record.getMessage()

        # Apply colors only if enabled and stream supports it (checked when handler is created)
        if self.colorize:
            # 1) Colorize LEVELNAME
            if self.color_levelnames:
                fg, bg, bold = LEVEL_COLORS.get(record.levelno, ("white", None, False))
                record.levelname = c(orig_levelname, fg=fg, bg=bg, bold=bold)

            # 2) Colorize message if requested via extra
            fg = getattr(record, "msg_color", None)
            bg = getattr(record, "msg_bg", None)
            bold = bool(getattr(record, "msg_bold", False))
            underline = bool(getattr(record, "msg_underline", False))
            dim = bool(getattr(record, "msg_dim", False))

            # If user supplied any styling flag, colorize whole message
            if any([fg, bg, bold, underline, dim]):
                colored_msg = c(orig_msg, fg=fg, bg=bg, bold=bold, underline=underline, dim=dim)
            else:
                # Otherwise leave message as-is; user can still embed c("...") manually.
                colored_msg = orig_msg

            # Inject a temporary attribute for the format string
            record.__dict__["_colored_message"] = colored_msg
            # Use %(message)s normally (we'll swap below)
            out = super().format(record)
            # Reset modified fields
            record.levelname = orig_levelname
            return out.replace(orig_msg, colored_msg, 1)
        else:
            # No color
            record.levelname = orig_levelname
            return super().format(record)

def make_console_handler(fmt: str, datefmt: str) -> logging.Handler:
    stream = sys.stdout
    colorize = supports_color(stream)
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.INFO)
    handler.setFormatter(ConsoleColoredFormatter(fmt=fmt, datefmt=datefmt, colorize=colorize))
    return handler
