"""lockhtml - Password-protect regions of HTML files for static hosting."""

__version__ = "0.1.0"

from .crypto import LockhtmlError, decrypt, encrypt, rewrap_keys

__all__ = ["encrypt", "decrypt", "rewrap_keys", "LockhtmlError", "__version__"]
