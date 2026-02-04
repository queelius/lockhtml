"""Configuration management for lockhtml.

Handles loading .lockhtml.yaml files with directory traversal,
environment variable overrides, and default values.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .crypto import LockhtmlError, generate_salt, hex_to_salt, salt_to_hex

CONFIG_FILENAME = ".lockhtml.yaml"
ENV_PASSWORD = "LOCKHTML_PASSWORD"
ENV_SALT = "LOCKHTML_SALT"


@dataclass
class TemplateConfig:
    """Template customization settings."""

    title: str = "Protected Content"
    button_text: str = "Unlock"
    error_text: str = "Incorrect password"
    placeholder: str = "Enter password"
    username_placeholder: str = "Enter username"
    color_primary: str = "#4CAF50"
    color_secondary: str = "#76B852"


@dataclass
class DefaultsConfig:
    """Default behavior settings."""

    remember: str = "ask"  # "none", "session", "local", "ask"
    remember_days: int = 0  # 0 = no expiration
    auto_prompt: bool = True  # Show password prompt on load if locked


@dataclass
class LockhtmlConfig:
    """Complete lockhtml configuration."""

    password: str | None = None
    salt: bytes | None = None
    users: dict[str, str] | None = None  # {username: password} for multi-user
    managed: list[str] | None = None  # Glob patterns for sync command
    defaults: DefaultsConfig = field(default_factory=DefaultsConfig)
    template: TemplateConfig = field(default_factory=TemplateConfig)
    custom_css: str | None = None  # Custom CSS content (replaces default styles)
    config_path: Path | None = None  # Path where config was loaded from

    def validate(self) -> None:
        """Validate configuration.

        Raises:
            LockhtmlError: If configuration is invalid.
        """
        valid_remember = {"none", "session", "local", "ask"}
        if self.defaults.remember not in valid_remember:
            raise LockhtmlError(
                f"Invalid remember value: {self.defaults.remember}. "
                f"Must be one of: {', '.join(valid_remember)}"
            )

        if self.defaults.remember_days < 0:
            raise LockhtmlError("remember_days must be non-negative")

        # Validate users dict
        if self.users is not None:
            if not isinstance(self.users, dict) or not self.users:
                raise LockhtmlError("'users' must be a non-empty dictionary")
            for username, user_password in self.users.items():
                if not username:
                    raise LockhtmlError("Username cannot be empty")
                if ":" in username:
                    raise LockhtmlError(
                        f"Username '{username}' cannot contain ':' (used as delimiter)"
                    )
                if not user_password:
                    raise LockhtmlError(
                        f"Password for user '{username}' cannot be empty"
                    )


def find_config_file(start_path: Path | None = None) -> Path | None:
    """Find .lockhtml.yaml by traversing up from start_path.

    Args:
        start_path: Directory to start searching from. Defaults to cwd.

    Returns:
        Path to config file if found, None otherwise.
    """
    if start_path is None:
        start_path = Path.cwd()
    else:
        start_path = Path(start_path).resolve()

    # If start_path is a file, use its parent directory
    if start_path.is_file():
        start_path = start_path.parent

    current = start_path
    while True:
        config_path = current / CONFIG_FILENAME
        if config_path.is_file():
            return config_path

        parent = current.parent
        if parent == current:
            # Reached root, no config found
            return None
        current = parent


def load_config(
    config_path: Path | None = None,
    start_path: Path | None = None,
    password_override: str | None = None,
) -> LockhtmlConfig:
    """Load configuration from file, environment, and overrides.

    Priority (highest to lowest):
    1. Function arguments (password_override)
    2. Environment variables (LOCKHTML_PASSWORD, LOCKHTML_SALT)
    3. Config file (.lockhtml.yaml)
    4. Defaults

    Args:
        config_path: Explicit path to config file. If None, searches.
        start_path: Directory to start config file search from.
        password_override: Override password from CLI argument.

    Returns:
        Loaded and validated configuration.
    """
    config = LockhtmlConfig()

    # Find or use explicit config file
    if config_path is not None:
        config_path = Path(config_path)
        if not config_path.is_file():
            raise LockhtmlError(f"Config file not found: {config_path}")
    else:
        config_path = find_config_file(start_path)

    # Load config file if found
    if config_path is not None:
        config = _load_config_file(config_path)
        config.config_path = config_path

    # Override with environment variables
    env_password = os.environ.get(ENV_PASSWORD)
    if env_password:
        config.password = env_password

    env_salt = os.environ.get(ENV_SALT)
    if env_salt:
        config.salt = hex_to_salt(env_salt)

    # Override with function argument
    if password_override is not None:
        config.password = password_override

    config.validate()
    return config


def _load_config_file(config_path: Path) -> LockhtmlConfig:
    """Load configuration from a YAML file.

    Args:
        config_path: Path to .lockhtml.yaml file.

    Returns:
        Configuration loaded from file.

    Raises:
        LockhtmlError: If file cannot be read or parsed.
    """
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise LockhtmlError(f"Invalid YAML in {config_path}: {e}") from e
    except OSError as e:
        raise LockhtmlError(f"Cannot read config file {config_path}: {e}") from e

    config = LockhtmlConfig(config_path=config_path)

    # Load password
    if "password" in data:
        config.password = str(data["password"])

    # Load salt
    if "salt" in data:
        config.salt = hex_to_salt(str(data["salt"]))

    # Load defaults
    if "defaults" in data and isinstance(data["defaults"], dict):
        defaults_data = data["defaults"]
        config.defaults = DefaultsConfig(
            remember=defaults_data.get("remember", config.defaults.remember),
            remember_days=defaults_data.get(
                "remember_days", config.defaults.remember_days
            ),
            auto_prompt=defaults_data.get("auto_prompt", config.defaults.auto_prompt),
        )

    # Load template
    if "template" in data and isinstance(data["template"], dict):
        template_data = data["template"]
        config.template = TemplateConfig(
            title=template_data.get("title", config.template.title),
            button_text=template_data.get("button_text", config.template.button_text),
            error_text=template_data.get("error_text", config.template.error_text),
            placeholder=template_data.get("placeholder", config.template.placeholder),
            color_primary=template_data.get(
                "color_primary", config.template.color_primary
            ),
            color_secondary=template_data.get(
                "color_secondary", config.template.color_secondary
            ),
        )

    # Load users
    if "users" in data and isinstance(data["users"], dict):
        config.users = {str(k): str(v) for k, v in data["users"].items()}

    # Load managed glob patterns
    if "managed" in data and isinstance(data["managed"], list):
        config.managed = [str(p) for p in data["managed"]]

    # Load template username_placeholder
    if "template" in data and isinstance(data["template"], dict):
        template_data_extra = data["template"]
        if "username_placeholder" in template_data_extra:
            config.template.username_placeholder = template_data_extra[
                "username_placeholder"
            ]

    # Load custom CSS from file
    if "css_file" in data:
        css_file_path = Path(data["css_file"])
        # Resolve relative paths against config file directory
        if not css_file_path.is_absolute():
            css_file_path = config_path.parent / css_file_path
        try:
            config.custom_css = css_file_path.read_text(encoding="utf-8")
        except OSError as e:
            raise LockhtmlError(f"Cannot read CSS file {css_file_path}: {e}") from e

    return config


def create_default_config(path: Path | None = None) -> Path:
    """Create a default .lockhtml.yaml config file.

    Args:
        path: Directory to create config in. Defaults to cwd.

    Returns:
        Path to created config file.

    Raises:
        LockhtmlError: If file already exists or cannot be written.
    """
    if path is None:
        path = Path.cwd()
    else:
        path = Path(path)

    config_path = path / CONFIG_FILENAME

    if config_path.exists():
        raise LockhtmlError(f"Config file already exists: {config_path}")

    # Generate random salt
    salt = generate_salt()

    config_content = f'''# lockhtml configuration
# WARNING: Add this file to .gitignore - it contains your password!

# Password for encryption (or use LOCKHTML_PASSWORD env var)
password: "your-strong-passphrase"

# Salt for consistent password hashing (auto-generated)
# Needed for remember-me and share links to work across re-encryptions
salt: "{salt_to_hex(salt)}"

# Multi-user access (uncomment to enable)
# users:
#   alice: "alice-password"
#   bob: "bob-password"

# Files managed by 'lockhtml sync' (uncomment to enable)
# managed:
#   - "encrypted/**/*.html"
#   - "site/admin/*.html"

# Default behavior
defaults:
  remember: "ask"        # "none", "session", "local", "ask"
  remember_days: 0       # 0 = no expiration
  auto_prompt: true      # Show password prompt on load if locked

# Template customization
template:
  title: "Protected Content"
  button_text: "Unlock"
  error_text: "Incorrect password"
  placeholder: "Enter password"
  # username_placeholder: "Enter username"  # For multi-user mode
  color_primary: "#4CAF50"
  color_secondary: "#76B852"
'''

    try:
        config_path.write_text(config_content)
    except OSError as e:
        raise LockhtmlError(f"Cannot write config file: {e}") from e

    return config_path


def update_config_users(config_path: Path, users: dict[str, str] | None) -> None:
    """Update the users section in a config file.

    Loads the existing YAML, modifies the 'users' key, writes back.
    Note: comments in the original file are not preserved.

    Args:
        config_path: Path to .lockhtml.yaml file.
        users: New users dict, or None to remove the users section.

    Raises:
        LockhtmlError: If file cannot be read or written.
    """
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise LockhtmlError(f"Invalid YAML in {config_path}: {e}") from e
    except OSError as e:
        raise LockhtmlError(f"Cannot read config file {config_path}: {e}") from e

    if users:
        data["users"] = users
    elif "users" in data:
        del data["users"]

    content = "# lockhtml configuration\n"
    content += "# WARNING: Add this file to .gitignore - it contains passwords!\n\n"
    content += yaml.dump(data, default_flow_style=False, sort_keys=False)

    try:
        config_path.write_text(content)
    except OSError as e:
        raise LockhtmlError(f"Cannot write config file {config_path}: {e}") from e


def config_to_dict(config: LockhtmlConfig) -> dict[str, Any]:
    """Convert config to dictionary for display.

    Note: Passwords are masked for security.
    """
    result: dict[str, Any] = {
        "password": "********" if config.password else None,
        "salt": salt_to_hex(config.salt) if config.salt else None,
    }

    if config.users:
        result["users"] = {k: "********" for k in config.users}
    else:
        result["users"] = None

    if config.managed:
        result["managed"] = config.managed
    else:
        result["managed"] = None

    result["defaults"] = {
        "remember": config.defaults.remember,
        "remember_days": config.defaults.remember_days,
        "auto_prompt": config.defaults.auto_prompt,
    }
    result["template"] = {
        "title": config.template.title,
        "button_text": config.template.button_text,
        "error_text": config.template.error_text,
        "placeholder": config.template.placeholder,
        "username_placeholder": config.template.username_placeholder,
        "color_primary": config.template.color_primary,
        "color_secondary": config.template.color_secondary,
    }
    result["config_path"] = str(config.config_path) if config.config_path else None
    return result
