"""Tests for lockhtml.config module."""

import pytest

from lockhtml.config import (
    CONFIG_FILENAME,
    DefaultsConfig,
    LockhtmlConfig,
    TemplateConfig,
    config_to_dict,
    create_default_config,
    find_config_file,
    load_config,
)
from lockhtml.crypto import LockhtmlError, generate_salt, salt_to_hex


class TestFindConfigFile:
    """Tests for find_config_file function."""

    def test_finds_config_in_current_dir(self, tmp_path):
        """Test finding config in current directory."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("password: test")

        found = find_config_file(tmp_path)
        assert found == config_path

    def test_finds_config_in_parent_dir(self, tmp_path):
        """Test finding config by traversing up."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("password: test")

        subdir = tmp_path / "sub" / "deep"
        subdir.mkdir(parents=True)

        found = find_config_file(subdir)
        assert found == config_path

    def test_returns_none_when_not_found(self, tmp_path):
        """Test returns None when no config found."""
        found = find_config_file(tmp_path)
        assert found is None

    def test_starts_from_file_path(self, tmp_path):
        """Test starting from a file path uses parent directory."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("password: test")

        file_path = tmp_path / "index.html"
        file_path.write_text("<html></html>")

        found = find_config_file(file_path)
        assert found == config_path


class TestLoadConfig:
    """Tests for load_config function."""

    def test_loads_from_file(self, tmp_path):
        """Test loading config from file."""
        salt = generate_salt()
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(f"""
password: "secret123"
salt: "{salt_to_hex(salt)}"
defaults:
  remember: "local"
  remember_days: 30
  auto_prompt: false
template:
  title: "Custom Title"
  button_text: "Open"
""")

        config = load_config(config_path=config_path)

        assert config.password == "secret123"
        assert config.salt == salt
        assert config.defaults.remember == "local"
        assert config.defaults.remember_days == 30
        assert config.defaults.auto_prompt is False
        assert config.template.title == "Custom Title"
        assert config.template.button_text == "Open"
        assert config.config_path == config_path

    def test_password_override(self, tmp_path):
        """Test password can be overridden."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "from-file"')

        config = load_config(config_path=config_path, password_override="from-arg")
        assert config.password == "from-arg"

    def test_env_override(self, tmp_path, monkeypatch):
        """Test environment variables override config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "from-file"')

        monkeypatch.setenv("LOCKHTML_PASSWORD", "from-env")

        config = load_config(config_path=config_path)
        assert config.password == "from-env"

    def test_arg_overrides_env(self, tmp_path, monkeypatch):
        """Test function argument overrides environment."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "from-file"')

        monkeypatch.setenv("LOCKHTML_PASSWORD", "from-env")

        config = load_config(config_path=config_path, password_override="from-arg")
        assert config.password == "from-arg"

    def test_missing_explicit_config_fails(self, tmp_path):
        """Test explicit config path that doesn't exist fails."""
        with pytest.raises(LockhtmlError, match="not found"):
            load_config(config_path=tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_fails(self, tmp_path):
        """Test invalid YAML fails."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("invalid: yaml: syntax:")

        with pytest.raises(LockhtmlError, match="Invalid YAML"):
            load_config(config_path=config_path)

    def test_invalid_remember_value_fails(self, tmp_path):
        """Test invalid remember value fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
defaults:
  remember: "invalid"
""")

        with pytest.raises(LockhtmlError, match="Invalid remember value"):
            load_config(config_path=config_path)

    def test_negative_remember_days_fails(self, tmp_path):
        """Test negative remember_days fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
defaults:
  remember_days: -1
""")

        with pytest.raises(LockhtmlError, match="non-negative"):
            load_config(config_path=config_path)

    def test_defaults_without_file(self):
        """Test loading defaults when no config file exists."""
        config = load_config(start_path="/nonexistent/path")

        assert config.password is None
        assert config.salt is None
        assert config.defaults.remember == "ask"
        assert config.defaults.remember_days == 0
        assert config.defaults.auto_prompt is True
        assert config.config_path is None


class TestCreateDefaultConfig:
    """Tests for create_default_config function."""

    def test_creates_config_file(self, tmp_path):
        """Test creating a new config file."""
        config_path = create_default_config(tmp_path)

        assert config_path.exists()
        assert config_path.name == CONFIG_FILENAME

        content = config_path.read_text()
        assert "password:" in content
        assert "salt:" in content
        assert "defaults:" in content
        assert "template:" in content

    def test_generated_salt_is_valid(self, tmp_path):
        """Test generated salt can be loaded."""
        create_default_config(tmp_path)

        # Should be able to load without error
        config = load_config(config_path=tmp_path / CONFIG_FILENAME)
        assert config.salt is not None
        assert len(config.salt) == 16

    def test_fails_if_exists(self, tmp_path):
        """Test fails if config already exists."""
        (tmp_path / CONFIG_FILENAME).write_text("existing")

        with pytest.raises(LockhtmlError, match="already exists"):
            create_default_config(tmp_path)


class TestConfigToDict:
    """Tests for config_to_dict function."""

    def test_masks_password(self):
        """Test password is masked in output."""
        config = LockhtmlConfig(password="secret")
        data = config_to_dict(config)

        assert data["password"] == "********"

    def test_none_password(self):
        """Test None password shows as None."""
        config = LockhtmlConfig()
        data = config_to_dict(config)

        assert data["password"] is None

    def test_includes_all_fields(self):
        """Test all fields are included."""
        salt = generate_salt()
        config = LockhtmlConfig(
            password="test",
            salt=salt,
            defaults=DefaultsConfig(remember="local", remember_days=7),
            template=TemplateConfig(title="Test"),
        )
        data = config_to_dict(config)

        assert "password" in data
        assert "salt" in data
        assert "defaults" in data
        assert "template" in data
        assert data["salt"] == salt_to_hex(salt)
        assert data["defaults"]["remember"] == "local"
        assert data["template"]["title"] == "Test"


class TestUsersConfig:
    """Tests for v2 multi-user, managed, and related config features."""

    def test_loads_users_from_yaml(self, tmp_path):
        """Test loading users dict from config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  alice: "pw-a"
  bob: "pw-b"
""")
        config = load_config(config_path=config_path)
        assert config.users == {"alice": "pw-a", "bob": "pw-b"}

    def test_loads_managed_from_yaml(self, tmp_path):
        """Test loading managed glob patterns from config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
managed:
  - "encrypted/**/*.html"
""")
        config = load_config(config_path=config_path)
        assert config.managed == ["encrypted/**/*.html"]

    def test_username_with_colon_fails(self, tmp_path):
        """Test that a username containing ':' fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  "alice:admin": "pw"
""")
        with pytest.raises(LockhtmlError, match="cannot contain ':'"):
            load_config(config_path=config_path)

    def test_empty_username_fails(self, tmp_path):
        """Test that an empty username fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  "": "pw"
""")
        with pytest.raises(LockhtmlError, match="cannot be empty"):
            load_config(config_path=config_path)

    def test_empty_password_fails(self, tmp_path):
        """Test that an empty password for a user fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  alice: ""
""")
        with pytest.raises(LockhtmlError, match="cannot be empty"):
            load_config(config_path=config_path)

    def test_users_empty_dict_fails(self, tmp_path):
        """Test that an empty users dict fails validation."""
        config = LockhtmlConfig(users={})
        with pytest.raises(LockhtmlError, match="non-empty dictionary"):
            config.validate()

    def test_config_to_dict_masks_user_passwords(self):
        """Test that config_to_dict masks all user passwords."""
        config = LockhtmlConfig(users={"alice": "pw"})
        data = config_to_dict(config)
        assert data["users"] == {"alice": "********"}

    def test_config_to_dict_includes_managed(self):
        """Test that config_to_dict includes managed patterns."""
        config = LockhtmlConfig(managed=["*.html"])
        data = config_to_dict(config)
        assert data["managed"] == ["*.html"]

    def test_users_and_password_coexist(self, tmp_path):
        """Test that both password and users can be set simultaneously."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "main-pw"
users:
  alice: "pw-a"
  bob: "pw-b"
""")
        config = load_config(config_path=config_path)
        assert config.password == "main-pw"
        assert config.users == {"alice": "pw-a", "bob": "pw-b"}

    def test_username_placeholder_loaded(self, tmp_path):
        """Test that template.username_placeholder is loaded from config."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
template:
  username_placeholder: "Who are you?"
""")
        config = load_config(config_path=config_path)
        assert config.template.username_placeholder == "Who are you?"

    def test_create_default_config_has_users_section(self, tmp_path):
        """Test that created default config contains commented-out users section."""
        config_path = create_default_config(tmp_path)
        content = config_path.read_text()
        assert "# users:" in content
        assert "#   alice:" in content
