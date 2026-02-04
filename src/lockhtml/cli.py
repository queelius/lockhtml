"""Command-line interface for lockhtml."""

from pathlib import Path

import click
import yaml

from . import __version__
from .config import (
    CONFIG_FILENAME,
    config_to_dict,
    create_default_config,
    find_config_file,
    load_config,
)
from .crypto import LockhtmlError
from .parser import (
    has_lockhtml_elements,
    process_file,
    sync_html_keys,
    wrap_body_for_encryption,
    wrap_elements_for_encryption,
)


@click.group()
@click.version_option(version=__version__, prog_name="lockhtml")
def main():
    """Password-protect regions of HTML files for static hosting.

    lockhtml encrypts <lockhtml-encrypt> regions in HTML files, allowing
    mixed public/private content on static sites like GitHub Pages.

    \b
    Quick start:
      lockhtml config init          # Create .lockhtml.yaml
      lockhtml encrypt index.html   # Encrypt HTML file
      lockhtml decrypt encrypted/   # Restore original
      lockhtml sync encrypted/ -r   # Re-wrap keys for current users
    """
    pass


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-d",
    "--directory",
    "output_dir",
    type=click.Path(),
    help="Output directory (default: encrypted/)",
)
@click.option("-p", "--password", help="Encryption password (or use config/env)")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
@click.option("--dry-run", is_flag=True, help="Show what would be done without changes")
@click.option(
    "--css",
    "css_path",
    type=click.Path(exists=True),
    help="Custom CSS file for lockhtml elements (replaces default styles)",
)
@click.option(
    "-s",
    "--selector",
    "selectors",
    multiple=True,
    help="CSS selector(s) to encrypt (can specify multiple)",
)
@click.option(
    "--hint",
    "selector_hint",
    help="Password hint for elements matched by selectors",
)
@click.option(
    "--remember",
    "selector_remember",
    type=click.Choice(["none", "session", "local", "ask"]),
    help="Remember mode for elements matched by selectors",
)
@click.option(
    "--title",
    "selector_title",
    help="Title for encrypted region (replaces default 'Protected Content')",
)
def encrypt(
    paths,
    recursive,
    output_dir,
    password,
    config_path,
    dry_run,
    css_path,
    selectors,
    selector_hint,
    selector_remember,
    selector_title,
):
    """Encrypt HTML files with <lockhtml-encrypt> regions.

    Without --selector, wraps all body content in a single encrypted region.
    With --selector, only wraps elements matching the CSS selector(s).

    \b
    Examples:
      lockhtml encrypt index.html
      lockhtml encrypt site/ -r
      lockhtml encrypt site/ -r -d encrypted/
      lockhtml encrypt file.html -p "password"
      lockhtml encrypt site/ --css custom.css
      lockhtml encrypt file.html --selector "#secret"
      lockhtml encrypt file.html -s "#main" -s ".private" --hint "Password hint"
      lockhtml encrypt file.html -s "#admin" --title "Admin Panel" -p "admin-pw"
    """
    if not paths:
        raise click.UsageError("No files or directories specified")

    # Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(paths[0]) if paths else None,
            password_override=password,
        )
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    # Determine multi-user vs single-user mode
    users = config.users
    if password and users:
        # CLI -p flag wins, single-user mode
        users = None
        pwd = password
    elif users:
        pwd = None  # Not needed, users dict has passwords
    else:
        pwd = config.password
        if not pwd:
            pwd = click.prompt("Enter encryption password", hide_input=True)

    # Load custom CSS if provided
    custom_css = None
    if css_path:
        try:
            custom_css = Path(css_path).read_text(encoding="utf-8")
        except OSError as e:
            raise click.ClickException(f"Cannot read CSS file: {e}")

    # Set default output directory
    if output_dir is None:
        output_dir = "encrypted"
    output_base = Path(output_dir)

    # Collect files to process
    files = _collect_files(paths, recursive)

    if not files:
        click.echo("No HTML files found")
        return

    # Process files
    processed = 0
    skipped = 0

    for input_path in files:
        # Determine output path
        output_path = _get_output_path(input_path, paths, output_base)

        # Read file content
        try:
            content = input_path.read_text(encoding="utf-8")
        except OSError as e:
            click.echo(f"Warning: Cannot read {input_path}: {e}", err=True)
            continue

        # Apply wrapping
        content_was_wrapped = False
        if selectors:
            content = wrap_elements_for_encryption(
                content,
                list(selectors),
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )
            content_was_wrapped = has_lockhtml_elements(content)
        elif not has_lockhtml_elements(content):
            # Default: wrap all body content
            content = wrap_body_for_encryption(
                content,
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )
            content_was_wrapped = has_lockhtml_elements(content)

        # Check for lockhtml elements (including newly wrapped ones)
        if not has_lockhtml_elements(content):
            skipped += 1
            continue

        rel_input = _relative_path(input_path)
        rel_output = _relative_path(output_path)

        if dry_run:
            click.echo(f"Would encrypt: {rel_input} -> {rel_output}")
            processed += 1
            continue

        try:
            # If content was wrapped (selector or body), write modified content
            # to output first, then encrypt from output
            if content_was_wrapped or selectors:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(content, encoding="utf-8")
                changed = process_file(
                    output_path,
                    output_path,
                    password=pwd,
                    config=config,
                    encrypt_mode=True,
                    custom_css=custom_css,
                    users=users,
                )
            else:
                changed = process_file(
                    input_path,
                    output_path,
                    password=pwd,
                    config=config,
                    encrypt_mode=True,
                    custom_css=custom_css,
                    users=users,
                )
            if changed:
                click.echo(f"Encrypted: {rel_input} -> {rel_output}")
                processed += 1
            else:
                skipped += 1
        except LockhtmlError as e:
            click.echo(f"Error processing {rel_input}: {e}", err=True)

    click.echo(f"\n{processed} file(s) encrypted, {skipped} skipped")


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-d",
    "--directory",
    "output_dir",
    type=click.Path(),
    help="Output directory (default: decrypted/)",
)
@click.option("-p", "--password", help="Decryption password (or use config/env)")
@click.option("-u", "--username", help="Username for multi-user encrypted content")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
@click.option("--dry-run", is_flag=True, help="Show what would be done without changes")
def decrypt(paths, recursive, output_dir, password, config_path, dry_run, username):
    """Decrypt HTML files with encrypted <lockhtml-encrypt> regions.

    \b
    Examples:
      lockhtml decrypt encrypted/index.html
      lockhtml decrypt encrypted/ -r
      lockhtml decrypt encrypted/ -r -d restored/
      lockhtml decrypt encrypted/file.html -u alice -p "alice-pw"
    """
    if not paths:
        raise click.UsageError("No files or directories specified")

    # Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(paths[0]) if paths else None,
            password_override=password,
        )
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    # Get password
    pwd = config.password
    if not pwd:
        pwd = click.prompt("Enter decryption password", hide_input=True)

    # Set default output directory
    if output_dir is None:
        output_dir = "decrypted"
    output_base = Path(output_dir)

    # Collect files to process
    files = _collect_files(paths, recursive)

    if not files:
        click.echo("No HTML files found")
        return

    # Process files
    processed = 0
    skipped = 0

    for input_path in files:
        output_path = _get_output_path(input_path, paths, output_base)

        # Quick check for lockhtml elements
        try:
            content = input_path.read_text(encoding="utf-8")
        except OSError as e:
            click.echo(f"Warning: Cannot read {input_path}: {e}", err=True)
            continue

        if not has_lockhtml_elements(content):
            skipped += 1
            continue

        rel_input = _relative_path(input_path)
        rel_output = _relative_path(output_path)

        if dry_run:
            click.echo(f"Would decrypt: {rel_input} -> {rel_output}")
            processed += 1
            continue

        try:
            changed = process_file(
                input_path,
                output_path,
                password=pwd,
                config=config,
                encrypt_mode=False,
                username=username,
            )
            if changed:
                click.echo(f"Decrypted: {rel_input} -> {rel_output}")
                processed += 1
            else:
                skipped += 1
        except LockhtmlError as e:
            click.echo(f"Error processing {rel_input}: {e}", err=True)

    click.echo(f"\n{processed} file(s) decrypted, {skipped} skipped")


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
@click.option("--dry-run", is_flag=True, help="Show what would be done without changes")
@click.option("--rekey", is_flag=True, help="Generate new content encryption key")
def sync(paths, recursive, config_path, dry_run, rekey):
    """Re-wrap encryption keys for current users.

    Updates encrypted files so that the current set of users in the config
    can decrypt them. Use after adding or removing users.

    If no paths are given, uses the 'managed' globs from the config file.

    \b
    Examples:
      lockhtml sync encrypted/ -r
      lockhtml sync encrypted/ -r --rekey
      lockhtml sync -c .lockhtml.yaml --dry-run
    """
    # Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(paths[0]) if paths else None,
        )
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    if not config.users:
        raise click.ClickException(
            "No 'users' defined in config. sync requires multi-user configuration."
        )

    # Determine files to process
    if paths:
        files = _collect_files(paths, recursive)
    elif config.managed and config.config_path:
        # Resolve managed globs relative to config file location
        config_dir = config.config_path.parent
        files = []
        for pattern in config.managed:
            matched = sorted(config_dir.glob(pattern))
            files.extend(
                f
                for f in matched
                if f.is_file() and f.suffix.lower() in {".html", ".htm"}
            )
        files = sorted(set(files))
    else:
        raise click.ClickException(
            "No paths specified and no 'managed' globs in config."
        )

    if not files:
        click.echo("No HTML files found")
        return

    processed = 0
    skipped = 0

    for input_path in files:
        try:
            content = input_path.read_text(encoding="utf-8")
        except OSError as e:
            click.echo(f"Warning: Cannot read {input_path}: {e}", err=True)
            continue

        if not has_lockhtml_elements(content):
            skipped += 1
            continue

        rel_path = _relative_path(input_path)

        if dry_run:
            click.echo(f"Would sync: {rel_path}")
            processed += 1
            continue

        try:
            result = sync_html_keys(
                content,
                old_users=config.users,  # Use current users to recover CEK
                new_users=config.users,
                rekey=rekey,
            )

            if result != content:
                input_path.write_text(result, encoding="utf-8")
                click.echo(f"Synced: {rel_path}")
                processed += 1
            else:
                skipped += 1
        except LockhtmlError as e:
            click.echo(f"Error syncing {rel_path}: {e}", err=True)

    click.echo(f"\n{processed} file(s) synced, {skipped} skipped")


@main.group()
def config():
    """Manage lockhtml configuration."""
    pass


@config.command("init")
@click.option(
    "-d",
    "--directory",
    type=click.Path(),
    default=".",
    help="Directory to create config in",
)
def config_init(directory):
    """Create a new .lockhtml.yaml configuration file.

    Generates a config file with a random salt and example settings.
    Remember to add .lockhtml.yaml to your .gitignore!
    """
    try:
        config_path = create_default_config(Path(directory))
        click.echo(f"Created: {config_path}")
        click.echo("\nNext steps:")
        click.echo("  1. Edit the password in .lockhtml.yaml")
        click.echo("  2. Add .lockhtml.yaml to .gitignore")
        click.echo("  3. Run: lockhtml encrypt <file.html>")
    except LockhtmlError as e:
        raise click.ClickException(str(e))


@config.command("show")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def config_show(config_path):
    """Display current configuration.

    Shows merged configuration from file, environment, and defaults.
    Password is masked for security.
    """
    try:
        cfg = load_config(config_path=Path(config_path) if config_path else None)
        data = config_to_dict(cfg)
        click.echo(yaml.dump(data, default_flow_style=False, sort_keys=False))
    except LockhtmlError as e:
        raise click.ClickException(str(e))


@config.command("where")
@click.option(
    "-d",
    "--directory",
    type=click.Path(exists=True),
    help="Directory to search from",
)
def config_where(directory):
    """Show which config file would be used.

    Searches up the directory tree for .lockhtml.yaml.
    """
    start = Path(directory) if directory else Path.cwd()
    config_path = find_config_file(start)

    if config_path:
        click.echo(f"Config file: {config_path}")
    else:
        click.echo(f"No {CONFIG_FILENAME} found (searched from {start})")


def _collect_files(paths: tuple, recursive: bool) -> list[Path]:
    """Collect HTML files from paths.

    Args:
        paths: Tuple of file/directory paths.
        recursive: Whether to search directories recursively.

    Returns:
        List of HTML file paths.
    """
    files = []
    html_extensions = {".html", ".htm"}

    for path_str in paths:
        path = Path(path_str)

        if path.is_file():
            if path.suffix.lower() in html_extensions:
                files.append(path)
        elif path.is_dir():
            if recursive:
                for ext in html_extensions:
                    files.extend(path.rglob(f"*{ext}"))
            else:
                for ext in html_extensions:
                    files.extend(path.glob(f"*{ext}"))

    return sorted(set(files))


def _get_output_path(input_path: Path, source_paths: tuple, output_base: Path) -> Path:
    """Determine output path for a file.

    Args:
        input_path: Original file path.
        source_paths: Original source paths from command.
        output_base: Base output directory.

    Returns:
        Output file path.
    """
    # Find which source path contains this file
    input_resolved = input_path.resolve()

    for source in source_paths:
        source_path = Path(source).resolve()

        if source_path.is_file():
            if input_resolved == source_path:
                return output_base / input_path.name
        elif source_path.is_dir():
            try:
                rel = input_resolved.relative_to(source_path)
                return output_base / rel
            except ValueError:
                continue

    # Fallback: just use filename
    return output_base / input_path.name


def _relative_path(path: Path) -> str:
    """Get a relative path for display."""
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    main()
