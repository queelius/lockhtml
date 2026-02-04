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
    update_config_users,
)
from .crypto import LockhtmlError
from .parser import (
    has_lockhtml_elements,
    mark_body,
    mark_elements,
    process_file,
    sync_html_keys,
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
      lockhtml mark index.html      # Tag elements for encryption
      lockhtml lock index.html      # Encrypt HTML file
      lockhtml unlock _locked/      # Restore original
      lockhtml sync _locked/ -r     # Re-wrap keys for current users
      lockhtml wrap file paper.pdf  # Encrypt arbitrary file
    """
    pass


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-s",
    "--selector",
    "selectors",
    multiple=True,
    help="CSS selector(s) to mark (can specify multiple)",
)
@click.option(
    "--hint",
    "selector_hint",
    help="Password hint for marked elements",
)
@click.option(
    "--remember",
    "selector_remember",
    type=click.Choice(["none", "session", "local", "ask"]),
    help="Remember mode for marked elements",
)
@click.option(
    "--title",
    "selector_title",
    help="Title for encrypted region (replaces default 'Protected Content')",
)
def mark(
    paths,
    recursive,
    selectors,
    selector_hint,
    selector_remember,
    selector_title,
):
    """Tag elements for encryption (in-place).

    With --selector, wraps matching elements in <lockhtml-encrypt> tags.
    Without --selector, wraps all <body> innerHTML in a single <lockhtml-encrypt>.

    Files are modified in-place. Content stays readable plaintext until locked.

    \b
    Examples:
      lockhtml mark index.html -s "#secret"
      lockhtml mark site/ -r -s ".private"
      lockhtml mark page.html --hint "Contact admin" --title "Members Only"
      lockhtml mark page.html  # wraps entire body
    """
    if not paths:
        raise click.UsageError("No files or directories specified")

    # Collect files to process
    files = _collect_files(paths, recursive)

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

        # Skip files already having lockhtml-encrypt elements (unless using selectors)
        if not selectors and has_lockhtml_elements(content):
            skipped += 1
            continue

        if selectors:
            modified = mark_elements(
                content,
                list(selectors),
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )
        else:
            modified = mark_body(
                content,
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )

        if modified == content or not has_lockhtml_elements(modified):
            skipped += 1
            continue

        rel_path = _relative_path(input_path)

        # Write in-place
        try:
            input_path.write_text(modified, encoding="utf-8")
            click.echo(f"Marked: {rel_path}")
            processed += 1
        except OSError as e:
            click.echo(f"Error writing {rel_path}: {e}", err=True)

    click.echo(f"\n{processed} file(s) marked, {skipped} skipped")


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-d",
    "--directory",
    "output_dir",
    type=click.Path(),
    help="Output directory (default: _locked/)",
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
def lock(
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
    """Lock (encrypt) HTML files with <lockhtml-encrypt> regions.

    Without --selector, auto-wraps body content if no <lockhtml-encrypt> elements exist.
    With --selector, wraps matching elements then encrypts.

    \b
    Examples:
      lockhtml lock index.html
      lockhtml lock site/ -r
      lockhtml lock site/ -r -d _locked/
      lockhtml lock file.html -p "password"
      lockhtml lock site/ --css custom.css
      lockhtml lock file.html --selector "#secret"
      lockhtml lock file.html -s "#main" -s ".private" --hint "Password hint"
      lockhtml lock file.html -s "#admin" --title "Admin Panel" -p "admin-pw"
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
        output_dir = "_locked"
        click.echo(f"Writing to {output_dir}/ (use -d to change)")
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
            content = mark_elements(
                content,
                list(selectors),
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )
            content_was_wrapped = has_lockhtml_elements(content)
        elif not has_lockhtml_elements(content):
            # Default: wrap all body content
            content = mark_body(
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
            click.echo(f"Would lock: {rel_input} -> {rel_output}")
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
                    mode="lock",
                    custom_css=custom_css,
                    users=users,
                )
            else:
                changed = process_file(
                    input_path,
                    output_path,
                    password=pwd,
                    config=config,
                    mode="lock",
                    custom_css=custom_css,
                    users=users,
                )
            if changed:
                click.echo(f"Locked: {rel_input} -> {rel_output}")
                processed += 1
            else:
                skipped += 1
        except LockhtmlError as e:
            click.echo(f"Error processing {rel_input}: {e}", err=True)

    click.echo(f"\n{processed} file(s) locked, {skipped} skipped")


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-d",
    "--directory",
    "output_dir",
    type=click.Path(),
    help="Output directory (default: _unlocked/)",
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
def unlock(paths, recursive, output_dir, password, config_path, dry_run, username):
    """Unlock (decrypt) HTML files with encrypted <lockhtml-encrypt> regions.

    Returns files to "marked" state (plaintext inside <lockhtml-encrypt> wrappers).

    \b
    Examples:
      lockhtml unlock _locked/index.html
      lockhtml unlock _locked/ -r
      lockhtml unlock _locked/ -r -d _unlocked/
      lockhtml unlock _locked/file.html -u alice -p "alice-pw"
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
        output_dir = "_unlocked"
        click.echo(f"Writing to {output_dir}/ (use -d to change)")
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
            click.echo(f"Would unlock: {rel_input} -> {rel_output}")
            processed += 1
            continue

        try:
            changed = process_file(
                input_path,
                output_path,
                password=pwd,
                config=config,
                mode="unlock",
                username=username,
            )
            if changed:
                click.echo(f"Unlocked: {rel_input} -> {rel_output}")
                processed += 1
            else:
                skipped += 1
        except LockhtmlError as e:
            click.echo(f"Error processing {rel_input}: {e}", err=True)

    click.echo(f"\n{processed} file(s) unlocked, {skipped} skipped")


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
        click.echo("  3. Run: lockhtml lock <file.html>")
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


@config.group()
def user():
    """Manage users for multi-user encryption."""
    pass


def _resolve_config_path(config_path: str | None) -> Path:
    """Find config file from explicit path or directory traversal.

    Args:
        config_path: Explicit path from -c flag, or None.

    Returns:
        Resolved Path to config file.

    Raises:
        click.ClickException: If no config file found.
    """
    if config_path:
        return Path(config_path)
    found = find_config_file()
    if not found:
        raise click.ClickException(
            f"No {CONFIG_FILENAME} found. Run 'lockhtml config init' first."
        )
    return found


@user.command("add")
@click.argument("username")
@click.option("-p", "--password", "user_password", help="Password (prompts if omitted)")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def user_add(username, user_password, config_path):
    """Add a new user to the config.

    Prompts for password interactively unless -p is given.
    """
    resolved = _resolve_config_path(config_path)

    # Validate username
    if not username:
        raise click.ClickException("Username cannot be empty.")
    if ":" in username:
        raise click.ClickException(
            f"Username '{username}' cannot contain ':' (used as delimiter)."
        )

    # Load current config
    try:
        cfg = load_config(config_path=resolved)
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    users = dict(cfg.users) if cfg.users else {}

    if username in users:
        raise click.ClickException(
            f"User '{username}' already exists. "
            "Use 'lockhtml config user passwd' to change their password."
        )

    # Get password
    if not user_password:
        user_password = click.prompt(
            "Password", hide_input=True, confirmation_prompt=True
        )
    if not user_password:
        raise click.ClickException("Password cannot be empty.")

    users[username] = user_password

    try:
        update_config_users(resolved, users)
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    click.echo(f"Added user '{username}'.")
    click.echo("Run 'lockhtml sync' to update encrypted files for the new user.")


@user.command("rm")
@click.argument("username")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def user_rm(username, config_path):
    """Remove a user from the config."""
    resolved = _resolve_config_path(config_path)

    try:
        cfg = load_config(config_path=resolved)
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    users = dict(cfg.users) if cfg.users else {}

    if username not in users:
        raise click.ClickException(f"User '{username}' not found.")

    del users[username]

    try:
        update_config_users(resolved, users if users else None)
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    click.echo(f"Removed user '{username}'.")
    click.echo("Run 'lockhtml sync' to update encrypted files.")


@user.command("list")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def user_list(config_path):
    """List configured users."""
    resolved = _resolve_config_path(config_path)

    try:
        cfg = load_config(config_path=resolved)
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    if not cfg.users:
        click.echo("(no users configured)")
        return

    for name in cfg.users:
        click.echo(name)


@user.command("passwd")
@click.argument("username")
@click.option(
    "-p",
    "--password",
    "user_password",
    help="New password (prompts if omitted)",
)
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def user_passwd(username, user_password, config_path):
    """Change a user's password."""
    resolved = _resolve_config_path(config_path)

    try:
        cfg = load_config(config_path=resolved)
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    users = dict(cfg.users) if cfg.users else {}

    if username not in users:
        raise click.ClickException(f"User '{username}' not found.")

    if not user_password:
        user_password = click.prompt(
            "New password", hide_input=True, confirmation_prompt=True
        )
    if not user_password:
        raise click.ClickException("Password cannot be empty.")

    users[username] = user_password

    try:
        update_config_users(resolved, users)
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    click.echo(f"Password updated for '{username}'.")
    click.echo("Run 'lockhtml sync' to update encrypted files.")


@main.group()
def wrap():
    """Encrypt arbitrary files into self-contained HTML.

    \b
    Commands:
      lockhtml wrap file <path>  Wrap a single file
      lockhtml wrap site <dir>   Wrap a directory as a site
    """
    pass


@wrap.command("file")
@click.argument("path", type=click.Path(exists=True))
@click.option("-p", "--password", help="Encryption password")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(),
    help="Output HTML file path (default: <filename>.html)",
)
def wrap_file_cmd(path, password, config_path, output_path):
    """Wrap a single file into self-contained encrypted HTML.

    The output HTML file contains everything needed to decrypt and view
    the file in a browser — no server required.

    \b
    Examples:
      lockhtml wrap file paper.pdf -p "password"
      lockhtml wrap file diagram.png -p "password" -o diagram.html
      lockhtml wrap file data.csv -c .lockhtml.yaml
    """
    from .wrap import wrap_file

    # Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(path),
            password_override=password,
        )
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    # Determine password and users
    users = config.users
    if password and users:
        users = None
        pwd = password
    elif users:
        pwd = None
    else:
        pwd = config.password
        if not pwd:
            pwd = click.prompt("Enter encryption password", hide_input=True)

    try:
        result = wrap_file(
            Path(path),
            password=pwd,
            config=config,
            output_path=Path(output_path) if output_path else None,
            users=users,
        )
        click.echo(f"Wrapped: {path} -> {result}")
    except LockhtmlError as e:
        raise click.ClickException(str(e))


@wrap.command("site")
@click.argument("path", type=click.Path(exists=True))
@click.option("-p", "--password", help="Encryption password")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(),
    help="Output HTML file path (default: <dirname>.html)",
)
@click.option(
    "--entry",
    default="index.html",
    help="Entry point HTML file within the directory (default: index.html)",
)
def wrap_site_cmd(path, password, config_path, output_path, entry):
    """Wrap a directory into self-contained encrypted HTML.

    All files in the directory are compressed and encrypted into a single
    HTML file. The browser extracts and renders the site after decryption.

    \b
    Examples:
      lockhtml wrap site my-site/ -p "password"
      lockhtml wrap site my-site/ -p "password" -o my-site.html
      lockhtml wrap site docs/ -p "password" --entry home.html
    """
    from .wrap import wrap_site

    # Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(path),
            password_override=password,
        )
    except LockhtmlError as e:
        raise click.ClickException(str(e))

    # Determine password and users
    users = config.users
    if password and users:
        users = None
        pwd = password
    elif users:
        pwd = None
    else:
        pwd = config.password
        if not pwd:
            pwd = click.prompt("Enter encryption password", hide_input=True)

    try:
        result = wrap_site(
            Path(path),
            password=pwd,
            config=config,
            output_path=Path(output_path) if output_path else None,
            users=users,
            entry=entry,
        )
        click.echo(f"Wrapped: {path} -> {result}")
    except LockhtmlError as e:
        raise click.ClickException(str(e))


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
