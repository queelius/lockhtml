# lockhtml

Password-protect regions of HTML files for static hosting.

## Overview

**lockhtml** encrypts marked regions of HTML files using `<lockhtml-encrypt>` custom elements, enabling mixed public/private content on static sites (GitHub Pages, Netlify, etc.).

Unlike tools that wrap entire pages, lockhtml preserves HTML structure - headers, footers, navigation, scripts, and styles stay public while only the marked content is encrypted.

## Installation

```bash
pip install lockhtml
```

## Quick Start

1. Mark content to protect:

```html
<!DOCTYPE html>
<html>
<head>
  <title>My Page</title>
  <script src="app.js"></script>
</head>
<body>
  <header>Public navigation</header>

  <lockhtml-encrypt hint="Contact admin for password">
    <main>
      <p>This content gets encrypted...</p>
    </main>
  </lockhtml-encrypt>

  <footer>Public footer</footer>
</body>
</html>
```

2. Initialize configuration:

```bash
lockhtml config init
# Edit .lockhtml.yaml to set your password
```

3. Encrypt:

```bash
lockhtml encrypt index.html
lockhtml encrypt site/ -r -d encrypted/
```

4. Deploy the encrypted files to your static host.

## Configuration

Create `.lockhtml.yaml` (add to `.gitignore`!):

```yaml
password: "your-strong-passphrase"
salt: "auto-generated-on-init"

defaults:
  remember: "ask"        # "none", "session", "local", "ask"
  remember_days: 0       # 0 = no expiration
  auto_prompt: true      # Show password prompt on load

template:
  title: "Protected Content"
  button_text: "Unlock"
  error_text: "Incorrect password"
```

Or use environment variable: `LOCKHTML_PASSWORD`

## CLI Reference

```bash
# Encrypt
lockhtml encrypt file.html
lockhtml encrypt site/ -r                    # Recursive
lockhtml encrypt site/ -r -d encrypted/      # Output directory
lockhtml encrypt file.html -p "password"     # Override password

# Decrypt (restore original)
lockhtml decrypt encrypted/file.html
lockhtml decrypt encrypted/ -r -d restored/

# Config
lockhtml config init          # Create .lockhtml.yaml
lockhtml config show          # Display current config
lockhtml config where         # Find config file location
```

## Browser Features

The encrypted HTML includes a Web Component that provides:

- **Password prompt**: Auto-shows on page load (configurable)
- **Remember-me**: Store password in localStorage/sessionStorage
- **Auto-decrypt links**: `#lockhtml_pwd=<password>` URL fragment
- **Logout**: `#lockhtml_logout` clears stored passwords
- **Event dispatch**: `lockhtml:decrypted` event for scripts

## Security

- AES-256-GCM encryption
- PBKDF2-SHA256 key derivation (310,000 iterations)
- Compatible with WebCrypto API
- Consistent salt for remember-me/share links across re-encryptions

## License

MIT
