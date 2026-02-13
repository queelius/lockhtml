# Real-World Use Cases

## Hugo Blog with Semi-Private Posts

You maintain a technical blog. Some posts are purely public, others mix public content with private thoughts, client details, or spoilers.

**Workflow:**

```bash
# Content source (Markdown)
content/posts/
├── public-post.md
├── semi-private-post.md (contains <pagevault> markers)
└── ...

# Build site
hugo -o build/

# Encrypt marked regions
pagevault mark build/posts/*semi-private* \
  --hint "Password in newsletter"
pagevault lock build/posts/ -r

# Deploy to GitHub Pages
git add build/_locked/
git commit -m "Publish posts"
git push origin gh-pages
```

**Result:** Posts display normally until readers hit protected sections. Password can be shared in your newsletter, Discord community, etc.

## Shared Knowledge Base

Your team maintains internal documentation. You want to make parts of it publicly discoverable (SEO, reference), but keep implementation details private.

**Example structure:**

```html
<h2>API Overview (Public)</h2>
<p>Our API provides REST endpoints for...</p>

<pagevault hint="See team wiki for credentials">
  <h2>API Key Rotation (Internal Only)</h2>
  <p>Keys rotate every 90 days. Here's how...</p>
</pagevault>

<h2>Rate Limits (Public)</h2>
<p>The API enforces rate limits...</p>

<pagevault hint="Internal only">
  <h2>Troubleshooting (Internal)</h2>
  <p>Common issues and solutions...</p>
</pagevault>
```

**Deploy to Netlify:**

```bash
pagevault lock docs/ -r --hint "See #engineering on Slack"
netlify deploy --dir _locked/
```

**Result:** Public visitors see what's available, team has full access with password.

## Client Progress Reports

You share project status with clients. Some sections (timeline, staffing, risks) are shared; others (internal notes, cost breakdowns) aren't.

**Approach:**

```bash
# Create report HTML
echo '<h1>Project Status</h1>' > report.html
# ... add content with <pagevault> sections ...

# Encrypt for client
pagevault lock report.html \
  -p "client-temporary-password" \
  -o client-report.html

# Email HTML file + password separately
# "Report attached. Password sent via Slack."
```

**Result:** Client can view on local machine or upload to their own site. Temporary password can be regenerated each week.

## Educational Material with Solutions

You publish educational problems publicly, keep solutions behind password.

**HTML structure:**

```html
<problem>
  <h3>Problem 1: Binary Search</h3>
  <p>Implement binary search in Python.</p>
  <p>Expected input/output examples provided...</p>
</problem>

<pagevault hint="Solutions for instructors only">
  <details>
    <summary>Solution</summary>
    <code>def binary_search(arr, target): ...</code>
  </details>
</pagevault>
```

**Workflow:**

```bash
pagevault mark problems.html -s "pagevault" \
  --hint "Instructor password"
pagevault lock problems.html
# Deploy to course website
```

**Result:** Students see problems; instructors enter password for solutions.

## Staging/Preview Content

Before public launch, share preview links with stakeholders.

**Setup:**

```bash
# Generate staging site
pagevault lock staging/ --site \
  -p "preview-password" \
  -o preview.html

# Host on temporary URL
curl -F "file=@preview.html" upload.example.com
# Share link + password with stakeholders
```

**Feedback period:** Stakeholders can test with temporary password.

**Launch:** Regenerate with final password, deploy to public.

## Confidential Technical Documentation

Patent-pending features, beta APIs, unreleased products – document them for team, encrypt for distribution to partners.

```bash
pagevault lock unreleased-features.html \
  -u "partner1" \
  -u "partner2"

pagevault config user add partner1
pagevault config user add partner2
pagevault lock unreleased-features.html
```

Each partner decrypts with their own password. No shared secret.

## Personal Notes on Public Blog

You maintain a public blog but want to keep personal reflections, draft ideas, experimental thinking visible only to close friends/supporters.

**Approach:**

```html
<article>
  <h1>Learning Rust</h1>

  <h2>Public Part: Getting Started</h2>
  <p>Here's how I learned Rust syntax...</p>

  <pagevault hint="Friends only">
    <h2>Personal Reflections</h2>
    <p>Honestly, I struggled with ownership concepts initially...</p>
    <p>These are raw thoughts, not polished advice.</p>
  </pagevault>

  <h2>Resources</h2>
  <ul>...</ul>
</article>
```

Deploy normally; friends know the password.

## Bonus: File Wrapping

Not all use cases need selective encryption. Sometimes you want to wrap *entire files*:

```bash
# PDF report
pagevault lock budget-report.pdf -p "password"
# Creates: budget-report.html (encrypted PDF viewer in browser)

# Spreadsheet
pagevault lock Q4-forecast.csv -p "password"
# Creates: Q4-forecast.html (encrypted data table)

# Image gallery
pagevault lock gallery/ --site -p "password"
# Creates: gallery.html (encrypted site bundle with all images)
```

All files become self-contained, shareable encrypted HTML. No server required.

## CI/CD Pipeline Integration

Use `--stdout` to decrypt wrapped files directly into a pipeline without intermediate files. This is useful for CI/CD systems that need to consume encrypted artifacts.

**Decrypt and process in one step:**

```bash
# Decrypt a wrapped PDF report and save to disk
pagevault unlock report.pdf.html --stdout -p "$SECRET" > report.pdf

# Pipe decrypted content to another tool
pagevault unlock data.csv.html --stdout -p "$SECRET" | csvtool col 1,3 -

# Use in GitHub Actions
- name: Decrypt report
  run: pagevault unlock report.pdf.html --stdout -p "${{ secrets.PAGEVAULT_PASSWORD }}" > report.pdf
```

**Verify before deploying:**

```bash
# Check password before attempting full decrypt
if pagevault check _locked/index.html -p "$DEPLOY_PASSWORD"; then
  pagevault unlock _locked/ -r -p "$DEPLOY_PASSWORD"
else
  echo "Wrong password, aborting deploy"
  exit 1
fi
```

## Audit Workflow

Run regular audits to catch configuration issues before they become problems.

**Pre-deploy audit:**

```bash
#!/bin/bash
set -e

# Audit config before encrypting
pagevault audit -c .pagevault.yaml

# If audit passes, proceed with encryption
pagevault lock site/ -r
rsync -av _locked/ deploy/
```

**Scheduled audit in CI:**

```yaml
# GitHub Actions example
- name: Audit pagevault config
  run: pagevault audit -c .pagevault.yaml
```

The audit checks password strength, salt quality, `.gitignore` hygiene, and integrity of managed encrypted files. Exit code 1 indicates issues that should be addressed.

---

## General Tips

**Password sharing:**
- Email password separately from HTML file
- Use shared password managers (1Password Teams, Bitwarden)
- Share via secure chat (Signal, encrypted email)
- Include password hint in prompt

**Recovery:**
- Always keep `.pagevault.yaml` backed up (or in secure storage)
- Test decryption before deploying
- Document password locations for team

**Iteration:**
- Use `pagevault unlock` to restore plaintext
- Edit, then re-encrypt with `pagevault lock`
- Update password and sync if needed: `pagevault sync _locked/ -r`

**Automation:**
```bash
#!/bin/bash
# Workflow for Hugo blog

hugo -o build/
pagevault mark build/ -r -s ".private"
pagevault lock build/ -r
rsync -av build/_locked/ deploy/
git add deploy/
git commit -m "Publish $(date)"
```

---

See [Getting Started](getting-started.md) for step-by-step examples.

See [CLI Reference](cli-reference.md) for all commands.
