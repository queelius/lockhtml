# lockhtml examples

Self-contained HTML files for experimenting with lockhtml.

## Files

### `simple.html` - Minimal starter
Color-coded public (green) and secret (red) sections. Good for a first test.

```bash
# Encrypt all secret sections at once
lockhtml encrypt simple.html -s ".secret" -p "demo"

# Or target just the credentials with a different password
lockhtml encrypt simple.html -s "#credentials" -p "ops-team" --title "Credentials"
```

### `blog.html` - Blog with members-only content
A blog with public articles that contain members-only extended analysis, plus
private subscriber analytics in the sidebar.

```bash
# Encrypt members-only content
lockhtml encrypt blog.html -s ".members-only" -p "members" --title "Members Only"

# Encrypt subscriber analytics with a different password
lockhtml encrypt encrypted/blog.html -s "#subscriber-stats" -p "admin" --title "Analytics"

# Or encrypt author contact info
lockhtml encrypt blog.html -s ".author-bio .contact" -p "staff"
```

### `dashboard.html` - SaaS analytics dashboard
Dashboard with public summary metrics and sensitive financials, customer data,
API keys, and account info.

```bash
# Encrypt API keys (most sensitive)
lockhtml encrypt dashboard.html -s "#api-keys" -p "devops" --title "API Keys"

# Encrypt financials and customer list with different password
lockhtml encrypt encrypted/dashboard.html -s "#financials" -s "#customers" -p "finance"

# Encrypt account details
lockhtml encrypt encrypted/dashboard.html -s "#account" -p "admin"
```

### `research-group.html` - Academic research group page
University research group with public-facing info and internal-only staff notes,
unpublished drafts, and grant portfolio.

```bash
# Encrypt all internal sections at once
lockhtml encrypt research-group.html -s ".internal" -p "group-pass"

# Or encrypt with separate passwords per section
lockhtml encrypt research-group.html -s "#staff-notes" -p "faculty" --title "Staff Notes"
lockhtml encrypt encrypted/research-group.html -s "#unpublished-work" -p "group" --title "Drafts"
lockhtml encrypt encrypted/research-group.html -s "#funding" -p "pi-only" --title "Grant Info"
```
