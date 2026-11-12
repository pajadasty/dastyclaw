# ReconClaw

A fast, asynchronous OSINT reconnaissance and digital footprinting toolkit built for security researchers, penetration testers, and investigative analysts.

---

## Capabilities

- **Concurrent Username Hunting**: Asynchronously probes 35+ major platforms (GitHub, Reddit, Twitter/X, Keybase, Steam, Telegram, Spotify, HackerNews, etc.) in parallel within seconds using bounded asyncio concurrency.
- **Certificate Transparency Subdomain Discovery**: Enumerates public subdomains and shadow infrastructure via `crt.sh` logs without sending invasive packets to target systems.
- **DNS & Anti-Spoofing Mail Security Audit**: Queries DNS records over HTTPS (DoH) and analyzes SPF (`v=spf1`) and DMARC (`_dmarc`) configuration to determine whether a domain is vulnerable to email spoofing.
- **HTTP Security Headers Audit**: Assesses web server hardening (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and calculates a letter grade (A+ through F) with remediation advice.
- **Automated Dossier Generation**: Exports investigation findings to structured **Markdown dossiers** and machine-readable **JSON reports**.

---

## Installation

```bash
git clone https://github.com/<your-username>/reconclaw.git
cd reconclaw
pip install .
```

For development and running tests:

```bash
pip install -e ".[dev]"
```

---

## Usage

### 1. Hunt a Username Across Online Platforms

Scan for digital footprints and active accounts across social networks, developer hubs, and creator platforms:

```bash
reconclaw user <target_username>
```

Example:

```bash
reconclaw user torvalds
```

Output:

```text
[*] Initiating Username Hunter for target: @torvalds
  [+] FOUND  GitHub         https://github.com/torvalds (547ms)
  [+] FOUND  GitLab         https://gitlab.com/torvalds (971ms)
  [+] FOUND  DockerHub      https://hub.docker.com/v2/users/torvalds/ (827ms)
  [+] FOUND  Keybase        https://keybase.io/torvalds (3001ms)
  [+] FOUND  HackerNews     https://news.ycombinator.com/user?id=torvalds (3082ms)
  ...
[*] Hunter complete: 19 active profiles found across 36 platforms.
```

Reports are automatically saved to `./reports/<username>_user_dossier.md` and `.json`.

---

### 2. Domain & Subdomain Intelligence

Enumerate subdomains via Certificate Transparency, resolve DNS, and evaluate mail spoofability:

```bash
reconclaw domain <target_domain>
```

Example:

```bash
reconclaw domain github.com
```

Output:

```text
[+] Certificate Transparency (crt.sh): Discovered 118 subdomains
    • api.security.github.com
    • asset-generator.github.com
    • central.github.com
    ...

[+] DNS Resolution:
    A      140.82.121.3
    MX     0 github-com.mail.protection.outlook.com.
    TXT    v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com ... ~all

[+] Email Anti-Spoofing Audit:
    Status: VULNERABLE TO SPOOFING
    SPF:    Softfail (~all)
    DMARC:  quarantine
    Note:   Partial Protection: Basic records present, but policy allows softfail delivery.

[+] Security Headers Audit: Grade: B (85/100)
    [PASS] Strict-Transport-Security    Enforces HTTPS encryption.
    [PASS] Content-Security-Policy      Restricts resource sources.
    [PASS] X-Frame-Options              Mitigates clickjacking.
    [PASS] X-Content-Type-Options       Prevents MIME-sniffing.
    [MISSING] Permissions-Policy        Missing feature permissions policy.
```

---

## CLI Options

```text
usage: reconclaw [-h] [--version] {user,domain} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

subcommands:
  user                  Hunt username across 35+ online platforms
  domain                Enumerate subdomains, DNS, SPF/DMARC & security headers

flags:
  -o, --output-dir DIR  Directory to save reports (default: ./reports)
  -c, --concurrency N   Concurrent network workers (default: 25)
  -t, --timeout SEC     Request timeout in seconds (default: 6.0)
  --no-export           Display results in terminal only without writing to disk
```

---

## Running Tests

All core modules are verified by unit tests:

```bash
python -m pytest -v
```

---

## Legal & Ethical Disclaimer

`ReconClaw` is intended exclusively for educational purposes, authorized security assessments, and digital investigation of public open-source intelligence (OSINT). Only gather data from authorized targets and public records.

---

## License

MIT License
