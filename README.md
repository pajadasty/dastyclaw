# DastyClaw 🦅🕵️‍♂️

**Fast, asynchronous OSINT reconnaissance and digital footprinting toolkit by pajadasty.**

Built for security researchers, penetration testers, CTF players, and investigative analysts to rapidly map targets from a single command.

```
  ____            _        ____ _                 
 |  _ \  __ _ ___| |_ _   / ___| | __ ___      __ 
 | | | |/ _` / __| __| | | |   | |/ _` \ \ /\ / / 
 | |_| | (_| \__ \ |_| |_| |___| | (_| |\ V  V /  
 |____/ \__,_|___/\__|\__, |\____|_|\__,_| \_/\_/   v0.1.0
                      |___/                       
 Tactical OSINT Reconnaissance & Footprinting Toolkit by pajadasty
```

---

## ⚡ Key Capabilities

- **Concurrent Username Hunting**: Asynchronously probes 35+ platforms (GitHub, Reddit, Twitter/X, Keybase, Steam, Telegram, Spotify, HackerNews, SoundCloud, Twitch, etc.) in under 2 seconds.
- **Certificate Transparency Subdomain Discovery**: Passively discovers subdomains and shadow infrastructure via `crt.sh` logs without sending invasive packets to target systems.
- **DNS & Anti-Spoofing Mail Security Audit**: Queries DNS records over HTTPS (Cloudflare 1.1.1.1 DoH) and audits SPF (`v=spf1`) and DMARC (`_dmarc`) configuration to determine whether a domain is vulnerable to email spoofing.
- **HTTP Security Headers Audit**: Assesses web server hardening (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and calculates a letter grade (A+ through F) with remediation advice.
- **Automated Dossier Generation**: Exports investigation findings to structured **Markdown dossiers** and machine-readable **JSON reports**.

---

## 🚀 Installation

```bash
git clone https://github.com/pajadasty/dastyclaw.git
cd dastyclaw
pip install .
```

For development and testing:

```bash
pip install -e ".[dev]"
```

---

## 💻 Usage

### 1. Hunt a Username Across Online Platforms

Scan for digital footprints and active accounts across social networks, developer hubs, and streaming platforms:

```bash
dastyclaw user pajadasty
```

Output:

```text
[*] Initiating Username Hunter for target: @pajadasty
  [+] FOUND  GitHub         https://github.com/pajadasty (489ms)
  [+] FOUND  GitLab         https://gitlab.com/pajadasty (478ms)
  [+] FOUND  PyPI           https://pypi.org/user/pajadasty/ (282ms)
  [+] FOUND  Spotify        https://open.spotify.com/user/pajadasty (256ms)
  [+] FOUND  SoundCloud     https://soundcloud.com/pajadasty (305ms)
  [+] FOUND  Twitch         https://www.twitch.tv/pajadasty (943ms)
  [+] FOUND  Hashnode       https://hashnode.com/@pajadasty (204ms)
  [+] FOUND  Medium         https://medium.com/@pajadasty (499ms)
  [+] FOUND  Pinterest      https://www.pinterest.com/pajadasty/ (670ms)
  [+] FOUND  Replit         https://replit.com/@pajadasty (709ms)

[*] Hunter complete: 10 active profiles found across 36 platforms.
```

Reports are automatically saved to `./reports/<username>_user_dossier.md` and `.json`.

---

### 2. Domain & Subdomain Intelligence

Enumerate subdomains via Certificate Transparency, resolve DNS, and evaluate mail spoofability:

```bash
dastyclaw domain target.com
```

Example:

```bash
dastyclaw domain github.com
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

## 🛠 CLI Options

```text
usage: dastyclaw [-h] [--version] {user,domain} ...

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

## 🧪 Running Tests

All core modules are verified by pytest:

```bash
pytest -v
```

---

## ⚖ Legal & Ethical Disclaimer

`DastyClaw` is intended exclusively for educational purposes, authorized security assessments, and digital investigation of public open-source intelligence (OSINT). Only gather data from authorized targets and public records.

---

## 📄 License

MIT License - Developed by **pajadasty**.
