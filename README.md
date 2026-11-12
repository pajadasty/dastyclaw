# DastyClaw 🦅🕵️‍♂️

**Fast, asynchronous tactical OSINT reconnaissance and digital footprinting toolkit by pajadasty.**

Built for security researchers, penetration testers, CTF players, and investigative analysts to rapidly map targets across social networks, developer platforms, emails, phone numbers, and domains.

```text
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

- **Interactive Target Profiler (`hunt`)**: Step-by-step wizard prompting for username, full name, email, phone number, and location to correlate findings into a unified intelligence dossier.
- **Concurrent Username Hunting**: Asynchronously probes 30+ platforms (including precision-crawled **Instagram**, **TikTok**, **Twitch**, **GitHub**, **Spotify**, etc.) in under 2 seconds.
- **Anti-Bot Bypass for Modern Social SPAs**:
  - **Instagram**: Employs Googlebot metadata extraction to parse server-side OpenGraph tags without session barriers.
  - **TikTok**: Parses router rehydration state (`__UNIVERSAL_DATA_FOR_REHYDRATION__`) for verified user presence.
  - **Twitch**: Queries direct high-performance GraphQL API.
- **Email Intelligence & Avatar Footprinting**: Validates format, checks MX mail servers via DNS-over-HTTPS (DoH), searches public Gravatar accounts, and correlates GitHub email owners.
- **Telephony Profiling**: Validates international E.164 formats, detects country prefixes, and generates instant WhatsApp/Telegram communication links.
- **Tactical OSINT Dork Generation**: Automatically formats tailored Google and DuckDuckGo search queries for social profiles, CV/resumes, pastebin leaks, and exposed git credentials.
- **Certificate Transparency Subdomain Discovery**: Passively discovers subdomains and shadow infrastructure via `crt.sh` logs without sending invasive packets to target systems.
- **DNS & Anti-Spoofing Mail Security Audit**: Queries DNS records over HTTPS (Cloudflare 1.1.1.1 DoH) and audits SPF (`v=spf1`) and DMARC (`_dmarc`) configuration to determine whether a domain is vulnerable to email spoofing.
- **HTTP Security Headers Audit**: Assesses web server hardening (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and calculates a letter grade (A+ through F) with remediation advice.
- **Multi-Format Dossier Export**: Automatically exports to **Markdown dossiers**, **machine-readable JSON**, and **interactive dark-mode HTML dashboards** (with `--open` auto-launch).

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

### 1. Interactive Multi-Vector Target Investigation (`hunt`)

The smartest way to profile a target. Prompts you step-by-step for known attributes:

```bash
dastyclaw hunt
```

Or pass flags directly and automatically open the HTML dossier in your web browser:

```bash
dastyclaw hunt -u pajadasty -n "Pavel" -e "pajadasty@gmail.com" -p "+420123456789" -l "Prague" --open
```

Output:

```text
[*] Tactical Target Profiler (Interactive OSINT Wizard)
Enter known intelligence attributes (press Enter to skip):

[?] Target handle / username (e.g. pajadasty): pajadasty
[?] Full Name (e.g. 'Pavel Novak'): Pavel
[?] Email address (e.g. target@example.com): pajadasty@gmail.com
[?] Location / City (e.g. 'Prague, Czechia'): Prague
[?] Phone number (e.g. '+420123456789'): +420123456789

[1/4] Hunting digital footprint for alias: @pajadasty
  [+] FOUND SoundCloud     https://soundcloud.com/pajadasty (260ms)
  [+] FOUND Spotify        https://open.spotify.com/user/pajadasty (291ms)
  [+] FOUND Twitch         https://www.twitch.tv/pajadasty (322ms)
  [+] FOUND GitLab         https://gitlab.com/pajadasty (438ms)
  [+] FOUND GitHub         https://github.com/pajadasty (520ms)
  [+] FOUND Replit         https://replit.com/@pajadasty (715ms)
  [+] FOUND TikTok         https://www.tiktok.com/@pajadasty (724ms)
  [+] FOUND Pinterest      https://www.pinterest.com/pajadasty/ (833ms)
  [+] FOUND Instagram      https://www.instagram.com/pajadasty/ (905ms)
  Discovery complete: 9 active profiles found.

[2/4] Auditing email footprint: pajadasty@gmail.com
  [+] Domain: gmail.com (MX: VALID (ACCEPTS MAIL))

[3/4] Profiling phone number: +420123456789
  [+] Region: Czech Republic (+420) (+420123456789)
  [+] WhatsApp Link: https://wa.me/420123456789
  [+] Telegram Link: https://t.me/+420123456789

[*] Generating tactical search dorks...
  • Social & Professional: Locate social media and LinkedIn profiles matching real name
  • Documents & Resumes: Discover publicly exposed resumes, presentations, and documents
  • Pastes & Dumps: Search for credentials, dump files, and mentions on paste sites
  • Code & Git Repos: Search for commits, exposed configs, and issue comments
  • Phone Footprint: Search for directory registrations, reverse phone listings, and contacts

[*] Intelligence Dossier Generated:
  Markdown Report -> reports\pajadasty_investigation_dossier.md
  JSON Data       -> reports\pajadasty_investigation_dossier.json
  Interactive HTML -> reports\pajadasty_investigation_dossier.html
```

---

### 2. Standalone Username Hunter

Scan for digital footprints and active accounts across social networks, developer hubs, and streaming platforms:

```bash
dastyclaw user pajadasty --open
```

---

### 3. Domain & Subdomain Intelligence

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
usage: dastyclaw [-h] [--version] {hunt,user,domain} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

subcommands:
  hunt                  Smart multi-vector OSINT investigation (Username, Name, Email, Phone, Location)
  user                  Hunt username across 30+ online platforms
  domain                Enumerate subdomains, DNS, SPF/DMARC & security headers

hunt options:
  -u, --username STR    Target username or handle (e.g. pajadasty)
  -n, --name STR        Target full name (e.g. 'Pavel Novak')
  -e, --email STR       Target email address
  -p, --phone STR       Target phone number (e.g. '+420...')
  -l, --location STR    Target city or location
  -i, --interactive     Launch interactive step-by-step wizard
  -b, --open            Automatically open generated HTML dossier in default browser
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
