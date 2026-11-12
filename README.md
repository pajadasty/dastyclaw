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

- **Interactive Target Profiler (`hunt`)**: Step-by-step wizard prompting for username, full name, email, and location to correlate findings into a unified intelligence dossier.
- **Concurrent Username Hunting**: Asynchronously probes 35+ platforms (GitHub, Reddit, Twitter/X, Keybase, Steam, Telegram, Spotify, HackerNews, SoundCloud, Twitch, etc.) in under 2 seconds.
- **Email Intelligence & Avatar Footprinting**: Validates format, checks MX mail servers via DNS-over-HTTPS (DoH), searches public Gravatar accounts, and correlates GitHub email owners.
- **Tactical OSINT Dork Generation**: Automatically formats tailored Google and DuckDuckGo search queries for social profiles, CV/resumes, pastebin leaks, and exposed git credentials.
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

### 1. Interactive Multi-Vector Target Investigation (`hunt`)

The smartest way to profile a target. Prompts you step-by-step for known attributes:

```bash
dastyclaw hunt
```

Or pass flags directly:

```bash
dastyclaw hunt -u pajadasty -n "Pavel" -e "pajadasty@gmail.com" -l "Prague"
```

Output:

```text
[*] Tactical Target Profiler (Interactive OSINT Wizard)
Zadejte známé údaje o cíli (nechte prázdné pro přeskočení):

[?] Přezdívka / Nickname (např. pajadasty): pajadasty
[?] Jméno a příjmení osoby (např. Pavel Novák): Pavel
[?] Emailová adresa (např. target@example.com): pajadasty@gmail.com
[?] Město / Lokalita (např. Praha / Czechia): Praha

[1/3] Skenování digitální stopy pro přezdívku: @pajadasty
  [+] PROFIL GitHub         https://github.com/pajadasty (246ms)
  [+] PROFIL Spotify        https://open.spotify.com/user/pajadasty (206ms)
  [+] PROFIL Twitch         https://www.twitch.tv/pajadasty (744ms)
  ...
  Nalezeno: 10 aktivních profilů.

[2/3] Prověřování emailové adresy: pajadasty@gmail.com
  [+] Doména: gmail.com (MX: VALIDNÍ (PŘIJÍMÁ POŠTU))

[3/3] Generování taktických vyhledávacích dotazů (OSINT Dorks)...
  • Social & Professional: Locate social media and LinkedIn profiles matching real name
    Google: https://www.google.com/search?q=site%3Alinkedin.com%2Fin...
  • Documents & CV: Search for published resumes, resumes, presentations or documents
  • Pastes & Dumps: Search for mentions in public paste and text storage sites
  • Code & Git Repos: Search for commits, config files, and issues containing the email

[*] Kompletní vyšetřovací spis vygenerován:
  MD Report:   reports\pajadasty_investigation_dossier.md
  JSON Data:   reports\pajadasty_investigation_dossier.json
```

---

### 2. Standalone Username Hunter

Scan for digital footprints and active accounts across social networks, developer hubs, and streaming platforms:

```bash
dastyclaw user pajadasty
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
  hunt                  Smart multi-vector OSINT investigation (Username, Name, Email, Location)
  user                  Hunt username across 35+ online platforms
  domain                Enumerate subdomains, DNS, SPF/DMARC & security headers

hunt options:
  -u, --username STR    Target username/handle (e.g. pajadasty)
  -n, --name STR        Target full name (e.g. 'Pavel Novák')
  -e, --email STR       Target email address
  -l, --location STR    Target city or location
  -i, --interactive     Launch interactive step-by-step wizard
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
