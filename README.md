# 🔗 Supply Chain Security Scanner

A security scanner that analyzes npm packages, pip packages, and Docker images for supply chain vulnerabilities.

## What It Does

Scans dependencies across three ecosystems and generates a comprehensive security report with risk scoring.

## Scanning Modules

- **NPM Scanner** — Analyzes Node.js packages for vulnerabilities, typosquatting, suspicious scripts, and outdated versions
- **PIP Scanner** — Analyzes Python packages using OSV database, detects typosquatting and new/unverified packages
- **Docker Scanner** — Checks Docker Hub images for official status, pull counts, typosquatting, and Dockerfile misconfigurations

## Detection Capabilities

- Typosquatting attacks (e.g. `reqeusts` vs `requests`)
- Suspicious install scripts (`postinstall`, `eval`, `base64`)
- New/unverified packages (supply chain injection risk)
- Outdated dependencies with known CVEs
- Unofficial or low-pull Docker images
- Dockerfile misconfigurations (root user, no HEALTHCHECK, latest tag)
- CVE lookups via OSV and NPM Advisory databases

## Technologies

- Python 3
- requests — API calls to NPM, PyPI, Docker Hub, OSV
- colorama — Colored terminal output
- python-dotenv — Configuration management

## Installation

    git clone https://github.com/kaansoyturk/supply-chain-scanner.git
    cd supply-chain-scanner
    python3 -m venv venv
    source venv/bin/activate
    pip3 install requests python-dotenv colorama rich packaging

## Usage

Demo mode (scans popular packages):

    python3 main.py

File mode (scans your project files):

    python3 main.py --files

File mode requires: `package.json`, `requirements.txt`, `Dockerfile`

## Example Output

    PHASE 1/3: NPM PACKAGES
      ✓ SAFE      : lodash
      ✓ SAFE      : axios
      🎯 TYPOSQUAT: reqeusts → requests

    PHASE 2/3: PIP PACKAGES
      ⚠ NEW PKG   : suspicious-lib — 1 day old
      🎯 CVE      : django — CVE-2024-XXXX

    PHASE 3/3: DOCKER IMAGES
      ✓ OFFICIAL  : nginx (13,010,439,674 pulls)
      🎯 LOW PULLS: unknown-image — 42 pulls

    Risk: 85/100 — CRITICAL
    Report saved: reports/supply_chain_report_20260515.json

## Developer

Kaan Soyturk — github.com/kaansoyturk