# SecureOps Toolkit

Security-first DevOps cheatsheet + a correlation-and risk-scoring log analyzer. Built with Flask, Alpine.js, and Tailwind.

## Highlights

- Command Guide: 55+ Docker, Git, GitHub CLI, and MongoDB commands with usage tips
- Risk-scored Log Analyzer (English + Swedish)
- Deterministic normalization (priority-based), allowlists, and single-escaped log lines
- Correlation rules: brute-force, password spraying, fail→success, WAF+auth, multi-port scans
- Deduplicated findings per rule + entity (clean, non-duplicated results)

## Quick Start

Python (3.12+)
```bash
git clone <repo-url>
cd SecureOps-Toolkit
python -m venv .venv
.venv/Scripts/activate  # Windows
# source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
python app.py
```

Docker
```bash
# Compose v2
docker compose up --build
# or Compose v1
docker-compose up --build
```

Open http://localhost:5000

## How Analysis Works (short)

- Parse: timestamps, level, service, and key=value (incl. quoted values)
- Normalize: Swedish/English phrases → unified event types via fixed priority
- Score: risk per IP/user → severity (low/medium/high/critical)
- Correlate: time-window rules + dedup per rule/entity; matched_lines merged

## Testing

```bash
pytest -q
```

## What’s New

- MongoDB tab with practical connection, CRUD, and backup/import-export commands
- Minimal usage line for each command using clear placeholders like <image>, <container>, <repo> and [options]

## License

MIT
