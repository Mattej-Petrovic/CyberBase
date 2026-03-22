# CyberBase

CyberBase is a bilingual cybersecurity learning and reference platform built to keep practical security knowledge in one place.

Instead of splitting commands, tool notes, security concepts, defensive guidance, and practice material across different tabs and documents, CyberBase brings them together in a single web app. The project is designed as a personal cybersecurity command center for study, revision, and quick day-to-day lookup, with a clear defensive and educational focus.

## Overview

CyberBase combines quick reference, deeper reading, and lightweight practice in the same interface.

With the app, you can:

- look up copy-ready commands with syntax, flags, and examples
- explore tools and understand what they do, how they work, and when to use them
- read about core cybersecurity concepts, principles, frameworks, protocols, and ports
- review DevSecOps topics covering containers, CI/CD pipelines, IaC, supply chain, and cloud security
- review defensive topics such as detection, logging, and hardening
- take short quizzes across multiple security topics
- paste or upload logs and inspect suspicious patterns with a rule-based analyzer
- use global search across the platform instead of searching each section separately

The goal is not to replace official documentation or professional tooling. It is to make common security material easier to revisit, understand, and use in practice.

## Core Features

- **Command Library**: Searchable, copy-ready commands with minimal usage, flags, workflows, and examples.
- **Toolbox**: CLI, GUI, and detection tool pages with explanations, usage patterns, GUI cheat sheets, quick panels, and deep dives.
- **Concepts**: Frameworks and standards, principles and identity, networking and protocols, and ports with structured detail pages.
- **DevSecOps**: Structured topic pages covering containers, orchestration, CI/CD pipelines, infrastructure as code, supply chain security, and cloud runtime security.
- **Defend**: Detection/logging topics and hardening guidance for common platforms and services.
- **Log Analyzer**: Upload or paste logs to detect risky patterns with a deterministic, rule-based engine and JSON API support.
- **Quiz**: Topic-based question sets with randomized runs and answer review.
- **Resource Hub**: Curated external resources for continued learning and hands-on practice.
- **Global Search**: Unified search across commands, tools, concepts, ports, and defend content.
- **Auth and Roles**: Firebase authentication, session cookies, user profiles, and role-aware access.
- **AI Assistant**: Contextual help and command explanations through the in-app drawer.

## Project Snapshot

- `121` command references
- `16` tool pages across CLI, GUI, and detection tooling
- `61` concept entries, including `36` common ports
- `10` defend topics across detection/logging and hardening
- `7` DevSecOps sections covering containers, orchestration, CI/CD, IaC, supply chain, and cloud security
- `13` quiz topics with randomized question sets
- `EN` and `SV` language support

Representative content includes tools such as `nmap`, `curl`, `Wireshark`, `Burp Suite`, `OWASP ZAP`, `Suricata`, and `Zeek`, plus concepts such as Zero Trust, IAM, MFA, NIST CSF, DORA, MITRE ATT&CK, TCP, DNS, TLS, and common service ports.

## How It Is Built

- **Backend**: Flask with Jinja templates
- **Frontend**: Tailwind CSS and Alpine.js
- **Localization**: Flask-Babel with English and Swedish content paths
- **Authentication**: Firebase Auth with server-side session cookies
- **User data**: Firestore for profiles, streaks, and leaderboard data
- **AI chat storage**: MongoDB
- **AI assistant**: Gemini-powered explain/help flow
- **Deployment**: Docker, Gunicorn, and Docker Compose support

The content model is largely data-driven. Commands, tools, concepts, defend topics, and quizzes live in JSON files, which makes the platform straightforward to extend without rebuilding core page logic.

One deliberate implementation choice is the Log Analyzer: it is rule-based rather than AI-driven, so the output stays repeatable, explainable, and tied to matched evidence in the submitted log lines.

## Running Locally

CyberBase depends on Firebase configuration, MongoDB, and a Gemini API key. The repository already includes a `Dockerfile` and `docker-compose.yml` for local development.

Run with Docker Compose:

```bash
docker compose up --build
```

Or run it directly with Flask:

```bash
pip install -r requirements.txt
flask --app app.py run
```

Environment setup should provide:

- Firebase Admin credentials via `FIREBASE_SERVICE_ACCOUNT_JSON` or `FIREBASE_SERVICE_ACCOUNT_PATH`
- Firebase web config values such as `FIREBASE_API_KEY` and `FIREBASE_PROJECT_ID`
- `MONGODB_URI`
- `GEMINI_API_KEY`

## Notes

CyberBase is best described as a practical cybersecurity hub for learning, reference, and lightweight analysis. It is not just a cheat sheet and not just a content site. The value of the project is in how those parts are combined into one consistent experience.
