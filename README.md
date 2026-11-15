# Skills Security Checker 🛡️

A composite GitHub Action and security CLI that audits agent skills against malicious actions, prompt injections, and unsafe commands using an OpenAI-compatible endpoint.

---

## Features

- **Prompt Injection Defense**: Detects jailbreak attempts, hidden developer overrides, and behavioral deviations in `SKILL.md` definitions.
- **Dangerous Command Detection**: Catches destructive shell operations (`rm -rf`, pipe-to-bash, unauthorized `sudo`).
- **Data Exfiltration Prevention**: Flags unauthorized access to secrets (`~/.ssh`, `~/.aws`, `.env`) and suspicious outbound network requests.
- **OpenAI-Compatible**: Seamlessly works with OpenAI, OpenRouter, Ollama, LiteLLM, vLLM, or any custom inference endpoint.
- **Native GitHub Annotations & Issues**: Emits inline `::error` annotations on PR diffs, generates Markdown step summaries, and optionally opens tracked GitHub Security Issues for findings with automatic deduplication.
- **Enterprise Findings Export**: Extensible exporter architecture supporting **OASIS SARIF v2.1.0** (GitHub Code Scanning) and **AWS Security Finding Format (ASFF)** (AWS Security Hub).

---

## Quickstart (GitHub Action)

Add this action to your `.github/workflows/security.yaml`:

```yaml
name: Audit Agent Skills

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  audit-skills:
    name: Skill Security Audit
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write # Required if create-issues is enabled
      security-events: write # Required if upload-sarif is enabled
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6

      - name: Run Skills Security Checker
        uses: ./ # Or your-username/skills-security-checker@v1
        with:
          target-directories: |
            skills
            prompts
            .copilot
          api-key: ${{ secrets.OPENAI_API_KEY }}
          fail-on-severity: 'HIGH'
          sarif-file: 'results.sarif'
          aws-findings-file: 'aws-findings.json'
          # Optional: Automatically open tracked GitHub Security Issues
          create-issues: 'true'
          github-token: ${{ secrets.GITHUB_TOKEN }}
          issue-min-severity: 'HIGH'

      - name: Upload SARIF report to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'results.sarif'
```

---

## Local Development & Testing

### Prerequisites
- Python 3.10+
- [`uv`](https://docs.astral.sh/uv/)

### Installation & Run
```bash
# Clone the repository
git clone https://github.com/your-username/skills-security-checker.git
cd skills-security-checker

# Sync dependencies
uv sync

# Copy example environment configuration
cp .env.example .env

# Run security scan
uv run python -m src.app
```

### Verification & Testing
```bash
# Run unit tests
uv run pytest -v

# Run linter & formatter
uv run ruff check .
uv run ruff format --check .

# Run static type checker
uv run mypy src
```

---

## Disclaimer

> [!CAUTION]
> **Provided "AS IS"**: This software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
>
> While Skills Security Checker uses heuristic static scanning and LLM-assisted semantic analysis to identify common attack vectors and malicious actions, no automated tool can guarantee 100% detection of all vulnerabilities, zero-days, or novel evasion techniques. Always employ defense-in-depth, least-privilege sandboxing, and manual human reviews for high-risk agent operations.

---

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).

