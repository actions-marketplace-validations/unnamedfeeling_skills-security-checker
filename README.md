# Skills Security Checker 🛡️

A composite GitHub Action and security CLI that audits agent skills against malicious actions, prompt injections, and unsafe commands using an OpenAI-compatible endpoint.

---

## Features

- **Prompt Injection Defense**: Detects jailbreak attempts, hidden developer overrides, and behavioral deviations in `SKILL.md` definitions.
- **Dangerous Command Detection**: Catches destructive shell operations (`rm -rf`, pipe-to-bash, unauthorized `sudo`).
- **Data Exfiltration Prevention**: Flags unauthorized access to secrets (`~/.ssh`, `~/.aws`, `.env`) and suspicious outbound network requests.
- **OpenAI-Compatible**: Seamlessly works with OpenAI, OpenRouter, Ollama, LiteLLM, vLLM, or any custom inference endpoint.
- **Native GitHub Annotations**: Emits inline `::error` and `::warning` annotations on PR diffs and generates rich Markdown step summaries.

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
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Skills Security Checker
        uses: ./ # Or your-username/skills-security-checker@v1
        with:
          # Specify one or more directories to audit (comma- or newline-separated)
          target-directories: |
            skills
            prompts
            .copilot
            .codex
          api-key: ${{ secrets.OPENAI_API_KEY }}
          endpoint: 'https://api.openai.com/v1' # Or custom endpoint
          model: 'gpt-4o'
          fail-on-severity: 'HIGH' # CRITICAL, HIGH, MEDIUM, LOW, or NONE
          show-attribution: 'true' # Set to 'false' to hide step summary attribution footer
          prompt-path: '' # Optional path to custom prompt markdown file
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

