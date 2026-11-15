# AGENTS.md — Developer & Agent Guide

Welcome to the **Skills Security Checker** project. This repository is designed to be fully agentic-friendly. Any AI coding agent or human contributor working on this repository should adhere to the rules, commands, and architectural patterns outlined below.

---

## 1. Project Overview & Architecture

`skills-security-checker` is both:
1. **A GitHub Action** (`action.yaml`): A composite GitHub Action that audits skills in a repository during CI/CD.
2. **A Python Security CLI**: Built on Python 3.13+ using [`uv`](https://docs.astral.sh/uv/), [`pydantic`](https://docs.pydantic.dev/), and the [`openai`](https://github.com/openai/openai-python) SDK to scan skill definitions (`SKILL.md`, scripts, configs) against malicious attack vectors.

### Threat Categories Assessed
- **`prompt_injection`**: Prompt override, jailbreaks, hidden instructions, behavioral deviation.
- **`command_injection`**: Arbitrary or dangerous shell commands (`rm -rf`, curl pipe-to-bash, privilege escalation `sudo`, unauthorized execution).
- **`data_exfiltration`**: Unauthorized credential access (`.env`, `~/.ssh`, `~/.aws`, environment variables) and unsolicited outbound network requests.
- **`insecure_file_access`**: Writing or tampering with files outside designated workspace boundaries.
- **`privilege_escalation`**: Tool abuse or requests for excessive, unneeded permissions.
- **`obfuscation`**: Base64-encoded payloads, hex strings, or evasion tactics hidden in markdown or scripts.

### Core File Structure
```
skills-security-checker/
├── AGENTS.md                   # This instruction guide
├── action.yaml                 # Composite GitHub Action definition
├── pyproject.toml              # Project dependencies, build tool, and lint/test configurations
├── .env.example                # Example local environment configuration
├── src/
│   ├── app.py                  # CLI entry point & GitHub Actions input orchestrator
│   ├── models.py               # Pydantic models for findings, reports, and summary
│   ├── scanner.py              # Recursive skill discovery & ingestion
│   ├── auditor.py              # OpenAI-compatible LLM auditing engine
│   └── reporter.py             # GitHub annotations (::error), Step Summary, & JSON export
└── tests/
    ├── fixtures/skills/        # Sample skills for deterministic test verification
    │   ├── safe-translator/    # Baseline benign skill
    │   ├── prompt-injection/   # Adversarial prompt override sample
    │   ├── command-exec/       # Dangerous shell commands sample
    │   └── exfiltration/       # Credential theft sample
    ├── test_scanner.py         # Scanner unit tests
    ├── test_models.py          # Schema validation unit tests
    ├── test_reporter.py        # Report generation & GitHub command tests
    └── test_auditor.py         # Auditor logic tests (with mocked LLM responses)
```

---

## 2. Agent Runbook & Verification Commands

Whenever you propose or make modifications, always execute this verification cycle:

### 1. Environment & Dependency Management
We use **`uv`** as the single source of truth for Python packages and virtual environments:
```bash
# Sync all dependencies including dev group
uv sync

# Add a runtime dependency
uv add <package>

# Add a development/testing dependency
uv add --dev <package>
```

### 2. Linting & Formatting
Always check and auto-format code before considering a task complete:
```bash
# Check for lint violations
uv run ruff check .

# Auto-fix lint violations
uv run ruff check --fix .

# Check formatting
uv run ruff format --check .

# Auto-format
uv run ruff format .
```

### 3. Running Unit Tests
All tests must pass without requiring a live OpenAI API key (use fixtures and mocks):
```bash
# Run full test suite
uv run pytest

# Run tests with verbose output
uv run pytest -v

# Run specific test file
uv run pytest tests/test_scanner.py
```

### 4. Running Local Smoke Test
To test the action script against the local test fixtures:
```bash
# Ensure .env is populated with test values (or mock endpoint)
uv run python -m src.app
```

---

## 3. Coding Guidelines & Invariants

1. **Deterministic Structured Outputs**:
   - Always define LLM response schemas via Pydantic (`src/models.py`).
   - Use `client.beta.chat.completions.parse` or schema-enforced JSON mode.
   - Never use unstructured regex-based LLM parsing for security findings.

2. **Fault Tolerance & Graceful Degradation**:
   - Malformed skill files must NOT crash the CLI. Log a `::warning::` or record an error finding, and continue scanning remaining skills.
   - Network errors or rate limits against the LLM endpoint must include exponential backoff or clean error messaging rather than unhandled tracebacks.

3. **Dual Execution Mode**:
   - When running in GitHub Actions: Read from `INPUT_*` environment variables (e.g. `INPUT_TARGET_DIR`, `INPUT_API_KEY`) and emit workflow commands (`::error::`, `::warning::`, `::notice::`) and markdown into `$GITHUB_STEP_SUMMARY`.
   - When running locally: Automatically load `.env` via `python-dotenv`, accept CLI arguments / standard env variables (`TARGET_DIRECTORY`, `API_KEY`), and output readable terminal logs.

4. **Security & Sandbox Safety**:
   - The security auditor must never execute code found inside the scanned skills. Analysis must be strictly static and LLM-semantic.
   - Never leak API keys or secrets in output logs or step summaries.

---

## 4. GitHub Actions Output Protocol

When running inside GitHub Actions, communicate with the runner via standard workflow commands:
- **Notice**: `::notice file={file},line={line}::{message}`
- **Warning**: `::warning file={file},line={line}::{message}`
- **Error (Fails CI)**: `::error file={file},line={line}::{message}`
- **Job Summary**: Append GitHub Flavored Markdown to the path in `$GITHUB_STEP_SUMMARY`.

