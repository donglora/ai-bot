set shell := ["bash", "-c"]

default: run

[private]
_ensure_tools:
    @mise trust --yes . 2>/dev/null; mise install --quiet

# Run the AI bot (optionally pass a serial port: `just run /dev/ttyACM0`)
run *args: _ensure_tools
    @uv run ai_bot.py {{args}}

# Run the full gauntlet: format-check, lint, type-check, tests
check: fmt-check lint typecheck test

# Format code
fmt: _ensure_tools
    @uv run ruff format .

# Check formatting without changing files
fmt-check: _ensure_tools
    @uv run ruff format --check .

# Lint (ruff)
lint: _ensure_tools
    @uv run ruff check .

# Auto-fix lint where possible
lint-fix: _ensure_tools
    @uv run ruff check --fix .

# Static type check (pyright)
typecheck: _ensure_tools
    @uv run pyright orac tests ai_bot.py

# Run the test suite
test *args: _ensure_tools
    @uv run pytest {{args}}

# Run tests with verbose output
test-v: _ensure_tools
    @uv run pytest -v

# Dump live metrics from a running bot (sends SIGUSR1 by PID; pass the pid)
metrics pid: _ensure_tools
    @kill -USR1 {{pid}}
    @echo "Sent SIGUSR1 to PID {{pid}}; check the bot's stderr for METRICS line"

# Tail the structured event log (JSONL)
events:
    @tail -F ~/.donglora/orac-events.jsonl

# Pretty-print the events log with jq
events-pretty:
    @tail -F ~/.donglora/orac-events.jsonl | jq .

# Clean cached artifacts
clean:
    @rm -rf .pytest_cache .ruff_cache __pycache__ orac/__pycache__ tests/__pycache__
