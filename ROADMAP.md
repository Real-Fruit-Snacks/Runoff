# Runoff Roadmap

Tracked improvements for the runoff project, organized by priority.

## Bugs (Fixed)

- [x] **1. Version mismatch** — `runoff/__init__.py` synced to `3.1.0` to match `pyproject.toml`
- [x] **2. CI references `hackles`** — `ci.yml` and `release.yml` updated to use `runoff`
- [x] **3. HTML output dead code** — `emit_html()` added, wired into `emit_structured()` and CLI pipeline
- [x] **4. `<DC_IP>` placeholder never substituted** — `_extract_host_from_bolt()` populates `config.dc_ip`
- [x] **5. Bare `print()` in API client** — replaced with Rich `console.print()` in `api/client.py`

## Testing Gaps

- [x] **6. CLI integration tests** — Added `tests/test_cli.py` with 45 tests using Click's `CliRunner` covering commands, global options, and output formats
- [x] **7. Tests for report.py and output.py** — Added `tests/test_report.py` with 36 tests for HTML report generation, structured output (JSON/CSV/HTML), and output-file support
- [x] **8. Tests for core/scoring.py** — Added `tests/test_scoring.py` with 17 tests for `calculate_exposure_metrics()`, `calculate_risk_score()`, and `get_risk_rating()`
- [x] **9. Broader query function coverage** — Expanded `tests/test_queries.py` to 111 tests covering 25+ query functions across all 13 categories

## Missing Features

- [x] **10. Remove dead shell code** — `runoff/shell/` directory already removed (confirmed not present)
- [x] **11. `--output-file` flag** — Added `-O`/`--output-file` global option to write results to a file instead of stdout
- [x] **12. Diff/comparison mode** — Added `runoff diff` command to compare two saved JSON result files and show new, resolved, and changed findings
- [x] **13. Query tagging** — Added `tags` field to `@register_query` decorator and `--tags`/`-t` CLI filter on `run` command; tagged 19 queries with `quick-win`, `requires-creds`, `noisy`, `stealthy`
- [x] **14. Progress bar for long runs** — Already implemented via `display/progress.py` and used in `run` command (confirmed working)
- [x] **15. Config file support** — Added `~/.config/runoff/config.yaml` for default connection settings; CLI flags and env vars override config file values

## Query Coverage Gaps

- [x] **16. Exchange queries** — Added Exchange Trusted Subsystem paths, mailbox delegation, and Exchange Windows Permissions paths queries
- [x] **17. GPO abuse queries** — Added `queries/gpo/` category with 3 queries: GPO Control to Computer Execution (HIGH), GPO Links to Tier Zero (CRITICAL), GPO Weak Link Chains (MEDIUM); added "gpo" to CLI CATEGORIES
- [x] **18. LAPS v2 / Windows LAPS queries** — Added 2 queries: "LAPS Coverage Gaps (Modern OS)" (MEDIUM, default) for modern OS without any LAPS, and "Windows LAPS Migration Candidates" (LOW, non-default) for legacy LAPS on modern OS
- [x] **19. Pre-Windows 2000 compatible access** — Added "Pre-Windows 2000 Compatible Access" query (HIGH, quick-win) detecting members including ANONYMOUS LOGON and Authenticated Users
- [x] **20. Cross-forest trust abuse** — Added "Cross-Forest ACL Abuse" (CRITICAL) for dangerous ACL edges across domains, and "SID Filtering Bypass Paths" (CRITICAL) for trusts with SID filtering disabled + cross-trust attack paths

## Code Quality / DX

- [x] **21. mypy in CI** — Added mypy step to CI lint job; fixed 219 type errors (implicit Optional, missing annotations, union-attr); added per-module overrides for legacy api/display code
- [x] **22. Security scanning in CI** — Added `security` job to CI with bandit (SAST) and pip-audit (dependency vulnerabilities); bandit config in pyproject.toml skips B101 (assert)
- [x] **23. API credential permissions** — Added `_check_permissions()` to `APIConfig` that warns via `warnings.warn()` when credential file (>0o600) or config directory (>0o700) are too permissive
- [x] **24. API retry logic** — Added exponential backoff retry (up to 3 retries, capped at 10s) in `_request()` for 5xx responses and connection errors
- [x] **25. `run_query()` uses legacy print** — Replaced all 9 `print(colors.FAIL/CYAN...)` calls in `bloodhound.py` with Rich `console.print()` using `[error]` and `[text.dim]` styles

## Nice-to-Haves

- [x] **26. Markdown output format** — Added `--output markdown` with `emit_markdown()` producing pipe-delimited tables; wired into all structured output paths
- [x] **27. Query dependency/ordering** — Added `depends_on` tuple field to `@register_query` and `sort_by_dependencies()` topological sort; `run` command auto-sorts; annotated 2 owned queries as examples
- [x] **28. Plugin system for custom queries** — Added `_load_plugins()` to auto-discover `.py` files in `~/.config/runoff/queries/` (respects `XDG_CONFIG_HOME`); plugins use `@register_query` decorator; errors emit warnings without crashing
- [x] **29. Neo4j connection pooling** — Added `_DriverPool` class that caches Neo4j drivers by `(uri, username)` key with stale-driver detection; `BloodHoundCE.connect()` uses the pool; pooled drivers are not closed on `bh.close()`
- [x] **30. Shell completion** — Added `runoff completion bash|zsh|fish` command that outputs shell-specific activation scripts using Click's `_RUNOFF_COMPLETE` env var
