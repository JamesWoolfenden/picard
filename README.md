# picard

Triage dependency vulnerability alerts: which ones actually reach your code.

Dependabot-style alerts list every advisory against every locked package. Most of the noise
is structural: one package with a burst of advisories that a single upgrade fixes, packages
that only ship in dev/test, packages that are installed but never run. picard collects the
evidence for each alert and proposes a verdict, so the ones that matter stand out.

Named for Jean-Luc Picard: weigh the reports, decide, make it so.

## What it checks

For a [uv](https://docs.astral.sh/uv/) project (`uv.lock`):

1. **Advisories** - looks up every locked package version in [OSV](https://osv.dev) (the
   same GitHub advisory data Dependabot uses, plus PyPI's), and groups them by the upgrade
   that fixes them: 19 alerts is often 3 upgrades.
2. **Shipped** - walks the lock file's dependency graph from the project's runtime
   dependencies (not its dev groups) and reports the chain that pulls each package in
   (`torch → filelock`).
3. **Imported** - scans the project's own non-test Python code for imports, mapping module
   names to packages via the installed environment (`dotenv` → `python-dotenv`).
4. **Executed** (optional) - reads a coverage.py report measured with third-party code
   included, and separates packages that were merely *imported* from those whose functions
   were actually *called*.

## Usage

```shell
picard scan -d path/to/project                    # table
picard scan -d . --format json                    # full evidence
picard scan -d . --format vex > picard.vex.json   # OpenVEX proposal
```

Execution evidence:

```shell
coverage run --include="*/site-packages/*" -m pytest
coverage json -i
picard scan -d . --coverage coverage.json
```

Example (pan, before its October 2026 fixes):

```text
pan: 20 advisories across 3 packages - 3 upgrade(s) fix all of them

VERDICT      PACKAGE     VERSION    FIX         SEVERITY  ALERTS  IMPORTED  EXECUTED
reachable    filelock    4.1.0      4.2.1       high      17      no        yes
reachable    setuptools  84.0.0     84.1.0      low       1       no        yes
import-only  certifi     2026.7.22  2026.10.19  critical  2       no        yes
```

## Verdicts

| Verdict | Meaning | OpenVEX status |
|---|---|---|
| `reachable` | imported by the project, or its functions ran | `affected` |
| `shipped` | in the production install, no evidence about use (no coverage given) | `under_investigation` |
| `import-only` | imported in the coverage run, but none of its functions called | `not_affected` / `vulnerable_code_not_in_execute_path` |
| `not-executed` | shipped, but none of its code ran in the coverage run | `not_affected` / `vulnerable_code_not_in_execute_path` |
| `not-shipped` | only dev/test dependencies pull it in | `not_affected` / `component_not_present` |

The VEX output is a *proposal* to review, not a decision: commit it once you agree with it.

## Limits - read before trusting a `not_affected`

- **Coverage is only as good as the run.** A test suite that stubs out the network never
  calls an HTTP library's TLS code, though production does on every request. In the example
  above, certifi - the alert that matters most - shows as `import-only` for exactly that
  reason. Prefer a run that exercises the app the way production does.
- **Package-level, not advisory-level (yet).** "Some of filelock's functions ran" isn't the
  same as "the vulnerable `ReadWriteLock` ran". Matching each advisory's affected functions
  (or data, as with certifi's CA bundle) against the evidence is the next stage.
- **Static imports only**: `importlib`/`__import__` aren't seen; coverage covers them.
- **Platform markers are ignored**: a dependency only installed on Windows still counts as
  shipped. Conservative, never under-reports.
- `uv.lock` only so far.

## Development

```shell
make test
make install
```
