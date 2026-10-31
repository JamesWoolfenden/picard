# picard

Triage dependency vulnerability alerts: which ones actually reach your code.

Dependabot-style alerts list every advisory against every locked package. Most of the noise
is structural: one package with a burst of advisories that a single upgrade fixes, packages
that only ship in dev/test, packages that are installed but never run. picard collects the
evidence for each alert and proposes a verdict, so the ones that matter stand out.

Named for Jean-Luc Picard: weigh the reports, decide, make it so.

## What it checks

For a [uv](https://docs.astral.sh/uv/) project (`uv.lock`), or an npm project
(`package-lock.json`, with fewer checks - see Limitations):

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
5. **Assessed** (optional, `--assess`) - Claude reads each shipped package's advisories and
   their fix commits, and says what each one is actually about: specific functions, shipped
   *data* (like a CA bundle), or install time only; what an attacker needs; and whether your
   deployment (`picard.yaml`) meets that. The affected functions are then checked against
   what the coverage run actually called - deterministically, not by the model.

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

Advisory assessment (needs `ANTHROPIC_API_KEY`; answers are cached per advisory, package
version, deployment and model in the user cache directory, so re-runs are free):

```shell
picard scan -d . --coverage coverage.json --assess
```

Describe the deployment in `picard.yaml` next to the lock file (or pass `--deployment`).
State only what you're sure of - anything left out is treated as unknown, never as safe:

```yaml
platform: linux
container: true
shared_host: false        # no other, untrusted local users/processes
outbound_tls: true        # makes HTTPS calls to other services
exposed:
  - HTTP API, only on a private Tailscale tailnet
untrusted_input:
  - media files and their tags on a read-only share
notes: >
  Packages are installed at image build time on Linux CI, never at runtime.
```

## Example

pan (a self-hosted music app) before its October 2026 fixes. Dependabot showed 19 alerts.

Package evidence only, from its test suite's coverage - note how wrong this ranking is:

```text
VERDICT      PACKAGE     VERSION    FIX         SEVERITY  ADVISORIES  IMPORTED  EXECUTED
reachable    filelock    4.1.0      4.2.1       high      17      no        yes
reachable    setuptools  84.0.0     84.1.0      low       1       no        yes
import-only  certifi     2026.7.22  2026.10.19  critical  2       no        yes
```

With `--assess` and pan's `picard.yaml`:

```text
pan: 20 advisories across 3 packages - 3 upgrade(s) fix all of them

VERDICT         PACKAGE     VERSION    FIX         SEVERITY  ADVISORIES  IMPORTED  EXECUTED
reachable       certifi     2026.7.22  2026.10.19  critical  2       no        yes
not-applicable  filelock    4.1.0      4.2.1       high      17      no        yes
not-applicable  setuptools  84.0.0     84.1.0      low       1       no        yes

certifi 2026.7.22: the problem is in data the package ships, used wherever the package is:
The issue is in the bundled CA data. The deployment makes outbound TLS calls via requests ...

filelock 4.1.0: preconditions don't hold here: The attack needs a second local user who can
create files in the lock directory, but the app runs alone in its own container ...
  17 advisories: 17 not-applicable

setuptools 84.0.0: preconditions don't hold here: The path escape depends on Windows
drive-qualified absolute path semantics ... This deployment runs only on Linux ...
```

## Dependabot: act on the alerts

`picard dependabot` reads a repository's Dependabot alerts, scans each lock file they refer
to, matches every alert to picard's verdict for the same advisory (by GHSA id, including
OSV aliases), and proposes an action. It's a dry run unless asked:

```shell
picard dependabot -d path/to/checkout                 # propose
picard dependabot -d . --apply                        # dismiss the fact-based ones
picard dependabot -d . --assess --apply-judged        # also the judged ones - review first
```

| picard verdict | Proposal | Dismissed by |
|---|---|---|
| `not-shipped` | dismiss as `not_used` | `--apply` (a fact from the lock file) |
| `not-executed`, `import-only` | dismiss as `not_used` | `--apply-judged` only (rests on a coverage run) |
| `not-applicable` | dismiss as `tolerable_risk` | `--apply-judged` only (rests on a model's assessment) |
| `reachable`, `shipped` | keep open | - |

Each dismissal carries picard's reason as its comment (Dependabot allows 280 characters),
so whoever reads the alert later sees why. Alerts on manifests picard can't read yet, or
whose advisory picard doesn't find at the locked version, are skipped, not dismissed.

Needs a GitHub token (`GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token`); dismissing needs
write access to Dependabot alerts. `--state fixed --lock old/uv.lock` replays past alerts
against an old lock, for checking picard's proposals against decisions already made.

garmin-mcp-gt (a live alert, October 2026) - a Vite app whose `vite build` bundles only
what the code imports:

```text
JamesWoolfenden/garmin-mcp-gt: 1 alert on 1 package in ui/package-lock.json - 1 to dismiss

PACKAGE  ALERTS  SEVERITY  VERDICT      ACTION
uuid     #10     medium    not-shipped  dismiss: not_used

uuid #10 - dismiss: not_used
  only pulled in by dev/test dependencies (firebase-tools → gaxios → uuid), and vite bundles only what the code
  imports, none of which pulls it in
  #10 GHSA-w5hq-g745-h8pq uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided

Dry run. --apply dismisses 1 alert.
```

Alerts of one package with the same proposal are one row (`filelock #3-8, #10-20 (17)`);
a reason shared by all of them is written once, and judged ones list each alert's own
reasoning, since that's what you're signing off with `--apply-judged`.

## Surface: what each dependency costs

Triage makes alerts cheaper; `picard surface` is for having fewer of them. For each direct
dependency it works out what would leave the production install if it were removed - its
own transitive packages, with native code, wheel size for the target platform, and every
advisory those packages have ever had - against how much of it the project uses.

```shell
picard surface -d .                         # table, biggest first
picard surface -d . --coverage coverage.json --detail
picard surface -d . --format json
```

pan, with its test coverage:

```text
pan ships 88 packages (linux x86_64, Python 3.12). What each direct dependency alone brings in:

DEPENDENCY                      PACKAGES  NATIVE  SIZE        PAST ADVISORIES  USED     FUNCTIONS CALLED
sentence-transformers (+torch)  26        6       >= 35.5 MB  178              2 names  1748
librosa                         12        5       65.0 MB     3                1 name   6
anthropic                       8         1       2.5 MB      16               1 name   13
uvicorn                         5         4       5.9 MB      8                command  0
...

Undeclared imports - declare them, or removing what brings them in breaks the code:
  httpx  via sentence-transformers → huggingface-hub → httpx
```

Then, per dependency, what it brings in (`cryptography*(42)`: native code, 42 past
advisories; `pywin32?`: no wheel for the target platform, so probably not installed there)
and the names the code uses from it.

- **Groups** - a direct dependency only another one needs goes with it: pan lists torch
  directly, but it's only there for sentence-transformers, so they're costed together.
- **Extras** count: `uvicorn[standard]`'s uvloop, httptools, watchfiles and websockets are
  attributed to uvicorn.
- **Used** is names imported from it, plus whether one of its console commands appears in
  the Dockerfile/Makefile/compose file (uvicorn is run, not imported).
- **Undeclared** imports - code importing a package it doesn't depend on - are flagged,
  because they're exactly what breaks when you remove the dependency that happened to
  provide them.
- Sizes from indexes that don't publish them (PyTorch's) show as `>=`.

## Verdicts

Each advisory gets its own verdict; a package shows its most serious one.

| Verdict | Meaning | OpenVEX status |
|---|---|---|
| `reachable` | the vulnerable code ran, its data is in use, or (unassessed) the package is used | `affected` |
| `shipped` | in the production install, no evidence about use; or install-time only | `under_investigation` |
| `import-only` | imported in the coverage run, but none of its functions called | `not_affected` / `vulnerable_code_not_in_execute_path` |
| `not-executed` | shipped, but none of the affected code ran in the coverage run | `not_affected` / `vulnerable_code_not_in_execute_path` |
| `not-applicable` | the advisory's preconditions don't hold for this deployment | `not_affected` / the assessment's justification |
| `not-shipped` | only dev/test dependencies pull it in | `not_affected` / `component_not_present` |

The VEX output is a *proposal* to review, not a decision: commit it once you agree with it.

## Limits - read before trusting a `not_affected`

- **Coverage is only as good as the run.** A test suite that stubs out the network never
  calls an HTTP library's TLS code, though production does on every request. Prefer a run
  that exercises the app the way production does.
- **`not-applicable` is only as good as `picard.yaml`.** Claude checks preconditions against
  what you wrote; a wrong deployment description gives wrong verdicts. The reasoning is in
  every verdict so it can be checked.
- **Assessments are model judgement.** Affected functions are extracted by a model from the
  advisory and fix; the match against coverage is exact, the extraction isn't. Unassessed
  advisories (a failed or declined request) keep their package-level verdict.
- **Static imports only**: `importlib`/`__import__` aren't seen; coverage covers them.
- **Platform markers are ignored**: a dependency only installed on Windows still counts as
  shipped. Conservative, never under-reports.
- Lock files: `uv.lock` and npm's `package-lock.json` (lockfileVersion 2 or 3). For npm,
  picard checks advisories, whether each package ships (runtime `dependencies` vs
  `devDependencies`) and whether your own non-test JS/TS imports it. When the project builds
  with a bundler (esbuild, webpack, vite, rollup, Next.js and the like, as a dependency or
  run by a `package.json` script), a dev-only package the code's imports reach is in the
  bundle, so it counts as shipped; `--coverage`, `--assess`
  and `surface` are Python-only for now. A package locked at several versions has each
  looked up.

## Further reading

- [Design](docs/design.md) - evidence layers, verdict rules, and why
- [Case study: pan's 19 alerts](docs/case-study-pan.md) - how picard came about, including
  the ranking it first got backwards
- [Roadmap](docs/roadmap.md) - churn, footprint, more ecosystems, integration

## Development

```shell
make test
make install
```
