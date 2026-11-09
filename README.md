# picard

Triage dependency vulnerability alerts: which ones actually reach your code.

Dependabot-style alerts list every advisory against every locked package. Most of the noise
is structural: one package with a burst of advisories that a single upgrade fixes, packages
that only ship in dev/test, packages that are installed but never run. picard collects the
evidence for each alert and proposes a verdict, so the ones that matter stand out.

Named for Jean-Luc Picard: weigh the reports, decide, make it so.

## What it checks

For a [uv](https://docs.astral.sh/uv/) project (`uv.lock`), an npm project
(`package-lock.json`) or a Go module (`go.mod`) - npm and Go with fewer checks, see
Limitations:

1. **Advisories** - looks up every locked package version in [OSV](https://osv.dev) (the
   same GitHub advisory data Dependabot uses, plus PyPI's and Go's), and groups them by the
   upgrade that fixes them: 19 alerts is often 3 upgrades. Records of the same
   vulnerability from different databases (`GHSA-…` and `PYSEC-…` / `GO-…`) count once.
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
import-only  certifi     2026.7.22  2026.10.19  critical  1       no        yes
```

With `--assess` and pan's `picard.yaml`:

```text
pan: 19 advisories across 3 packages - 3 upgrades fix all of them

VERDICT         PACKAGE     VERSION    FIX         SEVERITY  ADVISORIES  IMPORTED  EXECUTED
reachable       certifi     2026.7.22  2026.10.19  critical  1       no        yes
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
| `not-executed` from govulncheck (Go) | dismiss as `not_used` | `--apply` (a fact from the call graph) |
| `not-executed`, `import-only` otherwise | dismiss as `not_used` | `--apply-judged` only (rests on a coverage run) |
| `not-applicable` | dismiss as `tolerable_risk` | `--apply-judged` only (rests on a model's assessment) |
| `reachable`, `shipped` | keep open | - |

Each dismissal carries picard's reason as its comment (Dependabot allows 280 characters),
so whoever reads the alert later sees why. Alerts on manifests picard can't read yet, or
whose advisory picard doesn't find at the locked version, are skipped, not dismissed.

### Known exploited, likely exploited

`scan` and `dependabot` look each advisory's CVE up in CISA's Known Exploited Vulnerabilities
catalog and FIRST's EPSS scores. Findings in KEV (`!` in the KEV column) sort first whatever
their severity or verdict, then by verdict and EPSS. An advisory in KEV, or with an EPSS of
0.1 or more, is never dismissed by `--apply` or `--apply-judged`: it stays open with the
reason. If either source can't be reached the scan fails rather than dismiss without the
check; `--no-exploit-intel` skips both for offline runs.

It starts by checking the repository's Dependabot setup, since that decides how noisy the
alerts and PRs are: alerts on, **security updates on** (so an alert that matters gets a fix
PR), and **version updates off** (`open-pull-requests-limit: 0` - routine bumps that fix no
alert; `picard scan` finds the occasional one that fixes an advisory GitHub doesn't know
about). Each problem comes with the command or config change that fixes it, and open
Dependabot PRs are labelled security fix or version bump. Pinning is
[ghat](https://github.com/JamesWoolfenden/ghat)'s job, so it isn't checked here.

`--prs` reads Dependabot's open pull requests too. For each one, picard scans every lock it
changes at the PR's base and head commits and compares the advisories, and reports CI and
whether it's a major version bump - from the title's versions, or for a grouped PR (whose
title names none) from the lock diff, listing each package that moved major in
`major_changes`. `major` is left out of the JSON when neither could be read, so an unchecked
PR isn't mistaken for a safe one:

| Class | Meaning |
|---|---|
| `fixes-shipped` | removes an advisory against a package that ships - merge it |
| `fixes-dev-only` | removes advisories, but only against packages that don't ship |
| `adds-advisory` | the new versions have advisories the old ones didn't |
| `fixes-nothing` | a routine bump |
| `no-install-change` | can't change what's installed: a `>=` floor raised in an unpinned requirements file, or a manifest whose lock the PR leaves alone |
| `unknown` | changes files picard can't compare |

```text
PR   PACKAGE    CHANGE                      CI       WHAT IT DOES
#40  tzdata     >=2026.5 → >=2026.6         passing  no-install-change
#38  firebase   13.0.0 → 13.1.0             passing  fixes-shipped
#37  anthropic  >=1.13.0 → >=2.3.0 (major)  passing  no-install-change
#36  ruff       0.17.0 → 0.17.3             passing  no-install-change

#38 Bump firebase from 13.0.0 to 13.1.0 in /ui
  removes 1 advisory against shipped packages: re2js 2.8.6 GHSA-gg6h-894w-4m9c (high)
```

That #38 is a version update, not a security one - GitHub had no alert for re2js - is why
it's worth reading version PRs at all. These are facts only; whether a bump is *safe* to
merge (breaking changes, release notes, tests) is judgement, left to review.

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

### The judgement: `/picard-triage`

picard reports facts; some decisions need judgement - is a major bump safe for this code,
do an advisory's preconditions hold here. The [`picard-triage`](skills/README.md) Claude
Code skill runs `picard dependabot --prs`, investigates those (release notes against the
names the code uses, tests on the PR branch, the reasoning behind judged verdicts), proposes
a plan, and carries out each merge, close, dismissal or setting change on your confirmation.

For surface, the [`picard-surface`](skills/README.md) skill (`/picard-surface`) takes the
dependencies `picard surface` flags, judges whether each can really go and what to use
instead, and records every decision - including "leave it" - in `picard.yaml`.

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

pan:

```text
pan ships 88 packages (linux x86_64, Python 3.12). What each direct dependency alone brings in:

DEPENDENCY                      PACKAGES  NATIVE  SIZE        ADVISORIES  LAST 3Y         USED
sentence-transformers (+torch)  26        6       >= 35.6 MB  112         94 (40 events)  3 names
librosa                         12        5       65.0 MB     2           2               4 names
anthropic                       8         1       2.5 MB      8           8 (3 events)    1 name
uvicorn                         5         4       5.9 MB      4           0               command
fastapi                         3         0       0.3 MB      13          10 (7 events)   6 names
...

Little used for what it costs - is there something lighter, or a few lines of your own?
  sentence-transformers (+torch)
    uses 3 names (httpx.Client, httpx.ConnectError, sentence_transformers.SentenceTransformer); alone brings in 26
    packages; 6 with native code; 94 advisories in the last 3 years (40 separate events, 17 high or critical)
  librosa
    uses 4 names (librosa.beat, librosa.feature, librosa.load, librosa.resample); alone brings in 12 packages; 5 with
    native code; 65.0 MB; 2 advisories in the last 3 years (2 high or critical)
  ...

Undeclared imports - declare them, or removing what brings them in breaks the code:
  httpx  via sentence-transformers → huggingface-hub → httpx
```

Then, per dependency, what it brings in (`cryptography*(42)`: native code, 42 past
advisories; `pywin32?`: no wheel for the target platform, so probably not installed there)
and the names the code uses from it.

- **Advisories** are every advisory the group's packages have ever had, with a record filed
  by several databases (GHSA, PYSEC) counted once. **Last 3y** is the recent ones; *events*
  count each package's advisories published within a week of each other once, so an audit
  that files 17 at a time reads as one event, not 17.
- **Little used for what it costs**: used lightly (5 names or fewer, no command run) *and*
  heavy on at least one count - 10+ packages alone, 50 MB+, 3+ advisory events or 2+ high or
  critical advisories in the last 3 years. The facts are listed; whether something else
  would do is a judgement picard leaves to you (or the picard-triage skill). Don't swap
  cryptography, TLS or parsing of untrusted input for code of your own, however little of it
  you use.
- **No use found**: removable, but nothing imports it or runs its commands - unused, or
  loaded by name (a plugin, a driver, a server extra).

- **Groups** - a direct dependency only another one needs goes with it: pan lists torch
  directly, but it's only there for sentence-transformers, so they're costed together.
- **Extras** count: `uvicorn[standard]`'s uvloop, httptools, watchfiles and websockets are
  attributed to uvicorn.
- **Used** is names imported from it - for a bare `import x`, the `x.name`s the code
  references - plus whether one of its console commands appears in
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
  bundle, so it counts as shipped. A package locked at several versions has each looked up.
- Go: `go.mod` is the build list (replacements applied), plus the **standard library** at
  the `toolchain` or `go` line's version - Dependabot never alerts on stdlib, OSV does. That
  version is a minimum; the Go that builds the binary may be newer. What ships comes from
  `go list -deps ./...` (the non-test build, so test-only modules don't ship), run for
  linux/amd64 (with and without cgo), linux/arm64, darwin/arm64 and windows/amd64 and
  combined, so build tags can't hide a package. Go advisories name the affected packages,
  so an advisory whose packages the build compiles in on no platform is `not-shipped` - a
  fact. For the rest, picard runs [govulncheck](https://go.dev/doc/security/vuln/) (built
  in, no install needed) on the same platforms with the stdlib at that version, and its call
  graph decides: a vulnerable function called is `reachable`, with the call path as the
  reason; a vulnerable package compiled in but its vulnerable functions never called is
  `not-executed` - also a fact, so `dependabot --apply` dismisses it. A cgo platform with no
  C compiler to type-check its C files is analysed with cgo off, and the reason says so;
  those "never called" verdicts then count as judged. The call graph errs towards
  `reachable` (a call through an interface counts any implementation). It takes a few
  seconds a platform. Without a working `go` command, every required module counts as
  shipped.
- `--coverage`, `--assess` and `surface` are Python-only for now.

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
