# picard design

## The problem

A dependency alert says "package X at version Y has advisory Z". It doesn't say whether Z
matters to *this* project. Teams end up either upgrading everything blindly or ignoring the
feed, because the feed is mostly noise:

- **Bursts.** One audit of one package produces many advisories at once. pan got 17
  filelock alerts in one batch - all fixed by the same upgrade.
- **Shipping.** Dev and test dependencies raise alerts as loudly as runtime ones.
- **Use.** An installed package may never run, or run only a corner of itself.
- **Fit.** Most advisories have preconditions - another local user, a particular OS,
  attacker-controlled input of some kind - that a given deployment may simply not meet.

picard's job is to collect the evidence for each of those, propose a verdict per advisory,
and record it in a standard format, with every verdict carrying the reason it rests on.

## Principles

- **Evidence, not vibes.** Each verdict names what it's based on; "not affected" without a
  reason is never emitted.
- **Cheapest evidence first.** Exact facts (lock file, imports) before measurements
  (coverage) before judgement (model assessment).
- **Unknown is never safe.** Missing evidence keeps the more serious verdict. An
  unassessed advisory keeps its package-level verdict; a deployment fact left out of
  `picard.yaml` is treated as possibly true.
- **Proposals, not decisions.** The OpenVEX output is for a person to review and commit.
- **One action per upgrade.** Findings are grouped by package, because one version bump
  closes all of a package's advisories.

## Evidence layers

### 1. Advisories (`osv.go`)

Every locked package version is sent to [OSV](https://osv.dev)'s batch API, then each
advisory is fetched for its summary, details, severity, fix versions and references.
OSV aggregates GitHub's advisories (what Dependabot uses) and PyPI's, so it sees at least
what Dependabot does. Each database files its own record of a vulnerability (`GHSA-…`
alongside `PYSEC-…` or `GO-…`), aliasing the others; picard merges records that alias each
other into one advisory, keeping the GitHub id, so pan's count is Dependabot's 19 rather
than 20 (certifi's PYSEC record had been counted twice).

For Go, OSV also covers the standard library (package `stdlib`), which Dependabot doesn't,
and its advisories name the affected import paths. picard compares them with what
`go list -deps ./...` compiles in - on five platform/cgo combinations, combined, so a build
tag can't hide a package - and an advisory none of whose packages is compiled in anywhere
is `not-shipped`, as a fact.

For what is compiled in, picard runs govulncheck in-process (`golang.org/x/vuln/scan`) on
the same platforms, with `GOVERSION` set to the stdlib version picard looked up so both
agree on what's vulnerable. Its JSON stream has a finding per level reached - module,
package, symbol - told apart by the first frame of each trace; picard keeps the deepest
across platforms. A symbol finding is `reachable` with its call path; a package finding
without one is `not-executed`. Findings use the Go database's `GO-` ids, matched through
aliases. Both are facts from the call graph, so `--apply` acts on them - except where a
platform's cgo files couldn't be type-checked (no C compiler for it; `go list` doesn't
need one, govulncheck does). That platform is re-run with cgo off, which can miss a call
only its C-using files make, so "never called" then counts as judged. An advisory
govulncheck doesn't report (not in the Go database, or not for this version) keeps
`shipped`, saying so.

The fix version per advisory is the lowest fixed version above the locked one; per package,
the highest of those - the one upgrade that closes them all.

### 2. Shipped (`lock.go`)

`uv.lock` records the project itself as the package whose source is `.`, with its runtime
dependencies and dev groups. A breadth-first walk from the runtime dependencies gives the
production closure, and for each package the shortest chain that pulls it in
(`plexapi → requests → certifi`). Anything reachable only from dev groups is not shipped.

For npm, "dev dependency" only means "doesn't ship" when nothing bundles the build. A
bundler (esbuild, webpack, vite, rollup, Next.js, ...) copies whatever the code's imports
reach into its output, however it was declared. picard finds the bundler among the project's
own dependencies or as a command its `package.json` scripts run (`vite build`, with vite
brought in only by a plugin) - vitest pulling in vite to run tests doesn't count. Then a
dev-only package is shipped exactly when it's in the dependency closure of the packages the
code imports; one only a tool brings in (`firebase-tools → gaxios → uuid`) stays
`not-shipped`, and the reason says the bundler was taken into account.

Platform markers are ignored, deliberately: a Windows-only dependency counts as shipped.
That can over-report, never under-report.

### 3. Imported (`imports.go`)

A line-based scan of the project's own `.py` files, skipping virtualenvs, build output and
test directories (test imports are tracked separately - they don't ship). Module names are
mapped to package names through the installed environment's `*.dist-info` (`top_level.txt`,
else `RECORD`), because they often differ: `dotenv` is `python-dotenv`.

Static, so `importlib`-style imports are missed - coverage catches those.

### 4. Executed (`coverage.go`)

A coverage.py JSON report, measured with site-packages included
(`coverage run --include="*/site-packages/*"`). coverage.py 7.5+ records executed lines
per function, which separates two very different facts:

- **loaded** - the module body ran, i.e. it was imported;
- **called** - the body of one of its functions ran.

Package-level "loaded" turned out to be nearly useless: importing torch loads filelock and
setuptools, so everything looks executed. Function-level "called" is the useful signal.

The evidence is only as good as the run. A test suite that stubs the network never calls
TLS code that production calls on every request.

### 5. Assessed (`assess.go`, `claude.go`, `deploy.go`)

Some questions only reading the advisory can answer: *what* is vulnerable, and what does an
attacker need? For each advisory against a shipped package, Claude is given:

- the advisory text,
- the fix's code change (GitHub commit or PR from the advisory's `FIX` references, fetched
  as a `.patch`),
- the evidence so far (via chain, imports, functions called),
- the deployment description (`picard.yaml`),

and returns, as schema-constrained JSON:

| Field | Values |
|---|---|
| `affects` | `code` (specific functions), `data` (something shipped that every user of the package consumes), `install` (only while installing/building), `unclear` |
| `affected_symbols` | dotted names within the package, preferring what the fix changes |
| `preconditions` | what an attacker needs |
| `applies` | `yes` / `no` / `unclear` for this deployment |
| `justification` | the OpenVEX `not_affected` justification when `applies` is `no` |
| `reasoning`, `confidence` | for the person reviewing |

Two rules keep the model's part honest:

- **The model extracts; picard decides.** Whether an affected function ran is an exact match
  of `affected_symbols` against coverage's called functions (`MatchSymbols`), not a model
  opinion. A symbol covers a call if it appears as a whole run of dotted segments in the
  call's full name, so a function, its class or its module all match; a leading package name
  is also tried without, because advisories name public paths (`filelock.ReadWriteLock`)
  while code lives in private modules (`filelock._read_write`). Over-matching errs towards
  `reachable`.
- **Declines are failures, not answers.** Advisories describe vulnerabilities, so a safety
  refusal is possible. Requests opt into server-side fallbacks (`fallbacks: "default"`); a
  decline that survives them leaves the advisory unassessed with its package-level verdict.

Assessments are cached on disk keyed by advisory, package version, deployment hash and
model, so each is paid for once.

The deployment description holds only facts an operator can state with confidence -
platform, container, shared host, outbound TLS, exposure, untrusted input, notes - because
`not-applicable` verdicts are exactly as good as it is.

## Verdicts (`triage.go`)

Per advisory, first match wins:

1. Not shipped → `not-shipped`.
2. Assessed, `applies: no` → `not-applicable`.
3. Assessed, `affects: data` → `reachable` (used wherever the package is; coverage is beside
   the point).
4. Assessed, `affects: install` → `shipped` (a build-pipeline concern, not runtime).
5. Assessed `code` with symbols, and coverage shows none of the package ran → `not-executed`.
6. Assessed `code` with symbols, and function-level coverage → `reachable` if any affected
   symbol matched a called function, else `not-executed`.
7. Otherwise the package-level verdict: `reachable` (functions called, or imported directly),
   `import-only`, `not-executed`, or `shipped` when there's no coverage at all.

A package's verdict is its most serious advisory's: `reachable` > `shipped` >
`import-only` > `not-executed` > `not-applicable` > `not-shipped`.

## Dependabot (`github.go`, `dependabot.go`)

`picard dependabot` closes the loop from verdict to action on GitHub.

- **Alerts** are listed through the Dependabot alerts REST API (paginated via `Link`).
- **Lock per alert.** Each alert names its manifest; picard reads it when it's a lock it
  understands (`uv.lock`, `package-lock.json`), or the lock beside a `pyproject.toml` /
  `package.json`. One scan per lock, run from that lock's directory so imports are the
  right project's. Anything else is skipped with a reason - never dismissed.
- **Matching** is by advisory id: OSV's id or any of its aliases equals the alert's GHSA
  id, for the same package (names compared per ecosystem). No match - typically the lock
  already has the fix - means skip.
- **Two tiers of automation.** A `not-shipped` verdict is a fact from the lock graph, and
  a Go `not-executed` from govulncheck's complete call graph is too, so `--apply` dismisses
  them. Verdicts resting on a coverage run or a model's assessment are
  dismissed only with `--apply-judged`, because they're exactly as good as that evidence.
  Dependabot's `not_used` and `tolerable_risk` reasons carry picard's reasoning as the
  dismissal comment (truncated to Dependabot's 280 characters).
- **Dry run by default**, and failures to dismiss one alert don't stop the rest.

Replaying pan's 19 fixed alerts against its pre-fix lock matched all 19 to picard's
advisories: certifi kept open, the 18 filelock/setuptools alerts proposed as
`tolerable_risk` on judgement - the same calls made by hand.

## Surface (`surface.go`, `surface_scan.go`)

Triage reduces the cost of alerts; surface reduces their number, by showing what each
direct dependency costs.

- **What removing it removes** is the production closure minus the closure of the remaining
  direct dependencies - so a package shared with another dependency (numpy, used by librosa
  and sentence-transformers) is never attributed to either.
- **Groups.** A direct dependency that's only otherwise needed by one other direct
  dependency goes with it (pan's torch, listed for its CPU-index pin, is only there for
  sentence-transformers). One that several others need is reported as "removing it alone
  removes nothing".
- **Extras.** `pkg[extra]` installs the extra's optional dependencies; the lock reader adds
  them as pkg's own edges, so they're attributed to pkg. (This also fixed `scan`, which
  previously under-reported what ships.)
- **Wheel choice.** For the target OS/arch/Python (default: `picard.yaml`'s platform, x86_64,
  the lock's `requires-python` minimum), the best-fitting wheel across the package's locked
  variants: exact CPython build > stable ABI (`abi3`, if old enough) > `py3`. That decides
  *native* (a platform-specific wheel is compiled code) and *size* (unknown when the index
  doesn't publish it, e.g. PyTorch's, shown as `>=`).
- **History.** Every advisory ever published against each package, from OSV's batch API
  without a version (paged) - the churn signal, as opposed to current exposure.
- **Use.** Names imported from the group's modules (multi-line, aliased and commented
  `from x import (...)` handled), functions called in coverage, and console commands: each
  installed package's `entry_points.txt` `[console_scripts]`, matched as words in the
  Dockerfile, Makefile, compose and launch scripts.
- **Undeclared imports.** Production imports of a locked package that isn't a direct
  dependency - flagged with the chain providing it, or as failing in production when only
  dev dependencies provide it. These are the hidden coupling that breaks a removal.

## Output (`report.go`)

- **table** - one line per upgrade, then the reasoning, with advisory counts per verdict.
- **json** - everything, including each advisory's assessment.
- **vex** - an [OpenVEX](https://openvex.dev) document, one statement per advisory:

| Verdict | OpenVEX |
|---|---|
| `reachable` | `affected`, with an upgrade action |
| `shipped` | `under_investigation` |
| `import-only`, `not-executed` | `not_affected` / `vulnerable_code_not_in_execute_path` |
| `not-applicable` | `not_affected` / the assessment's justification |
| `not-shipped` | `not_affected` / `component_not_present` |

OpenVEX was chosen over tool-specific ignore files because other scanners and platforms
read it, and it states *why* something isn't affected rather than just silencing it.
