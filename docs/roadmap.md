# Roadmap

Roughly in order of value. Nothing here is started.

## Churn: is a package noisy, or risky?

Part of the original idea, not built yet. A package's alert history says something its
current alerts don't:

- advisories per year, and the share that were low severity or local-attacker-only;
- bursts - many advisories published together (an audit sweep of one subsystem, like
  filelock's 17) versus a steady trickle;
- release cadence and project health from [deps.dev](https://deps.dev) and OpenSSF
  Scorecard (maintainers, release frequency, scorecard checks) - free APIs.

The output would separate "noisy but rarely relevant" from "rarely flagged, so pay attention
when it is", and could feed a default stance per package.

## Footprint: how much of a package is used

Also from the original idea. Distinct functions/classes the project's code (and its
coverage run) touches, against the package's public surface, plus the weight of what it
pulls in transitively. "Uses 2 functions and drags in 14 packages" is a candidate to replace
with a few lines of code - useful beyond security.

## Better execution evidence

- **Production-like runs.** Document and script coverage of a smoke run of the real app
  (start the server under coverage, hit its endpoints), since test suites stub exactly the
  code that matters (network, TLS).
- **Merge several coverage reports** (tests + smoke).

## More ecosystems and lock files

- Python: `poetry.lock`, `requirements.txt` with hashes, `pdm.lock`.
- Go (`go.sum` + `govulncheck`-style symbol data, which Go advisories already carry).
- npm (`package-lock.json`).

## Platform markers

Evaluate `uv.lock` markers against the deployment's platform/Python version, so a
Windows-only dependency isn't counted as shipped on Linux. Today it is, deliberately
conservative.

## Integration

- **pan**: commit `picard.yaml` and the reviewed VEX file; run picard in CI.
- **picard's own CI**: GitHub Actions with tests on push, actions pinned with `ghat swot`.
- **AI-context output** (`--format ai-context`) like holden's, for use inside assistants.
- **Consume VEX**: read an existing VEX file and only report advisories without a recorded
  decision, so a reviewed `not_affected` stops resurfacing.
- **Expiry**: VEX statements carry a review-by date, after which they're reported again.

## Assessment quality

- Evaluate assessments against a hand-labelled set of advisories (pan's 20 are the first).
- Record the assessor model and date in VEX impact statements.
- Use OSV's `affected[].ecosystem_specific` symbol data where an ecosystem provides it,
  falling back to model extraction only when it doesn't.
