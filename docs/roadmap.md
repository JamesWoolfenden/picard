# Roadmap

Roughly in order of value.

## Done: surface (`picard surface`)

Per direct dependency: packages it alone brings in, native code, size, every past advisory,
names used, functions called, console commands run - plus undeclared imports. See the
README and design doc.

## Churn, beyond a total count

`surface` counts each package's past advisories. Still to do:

- advisories per year rather than all-time, and the share that were low severity or
  local-attacker-only (as assessed);
- bursts - many advisories published together (an audit sweep of one subsystem, like
  filelock's 17) versus a steady trickle;
- release cadence and project health from [deps.dev](https://deps.dev) and OpenSSF
  Scorecard (maintainers, release frequency, scorecard checks) - free APIs.

The output would separate "noisy but rarely relevant" from "rarely flagged, so pay attention
when it is", and could feed a default stance per package.

## Footprint, beyond names used

`surface` reports names imported and functions called. Still to do: compare against each
package's public surface ("uses 2 of 340 functions"), and suggest replacements - e.g. a
sentence-embedding model run with onnxruntime + tokenizers instead of the whole PyTorch
stack.

## Better execution evidence

- **Production-like runs.** Document and script coverage of a smoke run of the real app
  (start the server under coverage, hit its endpoints), since test suites stub exactly the
  code that matters (network, TLS).
- **Merge several coverage reports** (tests + smoke).

## More ecosystems and lock files

- Python: `poetry.lock`, `requirements.txt` with hashes, `pdm.lock`.
- Go: done for `go.mod`, with package-level reachability from `go list -deps` and
  function-level from govulncheck's call graph. Still to do: the toolchain version the build
  actually uses (Dockerfile `FROM golang:`, CI `setup-go`) rather than go.mod's minimum, and
  govulncheck on pull requests' go.mod (it analyses the checkout's own).
- npm: coverage evidence (v8 / vitest coverage), `surface`, and `npm audit`-style fix paths. Basic `scan` of `package-lock.json` is done.

## Platform markers

Evaluate `uv.lock` markers against the deployment's platform/Python version, so a
Windows-only dependency isn't counted as shipped on Linux. Today it is, deliberately
conservative.

## Integration

Done: `picard dependabot` proposes and (with `--apply` / `--apply-judged`) dismisses
Dependabot alerts. Still to do:

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
