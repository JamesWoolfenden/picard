# picard - Claude guidance

## What this project is

`picard` triages dependency vulnerability alerts: for each advisory against a locked
package, it collects evidence (shipped in production? imported? executed?) and proposes a
verdict, with OpenVEX output to record the decision. Sibling of ghat and holden, same
conventions (urfave/cli, zerolog, `src/core`, `src/version`).

Module path: `github.com/jameswoolfenden/picard`

## Layout (`src/core`)

- `lock.go` - uv.lock parsing, dependency closure with "why is this here" chains
- `npmlock.go`, `npmimports.go` - package-lock.json parsing (same Lock model, ecosystem npm)
  and the JS/TS import scan; `scan` picks the lock by file name
- `imports.go` - static import scan of the project's own code; module -> package owners
  from the installed environment's dist-info
- `coverage.go` - coverage.py JSON: per-module loaded vs functions actually called
- `osv.go` - OSV batch query + per-advisory details, fix-version selection, fix patches
- `deploy.go` - `picard.yaml` deployment description
- `assess.go` - Assessment, on-disk cache, symbol matching against coverage
- `claude.go` - Claude assessor (beta endpoint: structured output + server-side fallbacks,
  since advisories describe vulnerabilities and a refusal is possible)
- `triage.go` - evidence -> per-advisory and per-package Verdict
- `report.go` - table, JSON and OpenVEX output
- `github.go`, `dependabot.go` - `picard dependabot`: list a repo's alerts, match them to
  verdicts by GHSA id, propose/apply dismissals (fact-based with `--apply`, judged ones only
  with `--apply-judged`). Never dismiss real alerts while testing - dry-run, or use
  `--state fixed --lock <old lock>`.
- `surface.go`, `surface_scan.go` - `picard surface`: what each direct dependency alone
  brings in (packages, native code, size, advisory history, use) and undeclared imports
- `scan.go` - wires it together

## Working in this repo

- It's the user's own project: commit straight to `master`, no feature branches.
- Run `go test ./...` before committing; `make install` to update the binary on PATH.
- Never claim certainty the evidence doesn't support - verdicts are proposals, and every
  `not_affected` must say what evidence it rests on.

## Commit message style

Do **not** add `Co-Authored-By:` attribution lines to commits in this repo.
