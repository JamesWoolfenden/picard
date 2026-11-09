---
name: picard-triage
description: Work through a repository's Dependabot alerts and PRs with picard - picard supplies the facts (what ships, which advisories each PR fixes, the Dependabot setup), the skill does the judgement (is a bump safe to merge, do an advisory's preconditions hold) and carries out each action with the user. Changes GitHub state only on confirmation.
---

# picard triage

picard is deterministic: lock graphs, OSV advisories, import scans, Dependabot's API. It
can say *what* a PR or alert is - "removes a high advisory in a shipped package", "a floor
bump that changes nothing installed", "only a dev tool pulls this in". It can't say whether
anthropic 1 → 2 breaks the code, or whether an attacker could meet an advisory's
preconditions here. That's this skill's job, and then acting on the result with the user.

**Arguments:**
- Optional: a path to a checkout of the repository (default `.`).
- Optional: a GitHub owner (`JamesWoolfenden`) instead of a path - triage every repo they
  have, starting at step 0.
- Optional: `--dry-run` - investigate and present the plan, take no action.
- Usage: `/picard-triage`, `/picard-triage C:\code\garmin-mcp-gt`, `/picard-triage JamesWoolfenden`,
  `/picard-triage --dry-run`

**Rules that hold throughout:**
- **Every outward action is confirmed first** - merge, close, comment, dismiss, change a
  setting, push. Approval for one item isn't approval for the next.
- **Never merge a PR whose CI isn't passing**, and never on a major bump without having done
  step 3b.
- **picard's facts are checked, not trusted blindly** - and never contradicted without
  evidence. If picard is wrong, say so, and offer to report it (step 6).
- **Standing approval is allowed, but ask for it once.** Confirming every item separately
  costs a round trip each. After the first confirmed upgrade, offer a class-level approval -
  e.g. "push dependency upgrades to each repo's default branch when the tests pass and
  `picard scan` shows nothing reachable?" - and then do that class without asking again.
  Anything outside the class (a merge, a dismissal, a setting) is still its own question.
- **A dismissal's comment states only what you verified.** "Dev-only build dependency" is a
  claim about the build, not about picard's verdict - a bundled app ships its devDependencies.
  Say what was checked and by what (picard's `not-shipped`, a call graph, the lock chain), and
  where picard's verdict could be wrong for this kind of project, say so instead of asserting it.
- **Pinning isn't this skill's job** - an unpinned manifest is ghat's (`ghat audit`, and
  JamesWoolfenden/ghat#32 for requirements files). Point at it; don't pin here.

---

# Process

## 0. A whole account (owner argument only)

Skip this for a single repository. For an owner, get the picture before touching anything -
in **one GraphQL query**, not a call per repo (268 repos took ~26 seconds this way, and minutes
as a REST loop):

```shell
gh api graphql --paginate -f query='query($endCursor:String){repositoryOwner(login:"<owner>"){
  repositories(first:100,after:$endCursor,isArchived:false,isFork:false,ownerAffiliations:OWNER){
    pageInfo{hasNextPage endCursor}
    nodes{name pushedAt hasVulnerabilityAlertsEnabled vulnerabilityAlerts(states:OPEN){totalCount}
      pullRequests(states:OPEN,first:20){nodes{number title author{login}}}}}}}' \
  --jq '.data.repositoryOwner.repositories.nodes[]'
```

The Dependabot PRs are the ones whose `author.login` is `dependabot`. A repo with
`hasVulnerabilityAlertsEnabled: false` is **not being checked**: before offering to turn it on,
look for dependency manifests (`gh api repos/<owner>/<repo>/git/trees/HEAD?recursive=1`, paths
ending `go.mod`, `package.json`, `requirements*.txt`, `Pipfile.lock`, `uv.lock`, ...). A repo with
none (a Terraform module, a docs repo) gains nothing from alerts - say so rather than listing it
as a gap. Make a roll-up table (repo, open alerts, open PRs, alerts enabled, checked out
locally?) and show it first; when nothing has alerts or PRs, say that and stop.

Clone the repos that have alerts or PRs and aren't checked out (`gh repo clone`, next to the
others), then run steps 1-2 for each, in parallel where independent, and show **one** roll-up of
verdicts per repo. Work through the repos one at a time from step 3, biggest first - the same
few packages (go-git, otel, grpc, go-jose) often account for most of a family of repos, so a
fix found for one is cheap to repeat.

Before investing in a repo, check it is alive: the date of the last real commit, and ask if it
looks abandoned. A retired app doesn't need a framework migration - offer to archive or delete
it, after checking what would be lost (unpushed commits, stars, forks, open issues, whether
anything else references it).

## 1. Collect the facts

Work in a scratch directory outside the repo.

```shell
picard dependabot -d <path> --prs --format json > <scratch>/dependabot.json
```

If `picard` isn't on PATH, or `dependabot` / `--prs` is unknown, stop: the user needs
`make install` in their picard checkout. (There is no `--version` flag; `picard dependabot --help`
is the check.)

The JSON has three sections:
- `settings.checks` - Dependabot alerts / security updates / version updates, each `ok` or a
  `problem` with its `fix`; `settings.pull_requests` - Dependabot's open PRs.
- `alerts` - one per open alert: picard's `verdict`, `reason`, proposed `action`
  (keep-open / dismiss / skip), `dismiss_reason`, and `judged` (rests on coverage or a
  model's assessment rather than lock facts). The alert itself is nested under `.alert`:
  `.alert.number`, `.alert.dependency.package.name`, `.alert.dependency.manifest_path`,
  `.alert.security_advisory.{ghsa_id,severity,summary}`,
  `.alert.security_vulnerability.first_patched_version.identifier`. A jq on `.number` or
  `.package` returns null.
- `pull_requests` - one per PR: `class` (fixes-shipped, fixes-dev-only, adds-advisory,
  fixes-nothing, no-install-change, unknown), `removes` / `adds` advisories with verdicts,
  `ci`, `major` (absent = couldn't be checked, not false) with `major_changes` (each package
  that moved major, from the lock diff), `from` / `to` (empty for a grouped PR), `files`.

Then scan each lock in the repo for advisories Dependabot has **no alert for** - OSV knows
some GitHub doesn't:

```shell
picard scan -d <lock directory> --format json
```

for every directory holding a `uv.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock`,
`go.mod` or a pinned `requirements.txt` (skip
`node_modules`, `.venv`, `vendor`). For Go this includes the standard library, which
Dependabot never alerts on - expect unalerted stdlib advisories.
Keep the advisories with a shipped verdict (`reachable`, `shipped`) that match no alert;
note whether an open PR's `removes` covers them.

## 2. Show the picture

One compact summary before any detail:

- **Setup** - each failing check, one line.
- **PRs** - one line each: number, package, from → to, CI, class, and for `fixes-shipped`
  the advisories (package, severity).
- **Alerts** - grouped as picard's table groups them: package, alert numbers, verdict,
  proposed action.
- **Unalerted advisories** from step 1, if any.

Write it for a reader who hasn't seen the tool calls. Open with the result, name the picard
commands that produced it, and say what an empty or `null` field means in plain terms (e.g.
"`picard scan` found no advisories" - not a bare field name like `.findings`). If a jq
filter errors on a clean result, say that's why, don't leave the error unexplained.

## 3. Investigate - the judgement picard leaves open

Do these before proposing anything. Say what you checked and what you found.

### a. PRs that fix something (`fixes-shipped`, `fixes-dev-only`)

These are the ones worth merging. For each:
- CI `passing`? If `pending`, say so and revisit; if `failing`, read the failed job's log
  (`gh run view --log-failed`) and say why.
- What else changes: the PR's lock diff often moves more than the named package. Read
  `gh pr diff <n>` for the lock, list other packages that change major version.
- If `major` (or another package moves major), do 3b.

### b. Major version bumps

For the package going from major X to Y:
1. Find what the project uses from it - imports and names (`picard surface -d <dir>` lists
   names used per dependency for Python; grep imports for npm).
2. Read the release notes / changelog / migration guide between the two versions (GitHub
   releases via `gh release list -R <repo>` / `gh api`, or the package's changelog). Note
   every breaking change that touches a name the project uses.
3. **Check the peer dependencies of the new major.** A grouped Dependabot PR bumps the named
   packages and leaves the rest: `npm view <pkg>@<new> peerDependencies` (and `engines`)
   against what the project has. Kit 3 needing vite 8 and TypeScript 6 while the PR left
   both alone is the typical failure - and the only CI may be a secret scanner, so a green PR
   proves nothing.
4. Build it, in a scratch copy outside the repo (`git archive <head> | tar -x -C <scratch>`,
   then install and build; `git archive` leaves untracked files out, and a scratch path with odd
   characters can break tools like `vsce`, so compare against a baseline build before blaming
   the change). Prefer the project's real build over `check`/lint, which may already fail.

Report: the breaking changes that apply, those that don't, the peer dependencies, and the
build and test result. If a major bump is the only fix for a low-severity dev-only alert in a
project that is barely used, say that migrating costs more than the alert, and let the user decide.

**For `no-install-change` floor bumps, the major question is already settled in
production:** an unpinned `>=1.13.0` already installs 2.x on every build. Check the code
works with the version builds actually get *now* (resolve it: the PR's `to`, or
`uv pip compile` the file to see) - if it doesn't, production is already broken, which
matters far more than the PR.

### c. PRs that change nothing (`fixes-nothing`, `no-install-change`)

Noise for security purposes. Check whether the user might still want one - a feature in
the newer version they're waiting for, or keeping a floor honest - and propose closing the
rest with a comment saying why (picard's `reason`).

### d. `adds-advisory`

Read the added advisories: verdict, severity. Recommend not merging until a version
without them, unless they're `not-shipped` or clearly outweighed by what it removes.

### e. Alerts

- **`dismiss`, not judged** (`not-shipped`) - verify the chain in `reason` makes sense: is
  the top of the chain really a dev/build tool? For npm with a bundler, picard already
  checked whether the code's imports reach it; if there's a build output directory
  (`dist/`, `build/`), confirm the package isn't in it.
- **Go `dismiss`, not judged** (`not-executed` with `go_reach.level` `imported`) -
  govulncheck's call graph found no path to a vulnerable function on any platform. A fact,
  as solid as `not-shipped`; no need to second-guess it.
- **`dismiss`, judged** - read each `reason`. These rest on a coverage run (did it exercise
  the real paths?), a model's assessment against `picard.yaml` (are the deployment facts
  right?), or for Go a govulncheck run with a platform's cgo files unseen (does the project
  have its own cgo code, or use cgo-only stdlib paths - the `net` resolver, `os/user` - on
  that platform?). Say for each whether you agree.
- **`keep-open`** - find the fix: an open PR whose `removes` covers it, else the upgrade
  that does (`fix_version` from `picard scan`), and how to apply it
  (`uv lock --upgrade-package <pkg>`, `pipenv update <pkg>`, `npm update <pkg>` /
  `npm install <pkg>@<version>`, `yarn upgrade <pkg>`, or the pinned line in `requirements.txt`,
  in the lock's directory).
- **Go `reachable`** - `go_reach.trace` (in `picard scan --format json`) is the call path
  from the project's code to the vulnerable function. Read it: govulncheck errs towards
  reachable, so a call through an interface counts every implementation
  (`WriteTable → fmt.Fprintf → tls.(*Conn).Write` means the writer *could* be a TLS
  connection). Say whether the path is real. Even if it isn't, the fix is usually cheap - so
  prefer the upgrade over a `tolerable_risk` dismissal, and only dismiss on the user's say.
- **Go stdlib** - picard checks the stdlib at go.mod's `toolchain`/`go` version, a minimum.
  Find the Go the project is really built with (Dockerfile `FROM golang:`, CI `setup-go`,
  `.go-version`); if that already has the fix, the advisory doesn't apply to what ships, and
  the clean fix is raising the `toolchain` line so picard (and the next reader) agree. Either
  way the upgrade is a `toolchain`/`go` line bump, not a dependency bump.
- **`skip`** - say why picard couldn't judge it (usually a manifest it can't read).

### f. Unalerted shipped advisories

Same as a `keep-open` alert: the fixing PR, or the upgrade.

### g. Setup

For each failing check, its fix. Version updates off means editing
`.github/dependabot.yml` (`open-pull-requests-limit: 0` per entry) - a commit to the repo.

### h. `picard.yaml`

If the repo has none and judged verdicts matter (alerts kept open whose preconditions might
not hold), offer to draft one from the repo - Dockerfile, deploy scripts, Terraform, compose
- stating only facts the files show (platform, container, exposure, untrusted input), each
with where it came from, for the user to review. Unknown stays out: picard treats a missing
fact as possibly true.

### i. Attack surface

What the project ships that it could do without is a separate job: run `/picard-surface`. Mention
it in the plan if `picard surface` flags anything, but don't do it here.

## 4. Propose the plan

One list, most valuable first. **Fix before you dismiss**: an upgrade usually closes the
alerts a judged dismissal would have papered over, and Dependabot closes them by itself within
a minute of the push.
1. merges of PRs that fix shipped advisories,
2. upgrades for shipped advisories without a PR - then rescan (step 5),
3. dismissals of what is *left* after the upgrades and has no fix (facts first, then judged -
   each with its reason),
4. closes of noise PRs,
5. setup changes.

Each item: the action, the exact command, and the one-line reason. With `--dry-run`, stop
here.

Ask the user which to do - in groups where they're alike (e.g. "close #36, #37, #39, #40 as
changing nothing installed?"), individually where they aren't.

## 5. Act, one confirmed step at a time

- **Merge**: check `gh pr checks <n>` again first. Use the repo's merge method
  (`gh repo view --json squashMergeAllowed,mergeCommitAllowed,rebaseMergeAllowed`).
  `gh pr merge <n> --squash` (or the allowed one).
- **Close**: `gh pr close <n> --comment "<why>"`. Dependabot won't reopen that version; if
  the user wants no more PRs for the package, comment `@dependabot ignore this dependency`.
- **Dismiss** (only what no upgrade fixes): for all fact-based dismissals, `picard dependabot -d <path> --apply`; for
  judged ones the user agreed with, `--apply-judged`. If the user approved only some, dismiss
  those individually:
  `gh api -X PATCH repos/<repo>/dependabot/alerts/<n> -f state=dismissed -f dismissed_reason=<reason> -f dismissed_comment="<picard's reason, ≤280 chars>"`.
- **Upgrade**: on a branch, update the lock, re-run `picard scan` to confirm the advisory is
  gone, run the tests, commit following the repo's conventions, and open a PR (or push, if
  the user works straight on the main branch). Take the **highest** `fix_version` across the
  package's advisories, not the lowest, and **rescan after the upgrade and repeat until nothing
  is reachable**: new advisories keep appearing (a patch release of gRPC, a newer `x/net`, the
  Go standard library), and a bump that pulls in a dependency's own minimum
  (`x/net` needing a newer `x/text`) is normal - `go get` both together. For Go, raise the
  `go` line when the stdlib advisory is the remaining one, and check the Dockerfile and CI pin
  the same Go.
- **Commits**: edit files **byte-for-byte** - many repos here use CRLF, and `sed -i` or a jq
  round trip rewrites every line ending (or an escape like `\u2014`) and turns a 3-line change
  into a whole-file diff; check `git diff --stat` before committing. Read the hook config
  (`.pre-commit-config.yaml`) first: autofix hooks (`pretty-format-json`) re-sort a lockfile's
  keys, and linters can exit non-zero on informational findings. Fix the cause (exclude the
  lockfile, add a suppression with a reason, raise the severity floor - and say so) with the
  user's say-so; never `--no-verify`.
- **Setup**: run the `fix` command; for `dependabot.yml`, edit, commit, push as above.

After each action, report what was done and where (PR URL, alert number).

## 6. Confirm and close out

Show what's left, and why. After a fix, `picard dependabot` reports the alerts as `skip`
("already fixed in the lock") - that is not a failure. Read the real state from GitHub:
`gh api "repos/<repo>/dependabot/alerts?state=open" --jq length` (Dependabot re-evaluates within
about a minute of a push; an alert still open straight after is usually just not re-scanned
yet), and `gh pr list --author "app/dependabot"`. Then rerun `picard scan` per lock to confirm
nothing is shipped or reachable.

If picard was wrong anywhere (a verdict the evidence contradicts, a PR misclassified, a
manifest it should have read), say exactly how, and offer to open an issue on
JamesWoolfenden/picard with the repo, the item, what picard said and what was true.

**A large `skip` class is a finding too.** When a big share of the alerts can't be judged because
picard doesn't read their manifest (a quarter or more), say so in step 2 and offer the issue
straight away instead of at the end; the fix is usually a reader, not a workaround.
