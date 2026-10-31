---
name: picard-triage
description: Work through a repository's Dependabot alerts and PRs with picard - picard supplies the facts (what ships, which advisories each PR fixes, the Dependabot setup), the skill does the judgement (is a bump safe to merge, do an advisory's preconditions hold) and carries out each action with the user. Changes GitHub state only on confirmation.
disable-model-invocation: true
---

# picard triage

picard is deterministic: lock graphs, OSV advisories, import scans, Dependabot's API. It
can say *what* a PR or alert is - "removes a high advisory in a shipped package", "a floor
bump that changes nothing installed", "only a dev tool pulls this in". It can't say whether
anthropic 1 → 2 breaks the code, or whether an attacker could meet an advisory's
preconditions here. That's this skill's job, and then acting on the result with the user.

**Arguments:**
- Optional: a path to a checkout of the repository (default `.`).
- Optional: `--dry-run` - investigate and present the plan, take no action.
- Usage: `/picard-triage`, `/picard-triage C:\code\garmin-mcp-gt`, `/picard-triage --dry-run`

**Rules that hold throughout:**
- **Every outward action is confirmed first** - merge, close, comment, dismiss, change a
  setting, push. Approval for one item isn't approval for the next.
- **Never merge a PR whose CI isn't passing**, and never on a major bump without having done
  step 3b.
- **picard's facts are checked, not trusted blindly** - and never contradicted without
  evidence. If picard is wrong, say so, and offer to report it (step 6).
- **Pinning isn't this skill's job** - an unpinned manifest is ghat's (`ghat audit`, and
  JamesWoolfenden/ghat#32 for requirements files). Point at it; don't pin here.

---

# Process

## 1. Collect the facts

Work in a scratch directory outside the repo.

```shell
picard dependabot -d <path> --prs --format json > <scratch>/dependabot.json
```

If `picard` isn't on PATH, or `dependabot` / `--prs` is unknown, stop: the user needs
`make install` in their picard checkout.

The JSON has three sections:
- `settings.checks` - Dependabot alerts / security updates / version updates, each `ok` or a
  `problem` with its `fix`; `settings.pull_requests` - Dependabot's open PRs.
- `alerts` - one per open alert: picard's `verdict`, `reason`, proposed `action`
  (keep-open / dismiss / skip), `dismiss_reason`, and `judged` (rests on coverage or a
  model's assessment rather than lock facts).
- `pull_requests` - one per PR: `class` (fixes-shipped, fixes-dev-only, adds-advisory,
  fixes-nothing, no-install-change, unknown), `removes` / `adds` advisories with verdicts,
  `ci`, `major`, `from` / `to`, `files`.

Then scan each lock in the repo for advisories Dependabot has **no alert for** - OSV knows
some GitHub doesn't:

```shell
picard scan -d <lock directory> --format json
```

for every directory holding a `uv.lock` or `package-lock.json` (skip `node_modules`, `.venv`).
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
3. If the project's tests are quick, check out the PR branch in a worktree and run them.

Report: the breaking changes that apply, those that don't, and the test result.

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
- **`dismiss`, judged** - read each `reason`. These rest on a coverage run (did it exercise
  the real paths?) or a model's assessment against `picard.yaml` (are the deployment facts
  right?). Say for each whether you agree.
- **`keep-open`** - find the fix: an open PR whose `removes` covers it, else the upgrade
  that does (`fix_version` from `picard scan`), and how to apply it
  (`uv lock --upgrade-package <pkg>`, `npm update <pkg>` / `npm install <pkg>@<version>`
  in the lock's directory).
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

## 4. Propose the plan

One list, most valuable first:
1. merges of PRs that fix shipped advisories,
2. upgrades for shipped advisories without a PR,
3. dismissals (facts, then judged - each with its reason),
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
- **Dismiss**: for all fact-based dismissals, `picard dependabot -d <path> --apply`; for
  judged ones the user agreed with, `--apply-judged`. If the user approved only some, dismiss
  those individually:
  `gh api -X PATCH repos/<repo>/dependabot/alerts/<n> -f state=dismissed -f dismissed_reason=<reason> -f dismissed_comment="<picard's reason, ≤280 chars>"`.
- **Upgrade**: on a branch, update the lock, re-run `picard scan` to confirm the advisory is
  gone, run the tests, commit following the repo's conventions, and open a PR (or push, if
  the user works straight on the main branch).
- **Setup**: run the `fix` command; for `dependabot.yml`, edit, commit, push as above.

After each action, report what was done and where (PR URL, alert number).

## 6. Confirm and close out

Re-run `picard dependabot -d <path> --prs` and show the result - what's left, and why.

If picard was wrong anywhere (a verdict the evidence contradicts, a PR misclassified, a
manifest it should have read), say exactly how, and offer to open an issue on
JamesWoolfenden/picard with the repo, the item, what picard said and what was true.
