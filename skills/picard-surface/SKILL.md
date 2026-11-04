---
name: picard-surface
description: Review what a project ships that it could do without, with picard surface - picard measures what each dependency alone brings in and flags the little-used or unused ones; the skill judges whether each can really go, proposes the replacement, and records the decision (keep, defer, replace, remove) in picard.yaml so it stays traceable. Changes code only on confirmation.
disable-model-invocation: true
---

# picard surface

picard measures: the packages each direct dependency alone brings in, how much of it the code
uses, its advisory record. It can't say whether a flagged dependency can really go, or what to
use instead. That's this skill's job - and then recording the decision with the user, so a
flag that was looked at and left alone doesn't come back unexplained.

This is about attack surface, not advisories. Open alerts and PRs are `/picard-triage`'s.

**Arguments:**
- Optional: a path to a checkout of the repository (default `.`).
- Usage: `/picard-surface`, `/picard-surface C:\code\pike`

**Rules that hold throughout:**
- **Every code change is the user's decision** - propose, never make one unprompted.
- **Never record a decision the user hasn't made**, and show the entry before writing it.
- **picard's facts are checked, not trusted blindly** - and never contradicted without
  evidence. If picard is wrong, say so, and offer to report it on JamesWoolfenden/picard.

---

# Process

## 1. Collect the facts

Work in a scratch directory outside the repo. For every directory holding a `uv.lock`,
`package-lock.json` or `go.mod` (skip `node_modules`, `.venv`, `vendor`):

```shell
picard surface -d <lock directory> --format json > <scratch>/surface.json
```

If `picard` isn't on PATH, or `surface` has no Go or npm support, stop: the user needs
`make install` in their picard checkout.

Each dependency in `dependencies` has:
- `packages` - everything that would leave the install if it were removed (Python adds wheel
  size and native code; Go adds `compiled_packages`);
- `used_names` - what the project's code imports from it, and `command` for console commands
  it runs;
- `churn` - its advisory record: all-time, last 3 years, separate events, high or critical;
- `review` - when picard's rules fire: `unused` (nothing imports it) or `replace` (little used
  for what it costs);
- `decided` and `decided_stale` - a decision already recorded in `picard.yaml`, and why the
  facts no longer match it, if they don't.

## 2. Show the picture

One compact summary before any detail: totals, then each flagged dependency on a line with
its packages, names used and recent severe advisories. Separate **open** flags from ones
**decided** in `picard.yaml` (and say if any decision is stale).

Write it for a reader who hasn't seen the tool calls: open with the result, name the picard
commands that produced it, and explain empty or `null` fields in plain terms rather than by
field name.

## 3. Investigate - the judgement picard leaves open

For each open flag, and any stale decision, plus the heaviest few without a flag:

- **Is it really unused?** A plugin, driver or server extra is loaded by name, so grep config,
  Dockerfiles and entry points before saying remove.
- **If little used:** what does the code actually call (`used_names`, then the source)? Is
  that a few lines of the standard library, a narrower package (a sub-module published on its
  own, a single-purpose library), or the same thing reached another way (calling the `git`
  binary instead of a Git library)? Say what the replacement costs in API changes and tests,
  and which of the dependency's advisories it avoids.
- **Does the replacement move the dependency instead of removing it?** Calling a host binary
  or a service takes the risk out of the build but not out of the system, and `picard` can't
  see it. Say so.
- **Does any advisory actually reach the build?** `picard scan` says. If none does, the case
  for acting rests on surface alone, which is a weaker case.
- Prefer changes that shrink what *ships* (packages, compiled packages) over ones that only
  tidy the manifest.

## 4. Propose

Rank by surface removed (packages, then recent high or critical advisory events). For each:
the change, what it costs, what it removes, and a recommendation - including "leave it".
Ask the user, one dependency at a time.

## 5. Act and record, one confirmed step at a time

Whatever the answer, **record the decision**. Add an entry to `decisions:` in the repo's
`picard.yaml` (create it if needed; it is committed with the code, so `git log` is the history
of the decision):

```yaml
decisions:
  - dependency: <as picard surface names it>
    decision: keep | defer | replace | remove
    date: <today>
    reason: <the user's reasoning, in their terms, not yours>
    evidence: <the command, numbers and call sites it rests on>
    revisit: <what would reopen it>
    baseline: {packages: <n>, recent_severe: <n>}   # the measured facts at decision time
```

`keep` and `defer` settle the flag only while the baseline holds; if the dependency grows past
it, picard reopens the flag and says why. `replace` and `remove` record a decision to act and
leave the flag until the change lands.

- **A code change** (replace or remove): on a branch, make it, run the tests, commit following
  the repo's conventions, and open a PR (or push, if the user works straight on the main
  branch). Link the PR in the entry's `evidence`.
- **A decision only** (keep or defer): write the entry, and commit `picard.yaml` on its own so
  the decision has its own place in the history.

## 6. Confirm

Re-run `picard surface` and show the result: what changed in packages (before and after), and
which flags are now decided and which remain open.
