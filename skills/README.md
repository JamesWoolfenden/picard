# picard Claude Code skills

picard itself is deterministic: lock graphs, OSV, import scans, the Dependabot API. These
skills add the judgement on top - is a bump safe to merge, do an advisory's preconditions
hold - and carry out the actions with you.

| Skill | Purpose |
|-------|---------|
| `picard-triage` | Work through a repo's Dependabot alerts and PRs: picard's facts, then investigation of what needs judgement, then each merge / close / dismiss / setting change on your confirmation. |
| `picard-surface` | Review what a project ships that it could do without: picard measures what each dependency alone brings in, the skill judges whether it can go and what to use instead, and every decision (keep, defer, replace, remove) is recorded in `picard.yaml`. |

## Installation

Skills need to be in `~/.claude/skills/` to be available in any repo. Link rather than
copy, so updates stay in sync.

macOS / Linux:

```bash
ln -sf /path/to/picard/skills/picard-triage ~/.claude/skills/
ln -sf /path/to/picard/skills/picard-surface ~/.claude/skills/
```

Windows (a junction needs no admin rights; Git Bash's `ln -s` silently copies instead):

```powershell
New-Item -ItemType Junction -Path "$env:USERPROFILE\.claude\skills\picard-triage" -Target "C:\path\to\picard\skills\picard-triage"
New-Item -ItemType Junction -Path "$env:USERPROFILE\.claude\skills\picard-surface" -Target "C:\path\to\picard\skills\picard-surface"
```

## Usage

From a checkout of the repository:

```
/picard-triage              # investigate, propose, act on confirmation
/picard-triage --dry-run    # investigate and propose only
/picard-triage C:\code\garmin-mcp-gt

/picard-surface             # what could this project ship less of? decide, record in picard.yaml
```

## Requirements

- `picard` on PATH (`make install`), with `dependabot --prs`
- `gh`, logged in with access to the repo's Dependabot alerts
