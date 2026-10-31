# picard Claude Code skills

picard itself is deterministic: lock graphs, OSV, import scans, the Dependabot API. These
skills add the judgement on top - is a bump safe to merge, do an advisory's preconditions
hold - and carry out the actions with you.

| Skill | Purpose |
|-------|---------|
| `picard-triage` | Work through a repo's Dependabot alerts and PRs: picard's facts, then investigation of what needs judgement, then each merge / close / dismiss / setting change on your confirmation. |

## Installation

Skills need to be in `~/.claude/skills/` to be available in any repo. Link rather than
copy, so updates stay in sync.

macOS / Linux:

```bash
ln -sf /path/to/picard/skills/picard-triage ~/.claude/skills/
```

Windows (a junction needs no admin rights; Git Bash's `ln -s` silently copies instead):

```powershell
New-Item -ItemType Junction -Path "$env:USERPROFILE\.claude\skills\picard-triage" -Target "C:\path\to\picard\skills\picard-triage"
```

## Usage

From a checkout of the repository:

```
/picard-triage              # investigate, propose, act on confirmation
/picard-triage --dry-run    # investigate and propose only
/picard-triage C:\code\garmin-mcp-gt
```

## Requirements

- `picard` on PATH (`make install`), with `dependabot --prs`
- `gh`, logged in with access to the repo's Dependabot alerts
