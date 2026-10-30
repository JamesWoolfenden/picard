# Case study: pan's 19 alerts

picard exists because of one afternoon on pan, a self-hosted music app (FastAPI, Python
3.12, uv, one Docker container on a Synology NAS, reachable only over a private Tailscale
tailnet). This is what happened, including what went wrong, since that shaped the design.

## The alerts

Every push printed GitHub's warning: 19 Dependabot alerts - 1 critical, 1 high, 12 moderate,
5 low. Listed, they were three packages, all transitive:

| Package | Alerts | Fixed in | Summary |
|---|---|---|---|
| certifi | 1 critical | 2026.10.18 | bundled root CAs with compromised intermediate keys |
| filelock | 1 high, 11 moderate, 5 low | 4.2.1 | a family of lock-file attacks by another local user |
| setuptools | 1 low | 84.1.0 | Windows path escape during legacy wheel installation |

Three `uv lock --upgrade-package` calls fixed all 19. The interesting question came after:
could we have known which of them mattered?

## Judgement without tools

The first answer was judgement by package role, not code: certifi matters (it decides which
HTTPS servers to trust), filelock probably doesn't (needs a hostile local user; pan runs
alone in a container), setuptools doesn't ("install-time only, not in the running app").

The last part was wrong. picard's lock-file walk showed `torch → setuptools`: setuptools is
a runtime dependency of torch and ships in pan's image. The *verdict* survived (it's a
Windows-only install-time bug, and pan is Linux built in CI), but the reasoning didn't -
exactly the kind of confident shortcut a triage tool should replace with evidence.

## Stage 1-2: lock, imports, coverage

```text
pan: 20 advisories across 3 packages - 3 upgrade(s) fix all of them

VERDICT  PACKAGE     VERSION    FIX         SEVERITY  ALERTS  IMPORTED  EXECUTED
shipped  certifi     2026.7.22  2026.10.19  critical  2       no        unknown
shipped  filelock    4.1.0      4.2.1       high      17      no        unknown
shipped  setuptools  84.0.0     84.1.0      low       1       no        unknown
```

Useful already: 20 alerts (OSV had one more certifi advisory than Dependabot) are 3
upgrades, and each comes with its "why is this here" chain.

Then pan's test suite under coverage, with site-packages included. Package-level, every
package "executed" - importing torch loads filelock and the setuptools startup shim. So
picard moved to function-level coverage, which said:

- **filelock**: only import-time registration ran; no lock was ever taken.
- **setuptools**: none of its files loaded; the hit was `_distutils_hack`, a shim setuptools
  installs that runs at every interpreter start.
- **certifi**: loaded, but `where()` never called.

Which produced this - a ranking exactly backwards:

```text
VERDICT      PACKAGE     VERSION    FIX         SEVERITY  ALERTS  IMPORTED  EXECUTED
reachable    filelock    4.1.0      4.2.1       high      17      no        yes
reachable    setuptools  84.0.0     84.1.0      low       1       no        yes
import-only  certifi     2026.7.22  2026.10.19  critical  2       no        yes
```

Two lessons:

1. **Test coverage describes the tests.** pan's tests stub every network call, so
   certifi's code never runs in them - but production uses it on every HTTPS request.
2. **Some vulnerabilities aren't code paths at all.** certifi's problem is *data*: the CA
   list it ships. Any TLS client that trusts that list is affected, whatever functions run.
   No amount of execution evidence settles that; reading the advisory does.

## Stage 3: reading the advisories

With `--assess` and a `picard.yaml` describing pan (Linux container, no shared host,
outbound TLS, tailnet-only exposure, packages installed at build time):

```text
VERDICT         PACKAGE     VERSION    FIX         SEVERITY  ALERTS  IMPORTED  EXECUTED
reachable       certifi     2026.7.22  2026.10.19  critical  2       no        yes
not-applicable  filelock    4.1.0      4.2.1       high      17      no        yes
not-applicable  setuptools  84.0.0     84.1.0      low       1       no        yes
```

- **certifi** - `affects: data`; outbound TLS via requests uses certifi's bundle by default,
  so an on-path attacker with a compromised key could intercept it. Reachable regardless of
  coverage.
- **filelock** - all 17 need a second local user able to create files in the lock directory;
  pan runs alone as one unprivileged user in its own container. OpenVEX:
  `vulnerable_code_cannot_be_controlled_by_adversary`.
- **setuptools** - depends on Windows drive-qualified path semantics; pan is Linux-only and
  installs at build time. OpenVEX: `vulnerable_code_not_present`.

First run 34 seconds for 20 assessments; re-runs about 5 seconds from cache.

## What it changed

The fix was the same either way - three upgrades - so in this instance picard wouldn't have
changed what got done. What it changes is the next time a fix *isn't* cheap: a major-version
upgrade that breaks things, or a package with no fix yet. Then "17 of these 20 don't apply
to us, here's why, recorded in VEX" is the difference between dropping everything and
scheduling it.

The pre-fix `uv.lock` is kept as `src/core/testdata/pan-uv.lock`, and pan's deployment
description as `example/picard.yaml`, so this case stays a regression test with known
right answers.
