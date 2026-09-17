# bluesweep 0.3.0 validation record

Validation was run on 2026-09-17 against the working tree. The competition packet
used for the scope review was `Space RVB-1.1.pdf`, version 1.1.

## Completed

- `bash -n bluesweep.sh`
- `bash bluesweep.sh --selftest lint` — zero lint failures
- `bash bluesweep.sh --selftest unit` — all unit fixtures passed
- `bash bluesweep.sh --selftest sandbox` — all sandbox fixtures passed
- `python3 tests/test_integration.py` — 20 tests passed as the normal user
- `bash bluesweep.sh --selftest unit` grew to 97 assertions and `--selftest sandbox` to
  44, covering the triage rails, the credential-scanner fixtures, sudo/doas
  classification, capability decoding, process lineage and authentication correlation
- `unshare -Ur python3 tests/test_integration.py` — 19 tests passed in a UID-mapped
  root namespace
- The same 20 integration tests passed with a Debian mawk 1.3.4 wrapper; the wrapper
  logged 553 awk invocations, confirming that the compatibility run reached mawk.
- ShellCheck 0.11.0 reported no errors. The existing script has informational and
  warning findings that are retained for later cleanup; none were introduced as a
  syntax failure.
- A disposable-fixture syscall trace found no unexpected filesystem writes during a
  normal scan. Standalone `--remediate` wrote only its explicitly requested review
  file and created no scratch directory.
- A real rootless quick scan completed in 36 seconds with no `ERROR` findings. It
  reported 0 CRIT, 1 HIGH, 18 MED, 14 LOW and 128 INFO findings, plus 22 SKIPs, and
  exited 3 because skipped checks make the result incomplete.
- The stat capability probe was exercised against the image root rather than
  `/etc/hostname`, so minimal offline trees without a hostname still retain
  ownership and permission checks.

## False-positive work (same host, after the triage stage was added)

The reference scan above was the starting point for the noise work, so the same host
is the before/after measurement. Reported findings fell from **179 to 55**, measured at the
default `--rollup 10`.

| Check | Before | After | Where the reduction came from |
|---|---:|---:|---|
| MAP001 executable memfd mapping | 60 | 0 | deduplicated per named region instead of per JIT allocation, then the named-JIT triage rule |
| NET022 outbound peer | 49 | 5 | summarised per owning process and destination port instead of per connection |
| NET001 listening socket | 15 | 11 | inventory, rolled up past the tenth |
| SEC011 stored credential | 14 | 5 | assignment/keyword/value tests in the scanner; the 5 remaining are real |
| INT004 recently modified | 11 | 9 | volatile-file rules and package-transaction correlation. The correlation does not help on this host: `/var/log/emerge.log` is unreadable to a non-root user, so `pkg_txn=0` and the findings stand. An unmakeable correlation is never an exoneration |
| SUI012 unknown SUID | 5 | 5 | unchanged here: no `dpkg`/`rpm`/`qfile` ownership answer on this host. On a Debian or RHEL host these demote to LOW and name the package |
| PER003 shell startup hook | 2 | 0 | prompt-integration hooks are what every modern terminal installs |
| PAM002 `pam_permit` | 1 HIGH | 1 LOW | severity now depends on whether the stack is a login path |
| PRIV001 privileged group | 2 | 1 | distribution-shipped system members are inventoried, not reported |
| CTR004 process capabilities | 3 | 2 | the test uses the effective uid, so SUID-root helpers are no longer called unprivileged; masks are decoded to names |

Only **5** of the total reduction came from the `SIG_BENIGN` suppression table
(`triage_dropped_by_check: MAP001=1 PER003=2 INT004=2`), with 1 demotion and 1 rollup. The
rest came from fixing the checks, which is the intended ratio and is printed on every run.

The suppression rails were verified directly: a `CRIT`/`confirmed` finding with a `drop`
rule aimed at it demotes to `HIGH` instead of disappearing; `--no-suppress` restores every
dropped finding with the decision annotated in its evidence; `--raw` bypasses the stage
entirely. All three are unit tests, not one-off checks.

## Not completed here

- Host-root coverage could not be exercised: `sudo` requires authentication on this
  host. UID 0 in an unshare namespace is useful for code-path testing but cannot read
  host-root-only evidence.
- No live scored service was started or probed. Distcc, VNC, BIND, MySQL and Modbus
  checks use passive process/configuration observations and do not send requests.
- The full Debian, Ubuntu, Rocky and Fedora matrix, real kernel-rootkit scenarios,
  package verification with a target package database, and a host with actual mawk
  installed remain environment-gated.
- The package-ownership corroboration path (`dpkg`, `rpm`, `portage`, `apk`) was exercised
  through `prov_absorb` fixtures and through the triage stage, but not end-to-end against a
  real Debian or RHEL database — this host has neither, and its Portage `qfile` was not
  present either. The demotion logic is unit-tested; the manager output parsing for
  `portage` and `apk` is fixture-tested only.
- ShellCheck was not available in this environment for the post-refactor tree, so the
  earlier clean result was not re-confirmed after the reorganisation.

## Reproduce

```sh
bash -n bluesweep.sh
bash bluesweep.sh --selftest lint
bash bluesweep.sh --selftest unit
bash bluesweep.sh --selftest sandbox
python3 tests/test_integration.py
POSIXLY_CORRECT=1 python3 tests/test_integration.py

# false-positive regression: compare against the count recorded above
bash bluesweep.sh --quick --json - | grep -c '"record":"FIND"'
bash bluesweep.sh --quick --no-suppress   # what triage decided, and why
bash bluesweep.sh --explain SEC011        # one check, its rules and its ATT&CK id
```

The scanner has no runtime network dependency. Network access was used only to inspect
the competition source material and primary service documentation and to obtain
development-only validation binaries in `/tmp`; those files are not part of the tool.
