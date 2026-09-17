# AGENTS.md — working rules for `bluesweep.sh`

Instructions for AI agents modifying this repo. Read this before editing `bluesweep.sh`.

`plan.md` is the design rationale. `README.md` is for users. This file is the set of
invariants that break **silently** if you violate them — every one below is here because it
already went wrong once.

## The one hard constraint

`bluesweep.sh` is **one file**, run on a possibly-compromised host that may have no network,
no package manager, and no working repos. Therefore:

- No companion files at runtime. No config files, no downloads, no `curl`, no network calls.
- **No temp files.** Signature data is fed to `awk` via leading `SIG` records or process
  substitution, never written to disk. A forensic tool that scribbles in `/tmp` is a
  forensic tool that destroys evidence.
- **Read-only.** Writes no files, changes no configuration, starts no services, kills no
  processes. The only permitted writes are the explicit destinations: `--out`, `--ir`,
  `--baseline`, `--remediate`, and the `--selftest sandbox` scratch dir. If you add a write
  anywhere else, you have broken the tool's core promise.
- `main "$@"` stays the **last line of the file**. The script gets pasted into terminals and
  piped from `cat`; a truncated transfer must do nothing rather than half-execute.

## Governing principle: assume the userland is lying

The host may be rooted. `ps`, `ls`, `netstat`, `find` may be trojaned. So:

- Read `/proc` and `/sys` **directly**. Never parse `ps` when `/proc` will do.
- Results sourced from a tool rather than the kernel get confidence `untrusted-source`.
- Several checks exist *only* to diff the kernel's view against the tool's view. Do not
  "simplify" these into a single source — the divergence **is** the detection.

## Invariants that bite

### `$ROOT` on every path literal

Write `"$ROOT/etc/passwd"`, never `/etc/passwd`. `/proc` access goes through `$PROCFS`.
This makes `--root /mnt/victim` work (offline triage of a mounted image, where a live
rootkit can't interfere) and makes the sandbox selftest possible.

**The subtle one:** home directories read out of `/etc/passwd` are absolute (`/root`), so
they need prefixing too — `h="$ROOT$h"`. Forgetting this made four checks silently scan the
*live* host while claiming to scan the image. It produced no error, just false negatives.

### POSIX awk only — target is mawk, not gawk

Ubuntu's default `awk` is **mawk**. Banned: `strtonum`, `gensub`, `asort`/`asorti`,
`ENDFILE`/`BEGINFILE`, `length(array)`, regex `RS`, `\s`, `\d`. Use `[ \t]` and `[0-9]`.
`--selftest lint` enforces this; verify with `gawk --posix`.

Hex conversion without `strtonum`: shell `printf '%d' 0x16`, or an
`index("0123456789ABCDEF", c)` table in awk.

Never pass signature data via `awk -v` — `-v` interprets backslash escapes and will silently
mangle any pattern containing `\`. Use leading `SIG` records.

### `/proc` parsing traps

- **`/proc/PID/stat`**: `comm` can contain spaces *and* parentheses. Strip through the
  **last** `") "` — `rest=${st##*") "}`. This is the single most common bug in homemade
  `/proc` scripts.
- **`/proc/N/status`** separates key from value with a **TAB**, not a space. `${v// /}` will
  not strip it; use `${v//[[:space:]]/}`. This one silently produced 132 false CRITs.
- **Thread TIDs are hidden from `/proc` readdir by design** while `/proc/TID` stays statable.
  "Statable but unlisted" is **normal**, not evidence. The real test is whether the TID's
  `Tgid` resolves to a visible process. Getting this wrong fires on every threaded process.
- **`ps` diffing races.** Snapshot `ps` *before* reading `/proc`, then re-verify every
  discrepancy (re-stat `/proc/N`, or re-ask `ps -p N`). Otherwise any process that starts or
  exits mid-scan looks like it's hiding.

### New OBS types must be added to `SNAPSHOT_PROG`

`SNAPSHOT_PROG` carries an explicit **allowlist** of observation types and silently drops
everything else (`} else next`). A type that is not listed never reaches a baseline and is
never diffed — the check looks like it works, while the drift detection that is the tool's
highest-value mode quietly ignores it. This already went wrong once: nineteen observation
types were added across three rounds of work and none of them diffed.

Two branches: stable-key/changing-value types (`FILE`, `OPNUSER`, `KERNELEXEC`, ...) go in
the first; types where one key legitimately has many lines (`CRON`, `AUTORUN`, `TCPWRAP`,
...) go in the second, which folds the value into the key. Then give the type a severity in
`DIFF_PROG`'s `drift()` — an added `KERNELEXEC` or `OPNUSER` is CRIT, not the MED default.

### Triage is the only place a finding may be lowered

`TRIAGE_PROG` is the single stage allowed to drop, downgrade or collapse a finding. Do not
add a second one, and do not "fix" a noisy check by quietly raising its threshold in the
renderer - the renderer is display, and JSON consumers would then disagree with the
terminal about what was reported.

Three rails, all of them load-bearing:

- **A `CRIT` at confidence `confirmed` can never be dropped**, and never falls more than one
  level, whatever `SIG_BENIGN` says. A suppression table an attacker can write to must not
  be able to blind the tool.
- **`--no-suppress` must keep working.** It disables the table and annotates each finding
  with the decision triage would have made. `--raw` bypasses the stage entirely.
- **Rollup spares CRIT and HIGH** (5x the ceiling, minimum 50). Summarising a critical hides
  the paths an operator has to act on.

Prefer fixing a false positive **in the check** over adding a `SIG_BENIGN` row. The table is
for conditions that are properties of how Linux works; a check that matches the wrong thing
is a bug in the check. The distinction is visible in the output: `triage_suppressed` going
up is a worse outcome than the finding never being raised.

`SIG_BENIGN` fields are separated by `|@|`, not a bare pipe, because the target and evidence
fields are regular expressions and alternation is the point of them. Splitting on `|` fed
awk an unbalanced group and killed the run mid-stream.

### Corroboration beats pattern-matching

When a check is about to report a file, ask whether something independent can explain it:

- `OBS PKGOWN` / `OBS PROVENANCE` - does a package own this path? (`col_pkgown` resolves the
  handful of paths findings actually point at, in `--quick` too; `col_prov` does running
  executables in `--full`.) Supported managers: `dpkg`, `rpm`, `portage`, `apk`.
- `PKG_TXN_EPOCHDAY` - did the package manager run on the day this file changed?
- Effective uid, not real uid, when asking "is this process privileged". Reading the first
  field of `/proc/PID/status`'s `Uid:` line calls every SUID-root helper an unprivileged
  process holding capabilities.
- A second signal before reporting a renamed process, a lone `NOPASSWD`, or a `memfd`
  mapping. Each of those alone fires on healthy hosts in the double digits.

**A correlation that cannot be made is never an exoneration.** If the package log is
unreadable, `pkg_txn=0` and the finding is reported. Fail toward saying something.

### A SKIP is never a pass

Every check declares a fallback chain ending in an explicit `skip` with a reason. A check
that cannot run must say so. A false negative that renders as clean is the single most
dangerous failure mode in a defensive tool — worse than no tool at all.

`run_check` enforces that every check emits *some* verdict; a silent check is reported as an
`ERROR` finding (a bug in bluesweep, not a clean host).

**Consequence for collector-style checks:** if a check only emits `OBS` records and its
findings are generated downstream in `RULES_PROG`, `run_check` cannot see those. Such a check
must emit an `ok()` stating what it inventoried ("47 cron entries inventoried"). Otherwise it
trips the ERROR contract on every clean host.

### Findings that can repeat need deduplication

Multiple accounts can share a home directory; the same file can be reached by several paths.
Dedup with a `local -A done=()` set keyed on the resolved path. The renderer also collapses
repeats of the same check id beyond `maxper` so one noisy condition (a nested chroot full of
SUID binaries) can't bury everything else — but that's display-only, not a substitute for
deduping at the source.

### Never flag the defender's own tools

`SIG_AGENT` lists Wazuh, osquery, auditd, Falco, Velociraptor and friends. These are the
defender's telemetry and are frequently the first thing an attacker kills. Never report them
as suspicious, never suggest removing them, and treat a previously-running agent that has
stopped as CRIT drift.

### Remediation output

`--remediate` emits a **commented review script that is never executed**. Two rules:
every suggested fix is tagged with which listening services it could disrupt, and the
generator never emits a subnet-wide block — single IPs only.

## Architecture

Three stages, three processes:

```
{ emit_sig_tables; [diff baseline + MARK]; collect_all; }   # shell: OBS/FIND/SKIP records
  | awk "$RULES_PROG"      # OBS -> FIND via rules; carries SIG tables
  | awk "$CONFIG_RULES"    # service/application configuration grammars
  | awk "$TRIAGE_PROG"     # suppression, corroboration, rollup, ATT&CK
  | awk "$RENDER_PROG"     # terminal | NDJSON | exit code
```

`SNAPSHOT_PROG` passes `SIG` records through when `keep=1` (the diff path only), because the
triage stage runs downstream of the diff and needs the tables. A written baseline still
contains no `SIG` records.

Because collectors already emit `OBS`, **the baseline *is* the collector output** — one
collection path, so a snapshot can never drift from what's checked. Diff prepends the old
stream plus a `MARK` sentinel and compares in awk (no `sort`, no `diff`).

Record grammar, TAB-delimited, first field is the tag:

```
SIG  <table> <value>
OBS  <type> <key> <value>
FIND <check_id> <sev> <cat> <conf> <title> <target> <evidence> <fix_id>
SKIP <check_id> <reason>
OK   <check_id> <note>
META <k> <v>
MARK
```

Checks that are pattern matches over `OBS` belong in `RULES_PROG`. Checks with procedural
logic emit `FIND` from shell and pass through awk untouched. Hybrid on purpose — do not try
to write the whole tool in awk.

**Severity and confidence are separate axes.** `CRIT/HIGH/MED/LOW/INFO` is impact;
`confirmed/likely/possible/untrusted-source` is certainty. A CRIT/possible renders
differently from a CRIT/confirmed. Collapsing them turns the tool into a false-positive
firehose.

File layout: usage → options → **SIGNATURE BLOCK (fenced, editable)** → primitives →
capability probe → emitters → collectors → checks → awk programs → bounded filesystem
collectors and export modes → driver (registry, `collect_all`, `main`) → self-tests →
`main "$@"`. Everything the driver calls is defined above it; checks do not live below the
self-tests. Keep it that way - it drifted once and the registry ended up naming functions a
reader had not met yet.

## Adding a check

1. Write `chk_<name>()` in the checks section. Guard every external tool behind the
   `CAP_*` flags set by `probe_toolbox` — probe **behavior, not binary presence** (busybox
   `stat` exists but behaves differently; a trojaned `ps` exists and lies).
2. Every path gets `$ROOT`. Every dead end gets `skip`. Every clean pass gets `ok`.
3. Register it in `CHECKS_QUICK`.
4. Add a detector case to `--selftest sandbox` (plant a benign IOC) or `--selftest unit`
   (fixture through a pure parse function). If it can't be tested either way, say so in the
   environment-gated list rather than omitting it quietly.
5. Confirm the clean-sandbox run still reports zero findings. The false-positive regression
   matters as much as the detection.

## Performance discipline

Quick mode must perform **no full-filesystem walk** — that's architectural, not a tuning
goal. Full mode uses one `find` pass whose predicates filter in C, streamed to awk, capped
per category so a hostile directory can't exhaust memory.

Keep forks down: `case` not `grep`, `${v#...}` not `sed`, `read -r x < file` not `$(cat f)`,
one `awk` over a directory rather than one `grep` per file. Resolve socket inode → PID with a
single `ls -l /proc/*/fd/` pass, never one `readlink` per fd.

Never traverse NFS/CIFS/FUSE — a dead server hangs the walk forever.

## Verify before claiming done

**`PATH` is hard-set near the top of the script** (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`), so
a `PATH=/tmp/fb:$PATH ./bluesweep.sh` harness is silently ignored and proves nothing — the
run uses the system tool and passes. To test against a fake `awk`, `dpkg-query` or `rpm`,
rewrite that line in a scratch copy, and have the fake log its invocations so you can
confirm it was actually reached.

```sh
bash -n bluesweep.sh                      # syntax
./bluesweep.sh --selftest lint            # banned constructs, gawk-isms
./bluesweep.sh --selftest unit            # pure-function fixtures
./bluesweep.sh --selftest sandbox         # planted IOCs + clean-sandbox regression
shellcheck -s bash bluesweep.sh           # triage warnings, don't blanket-disable

# mawk compatibility (the failure that passes locally and breaks on Ubuntu)
printf '#!/bin/sh\nexec gawk --posix "$@"\n' > /tmp/fb/awk && chmod +x /tmp/fb/awk
sed 's|^PATH=/usr/sbin.*|PATH=/tmp/fb:&|' bluesweep.sh > /tmp/posix.sh
bash /tmp/posix.sh --selftest unit && bash /tmp/posix.sh --selftest sandbox

# no ERROR findings == every check yields a verdict
./bluesweep.sh --raw | awk -F'\t' '$1=="FIND" && $3=="ERROR"{print $2}'

# read-only proof
strace -f -e trace=openat,unlink,write ./bluesweep.sh --quick 2>&1 | grep -E 'O_WRONLY|O_CREAT'
```

Also worth running on a real distro matrix (`debian:12`, `ubuntu:22.04`, `ubuntu:24.04`,
`rockylinux:9`) with gawk removed, and unprivileged, which must complete and print how many
checks were degraded.

## Honesty rules

These are product requirements, not style preferences:

- The rootkit section must state that it detects *inconsistencies*, and that a rootkit which
  hooks `getdents`, `tcp4_seq_show` and the module list coherently defeats all of it. Clean
  output means "no sloppy rootkit found", never "clean host".
- "Modifies nothing" is precisely: writes no files, changes no config, starts no services,
  kills no processes. Reading still bumps atime on `relatime` mounts and the run lands in
  auditd and `wtmp`. Claim the accurate thing.
- Unprivileged runs lose roughly 40% of coverage (`/etc/shadow`, other users' `/proc/*/fd`,
  kernel symbols). Print that prominently rather than returning a shorter, cheerier report.
- Don't add capabilities to the README that the code doesn't have. If a module is partial,
  say which parts.

## Out of scope — don't add these

- **Windows.** No PowerShell counterpart; documented gap.
- **BSD/OPNsense, running natively.** The appliance ships no bash and mounts no procfs, and
  with no `/proc` the divergence checks — the point of the tool — have nothing to diff
  against. Do not attempt a POSIX-sh rewrite of 400+ bash constructs.

  **Offline `--root` against a copied appliance tree IS supported** and is the only
  sanctioned form: it runs on a Linux host, so bash and GNU tooling are the scanner's, not
  the target's. `TARGET_OS` is set to `freebsd` from the tree layout (`/conf/config.xml`, or
  `master.passwd` beside `/usr/local/etc/rc.d`), never from `uname`. FreeBSD paths are added
  to the existing path lists unconditionally rather than branched on — they simply do not
  exist on a Linux target. Everything `/proc`-derived still SKIPs, and must keep saying so.
- **Resident scanning, signature auto-update, quarantine.** This is an audit tool, not an
  antivirus; several competition rulesets ban AV outright.
- **YARA, hash reputation, any network lookup.** Signature coverage is deliberately shallow
  and offline.
