# bluesweep.sh — single-file blue team host triage

## Context

`linpeas.sh` gives attackers a drop-and-run enumeration of a Linux host. Defenders have no
equivalent: blue-team tooling is fragmented across Lynis (config audit), Loki/rkhunter (IOC
scan), UAC (artifact collection), AIDE (integrity baseline) and pspy (process watch). Each is
a separate install, several need a compiler or a working package manager, and in a competition
you frequently have neither network nor repos on the box you were just handed.

`bluesweep.sh` collapses those into one file you `scp` onto a possibly-already-compromised
host and run immediately. It answers the defender's first question — *what did the attacker
already do to this box, and what will let them back in?* — and then, via baseline/diff mode,
the second and harder one: *what changed in the last fifteen minutes?*

It replaces `discovery.sh` in blue-scripts, which today runs two `find -name` greps for the
literal strings `beacon` and `red-team`. It will live in its own repo.

**Driving use case** (from `~/Downloads/Space RVB-1.1.pdf`, PSU CCSO Red vs Blue 2026): a
six-hour defense of an Artemis-themed ground station, 30-minute hardening window before red
team goes live, scoring 50% uptime / 15% incident response / 15% injects / 15% C-suite. The
tool must be generic, but every Linux-reachable element of that packet must be covered by some
generic capability. See *Competition coverage* below for the traceability check.

## Decisions locked

| Decision | Choice | Reason |
|---|---|---|
| Targets | Debian 12, Ubuntu 22.04/24.04, RHEL/Rocky/Fedora, SUSE | Every Linux host in the packet, plus normal IR use |
| Shell | `#!/usr/bin/env bash`, bash 4+ | Present on all targets. Chosen over strict POSIX `sh`: dash reach buys nothing here and costs a banned-construct discipline across ~3000 lines |
| **awk** | **POSIX awk only — mawk-safe** | Ubuntu's default `awk` is **mawk**: no `strtonum`, no `gensub`, no `asort`, no `ENDFILE`. Verified a mawk-compatible hex→IP routine works. This is the single easiest way to ship something that passes on a dev box and fails on Ubuntu |
| `find` | GNU findutils; `-printf`, `-newermt`, `-xdev` | Guaranteed on targets. Probe `-printf` anyway and `SKIP` loudly if absent |
| Deps | None. `ss`/`netstat`/`lsof`/`rpm`/`dpkg`/`getcap`/`lsattr`/`openssl` optional | Every check declares a fallback chain ending in an explicit `SKIP` |
| Side effects | Writes no files, changes no config, starts/kills nothing | Two documented exceptions: `--baseline FILE` and `--selftest sandbox` |
| Privilege | Root preferred; unprivileged degrades **loudly** | ~40% of value is root-gated; the header states how many checks were degraded |
| Windows | **Out of scope**, documented | Columbia/Odyssey/Sputnik need separate tooling. Stated plainly in the README rather than implied |
| OPNsense router | **Out of scope**, documented | FreeBSD; no `/proc`, so the rootkit-divergence core doesn't port. Audit via its own UI |
| Name | `bluesweep.sh`, own repo | |

**Governing principle — assume the userland is lying.** On a compromised host `ps`, `ls`,
`netstat` and `find` may be trojaned. Every check that *can* read `/proc` or `/sys` directly
does so; several checks exist purely to diff the kernel's view against the userland tool's
view. Any result sourced from a tool rather than `/proc` is tagged `untrusted-source` in the
record so the renderer can mark it. This inversion — `/proc` first, tools second — is the
whole blue-team point.

---

## Architecture

### The spine: a streaming record pipeline

The most important decision is the data flow, not the language. Three stages, three processes:

```bash
{ emit_sig_tables                                  # signature data as leading records
  [[ -n $DIFF_FILE ]] && { cat "$DIFF_FILE"; printf 'MARK\n'; }
  collect_all                                      # collectors -> OBS records
} | awk "$RULES_PROG" \
  | awk "$RENDER_PROG"                             # color | NDJSON | IR | exit code
```

Consequences, all good:

1. **No findings accumulator.** Findings stream out; nothing accumulates in shell.
2. **Baseline/diff is nearly free.** `--baseline` is `collect_all > FILE`. `--diff` is the same
   stream with the old one prepended and a `MARK` sentinel. One collection code path forever,
   so the snapshot can never drift from what's checked.
3. **JSON escaping, dedup, severity tally and exit code all live in awk**, where associative
   arrays exist.

Record grammar, TAB-delimited, first field is the type tag:

```
SIG   <table> <value>                                  # signature tables, injected first
OBS   <type> <key> <value>                             # observation; the snapshot substrate
FIND  <check_id> <sev> <cat> <conf> <title> <target> <evidence> <fix_id>
SKIP  <check_id> <reason>
OK    <check_id> <note>
META  <k> <v>
MARK                                                   # baseline/current separator
```

Checks that are pattern matches over `OBS` become awk rules; checks with gnarly procedural
logic emit `FIND` directly from shell and pass through awk untouched. Hybrid deliberately —
do not write 3000 lines of awk.

### Two conventions to adopt in hour one

- **Every path literal is `"$ROOT/etc/passwd"`, never `/etc/passwd`**; `ROOT` defaults to
  empty, and `/proc` collectors use `PROCFS="$ROOT/proc"`. Costs nothing now, and buys
  `--root /mnt/victim` (offline triage of a mounted disk image — the best forensic feature
  available for near-zero cost) plus a testable selftest. Impossible to retrofit later.
- **`main "$@"` is the last line of the file.** It will get pasted into terminals and piped
  from `cat`; a truncated transfer must do nothing rather than half-execute.

### Section order inside the file

```
 1. shebang, set -u, IFS, PATH=/usr/sbin:/usr/bin:/sbin:/bin, LC_ALL=C, umask 077, traps
 2. VERSION, usage() heredoc
 3. constants: severity map, colors, separators, timeouts, ROOT="", budgets
 4. ===== SIGNATURE BLOCK ===== (fenced, editable)
 5. primitives: have, hex2ip, readlink_x, cat_safe, run_bounded, now_ms, warn/die
 6. probe_toolbox + probe_env (container, virt, distro, SELinux/AppArmor)
 7. emitters: emit_raw, finding, skip, ok, obs, meta
 8. collectors: col_proc col_net col_fs col_cron col_systemd col_users col_ssh
                col_mod col_pkg col_sysctl col_logs col_services
 9. checks, grouped by module (M01..M14)
10. awk programs as quoted variables: RULES_PROG WEBSHELL_PROG RENDER_PROG DIFF_PROG
11. baseline/diff driver
12. IR report builder, evidence dump, remediation emitter
13. selftest (unit | sandbox | lint)
14. arg parsing, check registry, main(), then `main "$@"`
```

---

## Capability probing and the anti-silent-pass contract

Probe **behavior, not binary presence** — busybox `stat` exists but behaves differently; a
trojaned `ps` exists and lies.

```bash
probe_stat() { case "$(stat -c '%s' "$ROOT/etc/hostname" 2>/dev/null)" in
                 ''|*[!0-9]*) CAP_STAT=0 ;; *) CAP_STAT=1 ;; esac; }
```

Every check is `chk_<id>` plus a registry entry. The runner enforces that a check **must**
emit something; a check that returns silently is itself reported as a bug:

```bash
run_check() {
  local _id=$1; _EMITTED=0
  "$_id"; local _rc=$?
  (( _EMITTED == 0 )) && emit_raw "FIND\t$_id\tERROR\tinternal\tconfirmed\tCheck produced no verdict\t-\trc=$_rc\t-"
}
finding() { _EMITTED=1; emit_raw "FIND\t$*"; }
skip()    { _EMITTED=1; emit_raw "SKIP\t$1\t$2"; }
```

Fallback chains are declared inline and fall off the end into `skip`, never into nothing:

```bash
chk_net_listen() {
  [[ -r $PROCFS/net/tcp ]] && { net_listen_proc; return; }
  have ss      && { net_listen_ss;      mark_untrusted ss;      return; }
  have netstat && { net_listen_netstat; mark_untrusted netstat; return; }
  skip NET001 "no /proc/net, no ss, no netstat — listening sockets UNKNOWN"
}
```

`SKIP` is a first-class citizen rendered prominently in the summary. **A run with 40 SKIPs is
not a clean run**, and the tool must never let a false negative read as a pass.

---

## Anti-tamper primitives

**Processes without `ps`.** Walk `$PROCFS/[0-9]*` directly. Parse `/proc/PID/stat` with
`${st##*") "}` to strip through the *last* `") "` — `comm` can contain both spaces and
parens, and getting this wrong is the most common bug in homemade `/proc` scripts.

Hidden-PID detection uses four independent probes, ranked by the rootkit class each defeats:

| Probe | Defeats | Cost |
|---|---|---|
| `/proc` listing vs `ps -e` PID sets | trojaned `ps`, LD_PRELOAD readdir hook | free |
| PPIDs referenced by visible procs but absent from `/proc` | `/proc` readdir hook | free |
| `/proc/*/task/*` TIDs with no matching `/proc/N` | thread-level hiding | free |
| `[[ -d /proc/N ]]` direct stat for every N ≤ `pid_max` not in the listing | getdents-hooking LKMs (Diamorphine class) | ~0.5s, full mode only |

**Sockets without `ss`/`netstat`/`lsof`.** Parse `$PROCFS/net/{tcp,tcp6,udp,udp6}`; `st=0A` is
LISTEN, inode is field 10. Hex→dotted-quad in pure bash with no forks (`printf` accepts `0x`
operands):

```bash
hex2ip() {  # 0100007F -> 127.0.0.1 (little-endian)
  local h=$1
  printf '%d.%d.%d.%d' "0x${h:6:2}" "0x${h:4:2}" "0x${h:2:2}" "0x${h:0:2}"
}
```

Map socket inode → owning PID in **one** fork (the naive version is one `readlink` per fd,
i.e. thousands):

```bash
ls -l /proc/[0-9]*/fd/ 2>/dev/null | awk '
  /^\/proc\/[0-9]+\/fd\/?:/ { split($0,a,"/"); pid=a[3]; next }
  / -> socket:\[/ { i=index($0,"socket:["); ino=substr($0,i+8); sub(/\].*/,"",ino)
                    print "OBS\tSOCKFD\t" ino "\t" pid }'
```

**The highest-value detector in the whole tool:** a socket inode present in `/proc/*/fd` with
**no corresponding row in `/proc/net/*`** means `tcp4_seq_show` is hooked. Most LKM rootkits
hide the `/proc/net/tcp` row and forget the fd link. That single cross-check is worth more
than the rest of the network section combined.

Unprivileged runs see only their own `/proc/*/fd` — such a check must report
`owner=unknown (insufficient privilege)`, never `owner=none`. Different strings, different
meanings.

**Kernel modules without `lsmod`** (`lsmod` is just formatted `/proc/modules`): read
`/proc/modules` directly, then cross-check against `/sys/module/*` both ways; decode all 18
bits of `/proc/sys/kernel/tainted` (bits `F` forced-load, `E` unsigned, `O` out-of-tree,
`R` forced-rmmod are the interesting ones); enumerate ftrace hooks via
`/sys/kernel/{tracing,debug/tracing}/enabled_functions` — any entry on a box with no tracing
tooling is HIGH, and modern khook/ftrace rootkits show up here while hiding everywhere else;
scan `/proc/kallsyms` for known rootkit symbol prefixes; check `/etc/modprobe.d/*` for
`install X /bin/sh -c ...`.

---

## Single-pass filesystem walk

Roots come from `/proc/mounts` filtered to real local filesystems. **Never traverse NFS/CIFS/
FUSE** — a dead server hangs the walk forever, which is a real competition failure mode — and
never `/proc /sys /dev /run /var/lib/docker /snap`.

One traversal, filtering done by `find`'s C code so the shell only ever sees the candidate set
(typically 500–20,000 lines, not millions — that is the memory bound):

```bash
find "${ROOTS[@]}" -xdev \( $PRUNE \) -prune -o \
  \(    -perm -4000 -o -perm -2000 \
     -o \( -perm -0002 \( -type f -o \( -type d ! -perm -1000 \) \) \) \
     -o -nouser -o -nogroup \
     -o -mtime -"$RECENT_DAYS" \
     -o -name "*${NL}*" \) \
  -printf 'W\t%m\t%U\t%G\t%s\t%T@\t%y\t%p\n' 2>/dev/null | classify_walk
```

`classify_walk` is one streaming awk pass tagging each row into buckets, capped at
`MAX_PER_CAT=200` with an explicit `truncated=1` flag so a hostile `/tmp` holding 400k
world-writable files can't OOM the run. A path containing a control character is *itself* a
finding — which is why `-name "*${NL}*"` is in the filter, converting a line-parsing weakness
into a detector.

**`--quick` performs no full-filesystem walk at all.** This is an architectural rule, not a
tuning goal: a cold-cache `find /` on a 40GB VM is 30–120s by itself. Quick mode is `/proc` +
config files + a fixed directory list.

**Budgets, enforced by a pure-bash watchdog** (`timeout(1)` may be absent): 150s walk, 60s
webshell scan, 60s hashing, 30s the rest. A stage that blows its budget emits
`SKIP ... budget exceeded — results INCOMPLETE` and the run exits 3. Degrade loudly.

**Fork budget**, measured in selftest: quick ≤ 1500 forks, full ≤ 6000. At 3000 lines you will
otherwise accidentally write a 20,000-fork script that takes 90s doing nothing. Practical
rules: `case` not `grep`; `${v#...}` not `sed`; `read -r x < file` not `$(cat file)`; one awk
over a directory, never one grep per file.

---

## Check modules

| ID | Module | Covers |
|---|---|---|
| M01 | baseline | OS/kernel/uptime, virt + **container detection** (reinterprets nearly every other finding), mounts, disk |
| M02 | accounts | UID 0 duplicates, empty/absent password fields, weak hash types, unexpected shells, sudoers `NOPASSWD`/wildcards, `.rhosts`/`.netrc`/`hosts.equiv`, recent logins, btmp failures, **duplicate password hashes across users**, optional `--weak-pass` candidate test (see below) |
| M03 | persistence | cron (`/etc/crontab`, `cron.d`, `cron.{hourly,daily,weekly,monthly}`, user spools), `at`; systemd units + **timers** + user units + generators + `ExecStart` scrutiny; sysvinit `rc*.d`/`inittab`; shell rc files (`/etc/profile.d`, `~/.bashrc`, `~/.zshrc`, `~/.bash_logout`); `update-motd.d`; xinetd/inetd; udev `RUN+=`; apt/dnf hooks; `~/.config/autostart` |
| M04 | rootkit | `/etc/ld.so.preload` + live `LD_PRELOAD`; the four hidden-PID probes; socket-fd vs `/proc/net` cross-check; `/proc/modules` vs `/sys/module`; taint bits; ftrace hooks; kallsyms; deleted-but-running exes; bind-mounts shadowing system dirs (`/proc/self/mountinfo`); hidden entries in `/dev`, `/dev/shm`; embedded rootkit path list |
| M05 | network | Listeners with owning binary; established outbound to non-RFC1918; promiscuous ifaces (`/sys/class/net/*/flags` bit `0x100`); AF_PACKET sniffers (`/proc/net/packet`); iptables/nftables incl. NAT+REDIRECT; `/etc/hosts`, `resolv.conf`, `nsswitch.conf` tampering |
| M06 | ssh | `authorized_keys` everywhere incl. non-default `AuthorizedKeysFile` and `command=` prefixes; `sshd_config` `PermitRootLogin`/`PasswordAuthentication`/**`ForceCommand`**/**`AuthorizedKeysCommand`**/`PermitUserEnvironment`; `~/.ssh/rc`, `/etc/ssh/sshrc`; host key mtimes |
| M07 | pam-nss | `/etc/pam.d/*` modules resolving outside `/lib*/security`, `pam_exec` lines, unknown `.so` |
| M08 | integrity | SUID/SGID vs embedded allowlist; world-writable files and dirs missing sticky; **immutable `+i` files** (`chattr` persistence); recent mtime in system dirs; orphans; `rpm -Va`/`dpkg --verify`/`debsums` when present |
| M09 | procs | Execution from `/tmp`, `/dev/shm`, `/var/tmp`, `/run/user`; reverse-shell cmdlines (`nc -e`, `bash -i >&`, `/dev/tcp/`, base64-piped-to-shell); kthread masquerade (`[kworker]` not descended from kthreadd) |
| M10 | logs | Zeroed/truncated `wtmp`/`btmp`/`lastlog`; history symlinked to `/dev/null` or size 0; `/var/log` recent-mtime-but-tiny; logrotate config; auditd present/running/rules |
| M11 | webshell | Webroot discovery from nginx/apache config (not just `/var/www`), then **weighted** scoring — see below |
| M12 | hardening | SELinux/AppArmor, firewall present+enabled, sysctl posture (ASLR, `kptr_restrict`, `dmesg_restrict`, `rp_filter`), world-readable secrets, NFS exports, Samba shares |
| M13 | **services** | Per-service hardening for the daemons that actually get scored — see below |
| M14 | **agents** | Security-agent allowlist: detect and *protect* Wazuh/osquery/auditd/Falco/Velociraptor. Never flag them, verify they're running and enrolled, and emit CRIT if one that was present in the baseline has stopped — attackers kill your telemetry first |

### M13 service modules

Driven by what real scored environments actually run. **Never assume default ports** — services
are often relocated; bind to what's actually listening.

| Service | Checks |
|---|---|
| **distcc** | `distccd` running/listening at all (it's a documented RCE vector), missing `--allow`, listening on non-loopback, running as root |
| **DNS / bind** | `named.conf` recursion open to the world, `allow-transfer` unset (AXFR), dynamic-update grants, zone-file mtime drift, `also-notify` to unexpected hosts |
| **SMTP / postfix / exim** | Open relay (`mynetworks`, `smtpd_recipient_restrictions`), **`/etc/aliases` entries piping to a command**, **`~/.forward` files** — both are classic and very-much-still-used persistence, and are missed by every generic scanner |
| **FTP / vsftpd / proftpd** | Anonymous login, anonymous *upload*, `chroot_local_user` off, writable upload dir under a webroot (upload-to-RCE chain) |
| **MySQL / MariaDB** | Users with host `%`, users with no password, `FILE` privilege grants, **UDF persistence** (`.so` in the plugin dir, `func` table entries), `secure_file_priv` empty, writable plugin dir, `init_file`/`init_connect` set |
| **VNC** | Unauthenticated servers, `~/.vnc/passwd` perms, `x11vnc` invoked with `-nopw`, VNC listening on non-loopback |
| **HTTP / Apache / nginx / PHP** | `.htaccess` tampering, PHP `auto_prepend_file`/`auto_append_file`, `disable_functions` emptied, writable webroot, alias/proxy_pass to a local port, `mod_cgi` on an upload dir |
| **Modbus / ICS** | Port-502-class listeners and who owns them; whether reachable from outside the intended HMI host; flagged INFO-only since blocking it breaks the process |

### M11 weighted webshell scoring

Raw regex matching over a WordPress tree produces hundreds of false positives; weighted
scoring produces ~3. Patterns carry weights; a file is reported at `score ≥ 10`, tiered
`≥20` CRIT/confirmed, `10–19` HIGH/likely, `5–9` MED/possible.

Performance discipline (this is what blows the 5-minute budget if done carelessly): one awk
invocation over all candidates via `find -exec awk ... {} +`, never one per file; a cheap
single-regex `TRIG` prefilter before the weighted loop so 90%+ of lines exit early; `-size
-2M`; an extension allowlist **plus** a content check on odd extensions (`<?php` in the first
3 lines of a `.ico` or `.jpg` is the classic upload-filter bypass).

### M02 optional weak-password check

`--weak-pass` tests a small embedded candidate list (plus any file given to `--weak-pass-file`)
against each `/etc/shadow` entry using that entry's own salt. Needs root and one of
`openssl passwd` / `mkpasswd` / `python3 crypt`; `SKIP`s explicitly otherwise. This is
self-audit of hosts you are defending, and it is the fastest way to discover that twenty
accounts still share a documented default password. Off by default.

---

## Findings model and output

**Severity:** `CRIT HIGH MED LOW INFO OK SKIP ERROR`, with the tiering rule written as a
comment block beside the constants so it stays consistent:

- **CRIT** — evidence of active compromise (hidden PID, socket missing from `/proc/net`,
  `ld.so.preload` set, SUID shell, webshell scoring ≥20, reverse-shell cmdline).
- **HIGH** — a viable persistence/privesc mechanism that shouldn't exist (unknown SUID,
  `AuthorizedKeysCommand` to a non-standard path, cron pulling from the internet, unit in `/tmp`).
- **MED** — weak posture, plausibly legitimate.
- **LOW/INFO** — inventory and hardening notes.

**Confidence is a separate axis:** `confirmed | likely | possible | untrusted-source`. This is
what keeps a blue-team tool from being a false-positive firehose — CRIT/possible renders
differently from CRIT/confirmed.

**Exit codes**, chosen not to collide with the shell's `1/2/126/127`:

| Code | Meaning |
|---|---|
| 0 | nothing above INFO |
| 10 / 20 / 30 / 40 | worst finding was LOW / MED / HIGH / CRIT |
| 2 | usage error |
| 3 | ran but incomplete (budget exceeded, or critical SKIPs) |
| 4 | selftest failure |

The code comes from the renderer's `exit`, which is the last pipeline stage, so `$?` is
correct with no bash-only `PIPESTATUS`. `--exit-zero` for pipelines.

**Output modes:**

- **Terminal** (default): severity-ordered, colored. Gate on `[[ -t 1 ]]`, `NO_COLOR`,
  `TERM != dumb`, `--no-color`.
- **`--json FILE`**: NDJSON, one object per line — streamable and `grep`-able, no
  trailing-comma dance. Escaping lives in one awk function, not in shell quoting.
- **`--out DIR`**: UAC-style evidence dump, everything under `DIR` with a manifest and hashes.
- **`--remediate FILE`**: commented shell script of suggested fixes, **never executed**. Two
  hard rules: every fix is tagged with which listening services it could disrupt, and anything
  that could drop a scored service is marked loudly; and **the generator never emits a
  subnet-wide block**, only single-IP rules (competition rules commonly forbid subnet blocks,
  and it's better practice anyway).
- **`--hunt REGEX`**: generic content hunt across the walk candidate set, reported as INFO.
  Covers flag-hunting (`ARTEMIS\{`), custom IOC strings, or a known attacker marker.

### `--ir` — incident response report mode

IR is 15% of the driving competition's score and the packet names exactly what counts as
proof. `--ir DIR` structures output around those four categories:

| Proof category | Source |
|---|---|
| Processes they ran | full `/proc` process table w/ exe, cmdline, ppid, start time; bash/zsh history with timestamps; `/var/log/auth.log` sudo and `su` lines; auditd execve records when available |
| IP addresses of intruders | established + recent sockets w/ owning binary; `auth.log`/`secure` accepted+failed SSH with source IPs; `wtmp`/`btmp` origins; webserver access logs correlated to the webshell paths M11 found |
| User accounts they used | account diff vs baseline, new/modified `authorized_keys`, sudoers changes, `lastlog`, password-change timestamps from `/etc/shadow` field 3 |
| Active sessions hijacked | `utmp` live sessions, `/proc/*/` sessions w/ controlling tty, orphaned screen/tmux sockets, SSH `ControlMaster` sockets |

Emits a Markdown skeleton with a UTC timeline, per-item evidence blocks, and SHA-256 of every
collected artifact, ready to convert to the PDF such submissions require. Timeline correlation
is what turns a pile of artifacts into a report a judge will accept.

---

## Baseline / diff

Because collectors already emit `OBS`, **the baseline *is* the collector output** — no second
implementation and no drift between what's checked and what's snapshotted.

```bash
./bluesweep.sh --baseline /media/usb/r1.base     # hardening window, before attackers go live
./bluesweep.sh --diff     /media/usb/r1.base     # every 15 minutes after
```

What goes in: `FILE` (mode:uid:gid:size:mtime:hash), `SUID`, `USER` (uid:gid:shell:home:
pwstate:nkeys — **never the hash**), `SSHKEY` (keyed by user:type:comment, valued by hash of
the key body), `LISTEN`, `PROC` (keyed by exe|argv identity, *not* PID — PIDs churn), `UNIT`
(enabled + hash of `ExecStart`/`ExecStartPre`/`User`), `CRON`, `MOD`, `SYSCTL`, `IFACE`,
`MOUNT`, `PKG`, `AGENT`.

Explicitly **not** in the baseline: anything that always changes — uptime, PIDs, socket
inodes, log sizes. That curation is the entire art of the feature; get it wrong and the diff
is unreadable.

Hash chain: `sha256sum` → `shasum -a 256` → `sha1sum` → `md5sum` → `cksum` (POSIX CRC32,
labelled `conf=weak-hash`) → size+mtime only with a `SKIP`. Algorithm recorded in `META`;
refuse to diff across algorithms.

Diff engine is awk over the single `MARK`-separated stream — no `sort`, no `diff`, O(n), memory
proportional to record count (~a few MB):

```awk
$1=="MARK" { cur=1; next }
!cur && $1=="OBS" { B[$2 SUBSEP $3]=$4; next }
 cur && $1=="OBS" { k=$2 SUBSEP $3
   if (!(k in B))     drift("ADDED",  $2,$3,"",$4)
   else if (B[k]!=$4) drift("CHANGED",$2,$3,B[k],$4)
   seen[k]=1; next }
END { for (k in B) if (!(k in seen)) { split(k,a,SUBSEP); drift("REMOVED",a[1],a[2],B[k],"") } }
```

Drift severity mapping is the product: `ADDED SUID|SSHKEY|MOD|USER` → CRIT; `ADDED
LISTEN|UNIT` → HIGH; `CHANGED FILE` for `/etc/{passwd,shadow,sudoers*}`, `authorized_keys`,
`ld.so.preload`, or any hash in `/usr/bin`,`/bin`,`/sbin` → CRIT; `CHANGED` mtime-only with
identical content → MED; `REMOVED AGENT` → CRIT; `REMOVED USER|SSHKEY` → INFO (probably you).

Refuse to diff across mismatched `machine-id`/hostname without `--force`, and always print
baseline age — a six-hour-old baseline on a compromised box is a baseline of a compromised box.

Second-order win: `--diff` **suppresses** the noisy inventory checks and replaces them with
deltas. That is what makes re-running every 15 minutes tolerable, and it is why baseline must
be built on the same collectors rather than bolted on afterward.

`--baseline FILE` writes to disk, violating read-only. Resolution: `--baseline -` writes to
stdout so it can be piped off-box, a path argument must be explicit, and the tool prints one
line naming the file it created and its hash. Disclose, don't pretend.

---

## Embedded signature data — no temp files

**Tier 1, literal token sets** (rootkit paths, bad module names, ~120-entry known-good SUID
list, security-agent allowlist): newline-delimited variables in a fenced, editable block,
injected into the stream as leading `SIG` records. **Never `awk -v tbl="$SIG"`** — `-v`
processes backslash escapes and will silently mangle any signature containing `\`.

**Tier 2, regex sets** (webshell, reverse shell, malicious cron): inline inside the awk program
text, avoiding all quoting round-trips. Write a literal `'` as `[\047]`.

**Tier 3, SUID allowlist:** one loosely distro-keyed union table, plus two rules that matter
more than the table itself — (1) any SUID/SGID outside `/usr/{bin,sbin,lib*,libexec}`,
`/bin`, `/sbin`, `/opt` is HIGH regardless of name, and (2) any SUID whose basename is a
shell/interpreter/GTFOBins staple (`bash sh dash python* perl ruby awk find vim tar cp mv env
node php gdb`) is **CRIT always**, even in `/usr/bin`.

Throughout: no `gensub`, no `asort`, no `length(array)`, no regex `RS`, no `\s`/`\d`, no
`ENDFILE` — mawk has none of them.

---

## Phased roadmap

| Phase | Deliverable | Rationale |
|---|---|---|
| **P0** | Skeleton + top 10 checks (~500 lines): arg parsing, `probe_toolbox`, emitters, text renderer, exit codes, the `$ROOT` convention. Checks: hidden-PID, listeners, cron, systemd units+timers, authorized_keys + sshd directives, `ld.so.preload`, SUID delta, deleted-exe, UID-0/empty-password, shell rc files | Emitters first because the record shape is the API everything compiles against. **P0 alone covers the competition's core use case — ship and dogfood it before anything else** |
| **P1** | Filesystem layer: one-pass walk, M08 integrity, M10 logs, M11 webshell, M07 PAM/NSS, udev/xinetd/motd, package verification | |
| **P2** | M13 services + M14 agents | The packet-specific surface; needs collectors stable |
| **P3** | Baseline/diff | Deliberately after collectors settle — building it earlier means rewriting the schema twice |
| **P4** | Output modes: NDJSON, `--out`, `--ir`, `--remediate`, `--hunt`, `--min-sev` | |
| **P5** | Selftest, lint, distro matrix, fork-budget enforcement | |
| **P6** | Deep rootkit: ftrace hooks, kallsyms, `/sys/module` divergence, bind-mount hiding, container reinterpretation | Highest-skill, lowest-frequency; correct to defer |

---

## Self-test

**`--selftest unit`** — pure functions, zero writes, safe in production. Enabled by a hard
design rule: **split every detector into `col_x` (touches the real system, returns text) and
`an_x` (pure function over text)**. Fixtures are canned `/proc/net/tcp` rows, canned
`/proc/PID/stat` lines (including a `comm` of `(we ird) x)` to pin the parser), canned
crontabs. That split makes ~80% of the logic testable including the kernel-facing parsers.

**`--selftest sandbox`** — plants benign IOCs under `mktemp -d` and re-runs with
`ROOT=$SANDBOX`. This is the one non-read-only mode: explicit request only, refuses if
`--root` is set, prints the sandbox path, cleans up on an `EXIT`/`INT` trap. Plants: a scoring
webshell, `curl|sh` cron, base64-blob cron, `command="/tmp/x"` authorized_keys,
`AuthorizedKeysCommand /tmp/k`, a unit + timer with `ExecStart=/tmp/x`, populated
`ld.so.preload`, a second UID-0 user, `/dev/shm/.hidden`, mode-666 `/etc/passwd`, a SUID
`/tmp/su` (gated — fails on `nosuid` tmpfs, so detect and `SKIP`), `.bash_history -> /dev/null`,
synthetic `proc/net/tcp` and `proc/1234/stat`, an `/etc/aliases` pipe entry, and a `~/.forward`.
Plus **a clean-sandbox run asserting zero findings** — the false-positive regression test is as
important as the positives.

**`--selftest lint`** — greps the script's own source for banned constructs and non-ASCII
bytes. shellcheck won't be on the competition box, and a construct that only fails on one
distro at 2am is exactly what this catches.

**Cannot be self-tested** — must be printed in the selftest summary, not quietly omitted: live
kernel-hidden PIDs/sockets/modules (parsers are fixture-tested; the live probe needs a real
rootkit — verify once manually in a throwaway VM with Diamorphine), taint bits, ftrace hooks,
kallsyms, immutable files, bind-mount hiding, promiscuous mode, firewall state, SELinux/
AppArmor, auditd, package verification. Summary should read `42 passed, 0 failed, 11
environment-gated`.

---

## Competition coverage traceability

Checked against `~/Downloads/Space RVB-1.1.pdf` so nothing in the packet is silently uncovered.

| Packet element | Covered by |
|---|---|
| Apollo (Debian 12) SSH / DNS / HTTP / **distcc** | M06, M13-dns, M11+M13-http, M13-distcc |
| Hubble (Ubuntu 24.04) SSH / **SMTP** / HTTP / **VNC** | M06, M13-smtp (aliases + `.forward`), M11, M13-vnc |
| Pathfinder (Ubuntu 22.04) SSH / **FTP** / HTTP / **MySQL** | M06, M13-ftp, M11, M13-mysql (incl. UDF) |
| Sat (Ubuntu 22.04) **Modbus TCP** | M13-modbus, INFO-only |
| Services may be relocated to new ports | No port assumptions anywhere; bind to observed listeners |
| Uptime is 50% | `--remediate` tags every fix with the services it could disrupt; no auto-execution. *Per your call, no health-check or watch mode — the scoreboard covers that* |
| IR is 15%, proof = processes/IPs/accounts/sessions | `--ir` builds exactly those four sections |
| "Do NOT remove wazuh-agent" | M14 allowlists it, never flags it, and CRITs if it stops |
| "No antivirus allowed" | No resident scanner, no signature auto-update, no quarantine. It's an audit tool — worth a one-line confirmation with White Crew regardless |
| Subnet blocking forbidden | `--remediate` emits single-IP rules only |
| Flags `ARTEMIS{}` earn store tokens | `--hunt 'ARTEMIS\{'` |
| Default password `Passw0rd123!` on 20 accounts | M02 duplicate-hash detection + `--weak-pass` |
| Router (OPNsense) in scope | **Not covered** — documented gap, audit via its UI |
| Columbia/Odyssey/Sputnik (Windows) | **Not covered** — documented gap |

---

## Verification

1. `bash -n bluesweep.sh`; `shellcheck -s bash` clean (warnings triaged, not blanket-disabled);
   `--selftest lint` passes.
2. `--selftest unit` and `--selftest sandbox`: all plantable detectors fire, clean-sandbox run
   produces zero findings, environment-gated count is printed not hidden.
3. Distro matrix in containers — `debian:12`, `ubuntu:22.04`, `ubuntu:24.04`, `rockylinux:9`,
   `fedora:latest`. **Run at least one pass with gawk removed** so mawk-only breakage surfaces.
4. Unprivileged run: completes, doesn't error, prints the degraded-checks header.
5. Read-only proof: run under `strace -f -e trace=openat,unlink,write` (or a pre/post
   `find / -newer` snapshot) and confirm no writes outside `--out`/`--baseline`.
6. Budgets: `--quick` under 60s, `--full` under 5min on a 2-vCPU VM; fork counts within budget
   via `--bench`.
7. Baseline round-trip: snapshot a clean container; plant a new SUID binary, a cron entry and
   an authorized key; re-diff; all three must surface as CRIT ADDED.
8. Bake-off on one host against `lynis audit system` and `rkhunter -c`: every high-severity item
   they find is either found by bluesweep or is a deliberate, documented scope exclusion.
9. Service-module fixtures: a container running distccd, bind9, postfix, vsftpd and MySQL in
   deliberately weak configs; confirm each M13 check fires.

## Known limits — stated in the script's own output and the README

- **Detecting a competent kernel rootkit from userland is infeasible.** These checks detect
  *inconsistencies*. A rootkit that hooks `getdents`, `tcp4_seq_show` and the module list
  coherently defeats all of it. Consistent results mean "no sloppy rootkit found", not "clean".
  The sound answer is out-of-band: snapshot the VM, mount the disk from a known-good host, diff.
  The rootkit section header says this verbatim — a blue-team tool that implies "clean" when it
  means "no inconsistency found" is worse than no tool.
- **"Modifies nothing" is precisely: writes no files, changes no configuration, starts no
  services, kills no processes.** Reading files still updates atime on `relatime` mounts, the
  run lands in auditd and `wtmp`, and page cache is perturbed. Claim the accurate thing.
- Hard dependency on `awk` and `find` in addition to bash, both POSIX. Say so in the README.
- No YARA, no hash reputation, no network lookups. Signature coverage is deliberately shallow
  and aimed at commodity and competition-grade persistence, not bespoke implants.
- Detection only. It never remediates on its own.
- Unprivileged ceiling: no other users' `/proc/*/fd`, no `/etc/shadow`, no `/proc/*/environ`,
  no kallsyms, no auditd state — roughly 40% of the value.
