# bluesweep.sh

Single-file Linux defender triage: persistence, privilege exposure, process/kernel
inconsistencies, service misconfiguration, credential-file exposure, and change detection.
Copy one Bash script to the host. No installation, downloads, package changes, or resident
agent. Scan content is never sourced or executed.

```sh
sudo bash bluesweep.sh --quick
sudo bash bluesweep.sh --full --json findings.ndjson --ir incident-01
sudo bash bluesweep.sh --quick --baseline before.base
sudo bash bluesweep.sh --quick --diff before.base
bash bluesweep.sh --root /mnt/victim --full
```

Version **0.2.0** implements all 14 planned module areas at varying depths. It is a triage
scanner, not a proof that a machine is clean or a complete replacement for specialist
forensic tools. See [the original design](plan.md) and the
[local linPEAS coverage comparison](docs/LINPEAS-COVERAGE.md) for exact scope and gaps.

## What it checks

| Area | Coverage |
|---|---|
| Host inventory | OS/kernel, container indicators, boot/uptime, memory/load, local disks, mounts, route/ARP tables, login/password policy |
| Accounts | Duplicate UID/UID 0, empty passwords, weak/duplicate hashes, shadow change/expiry metadata, sensitive groups, legacy trust files, sudoers/doas/polkit/D-Bus policy |
| Shell and session startup | Bash, Zsh, Fish, Ksh, Csh/Tcsh, Nushell configuration, login/logout profiles, X/session scripts, environment files, prompt/trap/loader hooks, orphaned home directories |
| Persistence | Cron/spools/at files, systemd units/timers/drop-ins/user units/generators, SysV init, udev, package-manager hooks, desktop autostart, network dispatchers, mail aliases and `.forward` |
| Kernel/processes | `/proc` PID/PPID/argv/executable/start ticks, selected hidden-PID inconsistencies, deleted executables, temporary-path execution, reverse-shell-like commands, loader variables, executable mappings, module/sysfs differences, taint, ftrace, symbols, sensitive mount overlays |
| Network | Kernel TCP/UDP listeners, owning-PID association, established peers, packet sockets, promiscuous flags, resolver inventory, firewall/NAT rules; `ss`/`netstat` fallback when live kernel sockets are unavailable |
| SSH | Default and alternate `AuthorizedKeysFile`, forced-command keys, sshd directives/drop-ins, SSH rc/environment files, key fingerprints |
| Authentication stack | PAM permit/exec/nonstandard module indicators; NSS configuration inventory; local privilege-policy checks |
| File integrity | Set-ID binaries/interpreters, world/group writable configuration, root-owned writable executables, orphan ownership, recent files, content/metadata fingerprints, extended ACLs, file capabilities, immutable flags, optional package verification |
| Logs / sessions | Empty accounting logs, history suppression, audit-rule availability, recent authentication/command events, controlling terminals and session/SSH/GPG socket permissions |
| Web | nginx/Apache webroot discovery, bounded weighted PHP/JSP/ASP heuristics, PHP hidden in image extensions, `.htaccess`/`.user.ini`, automatic prepend/append and proxy/CGI configuration |
| Services | distcc, DNS/BIND, SMTP/Postfix/Exim, FTP, MySQL/MariaDB, PostgreSQL, VNC, HTTP/PHP, Redis, MongoDB, MQTT, rsync, Supervisor, SNMP, Elasticsearch, CI security config, LDAP, NFS, Samba; ICS/Modbus observations remain informational |
| Containers / credentials | Runtime control-socket exposure, Kubernetes credential paths, process capabilities/seccomp, host-access configuration; 271 application/credential filename patterns and redacted credential-content indicators |
| Defender agents | Wazuh, osquery, auditd, Falco, Velociraptor and other known agents; local enrollment/config metadata; CRIT drift when a previously running agent is observed stopped |
| Binary provenance (`--full`) | `dpkg-query -S` / `rpm -qf` over every running executable: which binaries no package owns, graded by where they sit. Unowned inside `/usr/bin`, `/bin`, `/sbin` is treated differently from unowned inside `/usr/local` or `/opt`, where locally built software legitimately lives |
| Unknown services | Every listening socket scored on kernel-reported attributes rather than on a service name: unowned or deleted or memfd-backed executable, transient/user-writable path or working directory, absence of a systemd unit, binding beyond loopback, process name not matching the executable. This is the inverse of the name-driven service checks - a listener matching no known profile is what surfaces, not what is skipped |
| Outbound peers | Established connections to non-private peers, raised above inventory level when the owning process also fails provenance, placement or unit tests, or when the socket is held by a shell or interpreter. Reverse shells and beacons bind nothing, so for that implant class this is the only network evidence there is |
| Binary structure (`--full`) | ELF header and program-table anomalies over running executables and unpackaged/transient-path binaries: UPX packing, removed section header table, `ET_EXEC` with `PT_DYNAMIC` and no `PT_INTERP`, writable+executable load segments, and Shannon entropy above 7.2 across the first 64 KiB. Structural and offline - no signature database, no hashes, no network |
| binfmt_misc | Live interpreter registrations read from `/proc/sys/fs/binfmt_misc`, plus the `binfmt.d` configuration systemd replays at boot. A registration made at runtime exists nowhere on disk, so it survives every audit that only reads `/etc` |
| Kernel-run helpers | `core_pattern` (a `\|` value makes the kernel pipe every crash to that program, as root), `kernel.modprobe`, `poweroff_cmd`, `uevent_helper`, legacy `hotplug` - each read live from the kernel and compared against the distribution default, plus the `sysctl.conf`/`sysctl.d` entries that restore a hostile value at boot. systemd-coredump and apport are recognised and not flagged |
| Auto-executed directories | ~70 directories whose contents run automatically without being cron or a unit: `if-up.d`/`if-down.d`, dhclient enter/exit hooks, networkd-dispatcher, systemd sleep/shutdown/generator hooks, `Xsession.d` and GDM/LightDM hooks, kernel and initramfs postinst hooks, dpkg/apt/dnf/yum hooks, `tmpfiles.d`, `modules-load.d`, `sysctl.d`, `ld.so.conf.d`, `rsyslog.d`, `logrotate.d`, `acpi` actions. Entries are inventoried and scored for non-root ownership, world-writability, and - through the same command grammar as cron and units - remote-fetch and reverse-shell content |
| TCP wrappers | `hosts.allow`/`hosts.deny` `spawn`, `twist` and `aclexec` directives, which run a shell command on every matching connection |
| SSH client-side exec | `ProxyCommand`, `LocalCommand`, `PermitLocalCommand` and `Match exec` in the system `ssh_config`, its drop-ins, and every user's `~/.ssh/config` - a backdoor that fires when an operator sshes *out* of the box, including the operator hunting the intrusion |
| eBPF and dynamic tracing | Pinned objects under `/sys/fs/bpf`, installed `kprobe_events`/`uprobe_events`, and `bpftool prog list` where available. An eBPF implant hides processes and filters packets without a kernel module, so none of the module-list divergence checks see it |
| Hidden system files | Dot-files and dot-directories inside `/usr/bin`, `/bin`, `/sbin`, `/lib`, `/etc`, `/boot`, `/opt`, `/srv`, `/var/www` and `/dev/shm`, with packaging conventions (portage keepers, RHEL placeholders, the Fedora build-id tree, etckeeper, overlayfs whiteouts) allowlisted |
| Coinminers | Mining-pool URLs, miner binaries and miner flags across process command lines and the bounded candidate config set - the most common payload on a compromised competition host, and one that no persistence check sees because it is usually *started by* persistence rather than being it |
| Known-bad ports and artifacts | Commodity implant and coinminer artifact paths, and listeners on ports commonly used by backdoors and handlers. Both are shallow offline IOC lists reported as evidence, never as a verdict |

### Bashrc files really are scanned

The startup collector reads and fingerprints these locations for every home in the target
`/etc/passwd`, and also checks orphaned home startup files in the walk candidates:

- `.bashrc`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.profile`
- `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.zlogout`
- `.kshrc`, `.cshrc`, `.tcshrc`, `.login`, `.logout`, `.pam_environment`
- `.xinitrc`, `.xsession`, `.xsessionrc`, `.xprofile`
- `.config/fish/config.fish`, `.config/fish/conf.d/*.fish`
- `.config/nushell/config.nu`, `.config/nushell/env.nu`, `.config/environment.d/*.conf`

It also checks `/etc/profile`, `/etc/profile.d/*`, system Bash/Zsh/Csh/Fish files,
`/etc/environment`, `/etc/environment.d/*`, `/etc/update-motd.d/*`, and
`/etc/bash_completion.d/*`. Repeated homes are deduplicated. Unterminated final lines
are inspected. Files are read as text; no shell startup code is executed.

Remote-fetch-to-shell, reverse-shell patterns, temporary-directory sourcing, unsafe PATH,
`LD_PRELOAD`/`LD_AUDIT`, `BASH_ENV`/`ENV`/`ZDOTDIR`, prompt commands, traps, and writable
startup files receive findings. Fingerprints and line observations support subsequent diffs.
Dynamic source graphs, arbitrary `ZDOTDIR`, and shell condition evaluation are not resolved.

## Usage

```text
-q, --quick             Bounded fixed directories, depth 4; default
-f, --full              Local filesystem walk and deeper/package checks
-r, --root DIR          Offline target directory
-m, --min-sev SEV       Terminal filter: CRIT HIGH MED LOW INFO
-v, --verbose          Also show successful checks
    --baseline FILE    New snapshot file; - streams to stdout
    --diff FILE        Compare a compatible snapshot
    --force            Override host/machine-id mismatch only
    --json FILE        NDJSON records; - gives JSON-only stdout
    --out DIR          New evidence directory and hashed artifacts
    --ir DIR           Evidence directory plus Markdown IR report
    --remediate FILE   New commented review script; no executable fixes
    --hunt REGEX       Content hunt within selected file candidates
    --recent-days N    Recent file window, 1..99 days; default 7
    --weak-pass        Opt-in bounded local weak-password candidate test
    --weak-pass-file F Additional candidate file
    --bench            Elapsed time; fork count is not measured
    --selftest MODE    unit | sandbox | lint
    --raw              Post-rule tab-separated records; no severity exit calculation
    --no-color        Also honors NO_COLOR and nonterminal stdout
    --exit-zero       Suppress scan finding/incomplete exits
```

Output files/directories must be new; existing evidence is never overwritten implicitly.
Use the same directory for `--out` and `--ir` if both are specified. `--raw` is separate
from export modes. `--baseline` is separate from diff/export modes. Explicit output paths
are excluded from the filesystem walk so a snapshot cannot fingerprint itself.

### Exit codes and incomplete coverage

| Code | Meaning |
|---:|---|
| 0 | No finding above INFO |
| 10 / 20 / 30 / 40 | Worst finding LOW / MED / HIGH / CRIT |
| 2 | Invalid options, incompatible baseline, or unusable output destination |
| 3 | Incomplete scan: skipped capability, timeout, output failure, or internal error |
| 4 | Self-test failure |

Incomplete status takes precedence over severity. Read the findings even when the exit
code is 3. `--min-sev` only filters terminal display, not the exit calculation or exports.
SKIPs are explicit and never treated as successful checks. Repeated terminal findings and
skips are condensed; raw/JSON retains the individual records.

## Baseline and diff

Snapshots use the same collector as normal checks. They contain versioned META/OBS/SKIP
records, never executable shell. Stable file, user, key, startup, cron/unit, listener,
module, agent, group, privilege-state and package observations are curated for comparison.
PIDs, socket inodes, uptime, log lengths and transient process-security fields are excluded.
Process identity uses executable/argv rather than PID; selected scanner/helper identities
are omitted to reduce noise.

The scanner validates schema, size, record format, collection mode, hash tool, hostname and
machine-id before diffing. `--force` overrides identity only. Baseline age is shown.
New SUID files, accounts, SSH keys, modules and cron commands are CRIT; new listeners and
execution configuration are HIGH. Sensitive file-content changes are CRIT, but identical
content with changed mtime is MED. Changed startup fingerprints are HIGH. Agent transitions
from running to stopped are CRIT even when unrelated checks are skipped.

Removal findings are suppressed if current collection is incomplete: an unreadable file
must not be mistaken for a deleted file. This is conservative and can limit removal
reporting on unprivileged/offline runs. A baseline can already contain compromise.

Hash fallback: `sha256sum`, `shasum -a 256`, `sha1sum`, `md5sum`, `cksum`; weaker choices
are labelled in metadata. Files over 2 MiB use metadata-only fingerprints. Protected small
files that cannot be hashed are skipped explicitly. Snapshot record and byte limits are
reported, never silently discarded.

## Evidence and IR

`--out` writes `records.tsv`, default `findings.ndjson`, numbered artifacts, `manifest.tsv`
and `manifest.digest`. Selected passwd/group/resolver/SSH configuration and auth/audit/web
access/accounting logs are copied in bounded prefixes of at most 8 MiB; that limit is
recorded in the manifest. Hashes describe the collected bytes, not an implied full original.
Private SSH keys and shadow contents are not copied automatically.

`--ir` adds `report.md` with the four requested proof sections: processes, peer addresses,
accounts, and sessions. Evidence references point to `records.tsv` line numbers. File
mtime observations are converted to UTC; authentication timestamps retain their source
format/timezone. Mtimes can be altered and connections do not establish attacker identity.
The report is an analyst starting point, not automatic attribution or complete timeline
reconstruction.

`--remediate` writes comments describing review steps and service-disruption risks. It
contains no executable remediation, firewall blocks, service stops, or agent removal.

Exports use private permissions (`umask 077`). Process commands, config observations and
logs can contain sensitive material even though dedicated credential checks redact values.
Handle the resulting evidence accordingly.

## Bounds and dependencies

Target families: Debian 12, Ubuntu 22.04/24.04, RHEL/Rocky/Fedora and SUSE. Bash 4+ and
ordinary Linux core utilities are required, including `awk`, GNU `find`, `stat`, `sleep`,
`date` and `readlink`. Optional tools add capabilities and otherwise produce SKIPs:
`ss`, `netstat`, `getcap`, `getfacl`, `lsattr`, `auditctl`, firewall tools, package tools,
OpenSSL and hashing utilities. No package manager or network connection is needed to run.

- Quick mode has no whole-filesystem traversal: fixed roots and discovered webroots,
  maximum walk depth 4, with separately enumerated fixed startup/config locations.
- Full mode uses local mount roots and `-xdev`; known remote/FUSE mounts and
  `/proc`, `/sys`, `/dev`, `/run`, `/snap`, Docker/container storage are pruned from the walk.
  Dedicated kernel/runtime probes still inspect their specific virtual-file paths.
- Candidate selection includes recent/config/system-bin/set-ID/writable files, scripts,
  hidden/control-character names and the 271 application filename patterns.
- Maximum 20,000 walk candidates; content/hash scans generally cap files at 2 MiB;
  selected finding categories cap at 200. Oversized record fields are capped explicitly.
- Package-ownership queries run in `--full` only, batched 64 executables per manager
  invocation, and never against `--root` images: the host database does not describe a
  mounted image. Without a working `dpkg-query -S` / `rpm -qf` the answer is UNKNOWN and
  is reported as a SKIP, never as ownership.
- The ELF scan reads at most 64 KiB per file and caps candidates at 200. It deliberately
  does not re-read packaged content under `/usr/bin`, which `dpkg --verify` / `rpm -Va`
  already speak for; it reads what those two cannot.
- Bash watchdogs limit child commands; overall check budgets are 60 seconds quick and
  300 seconds full, with 30/60-second stage limits. A stuck kernel I/O operation cannot
  always be interrupted immediately; permission/candidate/time limits mean incomplete scans.
- Weak-password checking attempts up to 64 accounts/candidates with OpenSSL support for
  standard MD5/SHA-256/SHA-512 crypt salts. Unsupported hashes, including yescrypt/bcrypt
  or custom rounds, are skipped explicitly. No login attempts occur.

## Validation

```sh
bash -n bluesweep.sh
bash bluesweep.sh --selftest unit
bash bluesweep.sh --selftest sandbox
bash bluesweep.sh --selftest lint
python3 tests/test_integration.py
POSIXLY_CORRECT=1 python3 tests/test_integration.py
```

Native tests cover kernel parsers, command rules, service fixtures, rendering/exits,
agent/mtime drift, SUID/webshell/PAM/history fixtures and clean detector fixtures. Python
integration tests exercise whole-script CLI/export paths, clean images, shell variants,
service misconfigurations, custom webroots/keys, snapshot changes, hostile filenames,
no-clobber, output exclusion and an unchanged offline fixture after a normal scan.
Python is a development-test dependency only.

Environment-gated validation remains: real hidden-kernel attacks, package-ownership
provenance and the listener/outbound scores built on it (these need a real dpkg or rpm
database, so a Portage or Alpine host reports them as SKIP), actual mawk and the
full distribution container matrix, syscall-level no-write/fork accounting, and service
integration against running daemon instances. POSIX-mode gawk tests are not an actual
mawk run. `--bench` does not claim an unmeasured fork budget.

## Limits

Assume userland may be lying. Kernel files are preferred; tool-derived metadata is marked
or described as untrusted. The executable/FD ownership cache uses `ls`; coherent tampering
of the kernel, Bash and supporting tools can defeat this scanner. Socket/PID/module
inconsistencies also have legitimate race, namespace and visibility explanations.
Kernel taint is a diagnostic signal, not proof of compromise; bit descriptions follow the
[Linux kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html).

`--root` prefixes target paths but is **not filesystem confinement**: symlinks can resolve
outside the image. Use a known-good isolated analysis environment for adversarial images.
The unknown-service and outbound scores are heuristics over attributes, not verdicts: an
administrator's hand-built daemon in `/opt` scores like an implant does, and an implant
that is packaged, unit-managed and placed in `/usr/sbin` scores like a daemon. The binary
structure rules describe what compilers and linkers do not emit, so a deliberately packed
vendor tool is a true positive of packing and a false positive of malice. None of it is a
substitute for a signature engine, and no rule here reads file content for known payloads.

The tool does not claim complete application grammar/include resolution, authenticated
SQL audit, server-side enrollment verification, vulnerability-database coverage or full
linPEAS parity. The [coverage ledger](docs/LINPEAS-COVERAGE.md) lists those distinctions.

### OPNsense and pfSense

The appliance ships no bash and mounts no procfs, so bluesweep cannot run on it. It reads a
**copy of the appliance filesystem from a Linux host** instead:

```sh
ssh root@router tar -cf - /conf /etc /usr/local/etc /var/cron /root | tar -xf - -C /mnt/opn
./bluesweep.sh --root /mnt/opn --baseline router.snap     # before the attack window
./bluesweep.sh --root /mnt/opn --diff router.snap         # repeatedly, afterwards
```

`/conf/config.xml` holds essentially the whole system state — accounts, SSH keys,
privileges, firewall and NAT rules, cron, installed packages and a `<revision>` stamp — so
it is parsed into per-item observations, and a router account added by an attacker appears
as `ADDED OPNUSER` at CRIT. Hashes and key material are deliberately **not** recorded: user
records carry the hash *type* and a yes/no for keys, never the values.

Everything `/proc`-derived SKIPs, and says so. The filesystem checks do run: FreeBSD
auto-run directories (`rc.d`, `rc.syshook.d`, `periodic`, `devd`, `ppp` hooks) are scored by
the same command grammar as Linux cron, so a `curl | sh` dropped in `rc.syshook.d/start` is
a CRIT. A config.xml diff catches anything done through the UI or API; it does **not** catch
shell-level changes that bypass the configuration, which is why the filesystem checks matter
alongside it.

Normal scans create no files or configuration and do not act on target processes/services.
Explicit snapshots/exports/sandbox tests write files. Reading may change atime; scans and
child commands may appear in host audit logs. Watchdogs terminate only scanner-owned child
commands. Windows, macOS and BSD (including OPNsense/pfSense) need separate tools.

## License

MIT. See [LICENSE](LICENSE).
