# Space RVB 1.1: competition and defensive triage guide

Based on the supplied **Penn State CCSO RED vs. BLUE 2026, version 1.1** packet
(`Space RVB-1.1.pdf`, 13 PDF pages). Page references below are PDF page numbers.
The packet defines the exercise; scanner findings are observations to investigate,
not proof that Red Crew caused them.

## What the competition asks you to do

Blue Crew defends the Artemis ground station against Red Crew (SINGULARITY), keeps
scored services available, answers Orange Crew's management questions, and completes
White Crew's injects. The packet gives a 30-minute hardening period before Red goes
active (p. 3). Its timeline says check-in 09:30, start 10:00, ceasefire 16:30 and awards
16:45 (p. 8); the introduction calls it a six-hour simulation. Confirm the actual
attack-start time with White Crew rather than treating those descriptions as identical.

| Scoring category | Weight | Practical priority |
|---|---:|---|
| Uptime | 50% | Preserve legitimate access and service behavior while hardening |
| Incident reports | 15% | Record evidence and explain what it proves |
| Injects | 15% | Assign an owner and track each deadline |
| C-suite | 15% | Explain impact, confidence, response and remaining risks plainly |
| “The Game” | 5% | Details are revealed during the event |

The scoring weights are on p. 5. Flags of the form `ARTEMIS{...}` earn store tokens
(p. 8); this is separate from any assumption about how “The Game” will be scored.
The account table lists twenty accounts with a shared published initial password
(p. 9). Coordinate password changes with service dependencies and the competition's
access requirements; a shared starting credential is an immediate exposure.

## Scope and service map

`x` is the team-specific octet shown in the packet, not a scanner input. The topology
(p. 6) puts the Windows machines on the internal subnet, Apollo/Hubble/Pathfinder on
the user subnet, and Wazuh on the management subnet, behind OPNsense.

| Host | Address | Scored services (p. 7) | bluesweep coverage |
|---|---|---|---|
| Apollo, Debian 12 | `10.x.2.10` | SSH, DNS, HTTP-DNSGui, distcc | Linux scan; SSH, BIND ACLs, web files and live distcc policy |
| Hubble, Ubuntu 24.04 | `10.x.2.11` | SSH, SMTP, HTTP, VNC | Linux scan; mail configuration/forwarding, web files and VNC security options |
| Pathfinder, Ubuntu 22.04 | `10.x.2.12` | SSH, FTP, HTTP, MySQL | Linux scan; FTP configuration, web files, MySQL configuration/argv |
| Sat, Ubuntu 22.04 | `10.x.2.13` | Modbus TCP | Passive inventory; no PLC writes or protocol requests |
| Router, OPNsense | `172.16.x.3` | SSH, HTTPS | Offline copied tree on an authorized Linux analysis host; no native BSD execution |
| Columbia, Windows Server 2022 | `10.x.1.10` | LDAP/LDAPS, SMB, WinRM | Separate Windows tooling required |
| Odyssey, Windows Server 2022 | `10.x.1.11` | MSSQL, SMB, WinRM | Separate Windows tooling required |
| Sputnik, Windows 10 | `10.x.1.12` | SMB, WinRM | Separate Windows tooling required |

The satellite can **only be controlled through Hubble's HMI/PLC** (p. 6). A listener on
port 502 is merely a possible Modbus observation, not proof of compromise. DNSGui,
the HMI application, database account grants/UDFs, and end-to-end service health still
need application-specific review; bluesweep does not log into them or exercise exploits.
Services may move, but scoring checks stay the same (p. 4). Runtime checks associate
recognized processes with observed socket inodes rather than assuming default ports.
Missing PID visibility is incomplete evidence, especially without root.

## Rules that affect response

The packet (pp. 4, 6, 8) permits individual-IP blocking and prohibits subnet blocking,
attacks on other teams, deceiving service checks, antivirus, and removing `wazuh-agent`.
Wiretap, the scoring engine and OpenStack infrastructure are outside your administrative
scope. Red will not attack the Wazuh SIEM node. Other teams' store accounts are off limits.
**Nothing, including malware, may leave the competition environment.** Keep exported
records, router copies and analysis within that environment; use the prescribed report
submission workflow. A one-shot audit script's classification under the antivirus rule
is a White Crew decision, not something this repository can authorize.

bluesweep does not block addresses or apply remediation. `--remediate` writes comments
for review and identifies potential service disruption. It never recommends that an
unobserved listener means a change is safe. Preserve defender telemetry and use Wazuh to
corroborate local findings.

## Suggested workflow

1. Establish console access, assign host owners and record which services are working.
   Take an initial quick scan; read the SKIPs as well as the findings. Make a baseline
   inside the competition environment before changes, but remember that initial state
   may already contain compromise.
2. During hardening, prioritize accounts/SSH, concrete authentication bypasses, exposed
   distcc access, dangerous persistence and writable execution paths. Review each
   change against the scored services and retain a working access path.
3. Rescan with the same privilege, root and quick/full mode. Use diff to distinguish
   newly introduced accounts, keys, commands, listeners and service policies. Record
   your own changes so they do not become unexplained incident alerts.
4. Preserve incident evidence before repair. Use the scoreboard for uptime and Wazuh
   for independent telemetry. Track inject deadlines alongside incident response.

```sh
# Rootless is supported; root improves visibility when available.
bash bluesweep.sh --quick
sudo bash bluesweep.sh --quick
sudo bash bluesweep.sh --quick --baseline before.base
sudo bash bluesweep.sh --quick --diff before.base
sudo bash bluesweep.sh --quick --ir incident-01 --remediate review-01.sh
sudo bash bluesweep.sh --quick --weak-pass
bash bluesweep.sh --quick --hunt 'ARTEMIS[{]'
```

Choose new output paths; exports do not overwrite existing evidence. Version 0.3.0 uses
baseline schema 2; preserve older snapshots and capture a fresh baseline after upgrading. `--weak-pass` is
an opt-in local candidate comparison with readable hashes, never a login attempt.
Unsupported hash schemes are explicit SKIPs. `--hunt` searches bounded candidates,
so it cannot guarantee that every flag was found. A scan with SKIPs exits 3 even when
it also contains urgent findings. Rootless coverage can lose roughly 40% of checks.
A namespace UID of 0 does not confer access to host-root evidence.

## Reading service and exploit-surface findings

| Evidence | Detection and restraint |
|---|---|
| distccd universal `--allow` plus associated non-loopback listener | SRV001 HIGH/possible; arbitrary work by permitted clients is a documented trust risk, but firewall reachability is untested. Merely running scored distcc is inventory. Socket UID alone is not the daemon's current privilege. |
| Xvnc/Xtigervnc/x0vncserver explicitly offers `None`, `TLSNone` or `X509None` | HIGH without an associated external listener, CRIT/possible with one. Recognizes separated/equals option forms and the last security-types value. Clients/viewers are excluded. Runtime changes are not queried; x11vnc `-nopw` alone is not proof of disabled authentication. |
| Literal BIND ACL with `any`, `0.0.0.0/0` or `::/0` | Multiline/comment-aware DNS001–003; `!any`, quoted names and `company` do not become wildcard grants. ACL references, view inheritance and full effective configuration are not resolved. |
| MySQL `skip-grant-tables` | SQL001 for an enabled server-file setting, SQL005 for enabled startup argv. OFF/false/0 and client-only groups are not bypass findings. Includes, group suffixes and runtime grant reloads remain limits; remote reachability is not inferred. |
| PHP request input, decoding, or a lone execution API | Insufficient for a webshell finding by itself. WEB001 requires combined execution/input/obfuscation signals, direct request-to-execution syntax, or PHP disguised as an image. Static correlation still needs source review. |
| User systemd units and standard execution hooks | Inventory plus content checks and drift. Existence alone is not a high-severity compromise finding; enabled state and drop-in precedence require review. |

There is no version-only CVE verdict, exploit execution or network vulnerability lookup.
Backported fixes and runtime configuration make version strings insufficient evidence.
The absence of findings is not proof of a clean system; coherent kernel tampering can
hide from all local userland checks.

## Incident reports and management answers

The packet requires proof: processes, intruder IP addresses, accounts used and hijacked
sessions (p. 11). `--ir` creates Markdown with those evidence sections, record-line
references, artifact digests, a timeline and an analyst-assessment template. Most
observations are unattributed: a connection is not automatically an attacker, and a
file mtime is not automatically an attack timestamp.

Fill in what happened, the affected service, evidence IDs, observed times, actions,
availability impact and uncertainties. Convert the reviewed report to **PDF** using
an approved editor inside the competition environment. The packet requires PDF upload
to Discord before the deadline (pp. 12–13); bluesweep does not generate or submit PDFs.
For Orange Crew, explain service impact, what is known, what is uncertain and the next
verification step. Do not present a heuristic as a confirmed intrusion.

## Research behind this revision

Reviewed on 2026-09-17. These are design references, not downloaded runtime dependencies;
no external tool or exploit was executed on the target.

- Local `blue-scripts/discovery.sh`: basic artifact, set-ID, permissions, sockets and
  recent-file inventory. bluesweep keeps those observations bounded and read-only.
- Local linPEAS copy: see [the existing coverage ledger](LINPEAS-COVERAGE.md). Its broad
  privilege/exposure inventory is useful for choosing review targets, not automatic
  attribution or a reason to label every legitimate service as malicious.
- [Lynis database checks](https://github.com/CISOfy/lynis/blob/master/include/tests_databases):
  informed separating configuration posture from evidence of an attack.
- [UAC process artifact](https://github.com/tclahr/uac/blob/main/artifacts/live_response/process/ps.yaml):
  reinforced keeping process context for incident evidence; bluesweep retains its own
  direct `/proc` collection instead of executing the artifact's commands.
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester): reviewed
  its vulnerability-auditing approach; no exploit payloads or version-only findings added.
- Primary semantics: [distcc security](https://www.distcc.org/security.html),
  [TigerVNC Xvnc parameters](https://tigervnc.org/doc/Xvnc.html), and MySQL
  [server options](https://dev.mysql.com/doc/refman/8.0/en/server-options.html) and
  [option files](https://dev.mysql.com/doc/refman/8.0/en/option-files.html).
