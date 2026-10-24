#!/usr/bin/env python3
"""Read-only media-stack checks. Python 3.9+, standard library, Docker CLI."""
import argparse
import datetime as dt
import email.message
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import smtplib
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

LEVEL = {'PASS': 0, 'INFO': 0, 'WARN': 1, 'FAIL': 2}


def command(args, timeout=20, stdin=None):
    # Never include command arguments or subprocess output in raised errors: secrets
    # can exist in Docker metadata, app settings, or authentication headers.
    try:
        p = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('command timed out') from None
    except OSError:
        raise RuntimeError('required executable unavailable') from None
    if p.returncode:
        raise RuntimeError('command failed (exit %d)' % p.returncode)
    return p.stdout.strip()


def http_json(url, data=None, headers=None):
    request = urllib.request.Request(url, data=None if data is None else json.dumps(data).encode(),
                                     headers=headers or {})
    with urllib.request.urlopen(request, timeout=12) as r:
        body = r.read(2_000_000)
        return json.loads(body) if body else None


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def disk_result(total, available, free_inodes, inodes, warn=80, critical=90, minimum=2):
    used = 100 * (1 - available / total) if total else 100
    inode_used = 100 * (1 - free_inodes / inodes) if inodes else 0
    level = 'FAIL' if used >= critical or inode_used >= critical or available < minimum * 2**30 else (
        'WARN' if used >= warn or inode_used >= warn else 'PASS')
    return level, used, inode_used


def new_issues(rows, previous_counts, minimum=2):
    counts, active = {}, {}
    for row in rows:
        if LEVEL[row['level']]:
            key = row['id']
            counts[key] = previous_counts.get(key, 0) + 1
            if counts[key] >= minimum or row.get('urgent'):
                active[key] = row['level']
    return counts, active


def signature(active):
    return hashlib.sha256(json.dumps(active, sort_keys=True).encode()).hexdigest()


class Monitor:
    def __init__(self, config, old, daily):
        self.c, self.old, self.daily = config, old, daily
        self.project = Path(config['project_dir']).expanduser().resolve()
        self.rows, self.containers, self.new_metrics = [], {}, {}
        self.cache = old.get('daily_cache', {})

    def add(self, key, level, detail, urgent=False):
        self.rows.append(dict(id=key, level=level, detail=detail, urgent=urgent))

    def attempt(self, key, action):
        try:
            action()
        except Exception as e:
            # Do not leak urllib URLs, credentials, XML, cookies, or Docker env.
            detail = str(e) if isinstance(e, RuntimeError) else type(e).__name__
            self.add(key, 'WARN', 'Unable to complete check: ' + detail)

    def dex(self, container, *args, timeout=20):
        return command(['docker', 'exec', container, *args], timeout)

    def container_checks(self):
        for name in self.c['containers']:
            try:
                obj = json.loads(command(['docker', 'inspect', name]))[0]
            except Exception:
                self.add('container:' + name, 'FAIL', name + ': missing or Docker unavailable')
                continue
            self.containers[name] = obj
            state = obj['State']
            if not state.get('Running'):
                self.add('container:' + name, 'FAIL', name + ': ' + state.get('Status', 'not running'))
            elif state.get('Health', {}).get('Status') in ('unhealthy', 'starting'):
                self.add('container:' + name, 'FAIL', name + ': ' + state['Health']['Status'])
            else:
                self.add('container:' + name, 'PASS', name + ': running')
            current = {'id': obj['Id'], 'restarts': obj.get('RestartCount', 0)}
            previous = self.old.get('metrics', {}).get('restart:' + name, {})
            delta = current['restarts'] - previous.get('restarts', current['restarts'])
            if previous.get('id') == current['id'] and delta > 0:
                self.add('restart:' + name, 'WARN', '%s: %d restart(s) since last run' % (name, delta), True)
            self.new_metrics['restart:' + name] = current

    def vpn_checks(self):
        gateway = self.c['vpn_container']
        self.dex(gateway, '/gluetun-entrypoint', 'healthcheck')
        self.add('vpn:health', 'PASS', 'Gluetun live health check passed')
        ns = self.dex(gateway, 'readlink', '/proc/self/ns/net')
        gateway_ip = None
        try:
            gateway_ip = str(ipaddress.IPv4Address(self.dex(gateway, 'cat', '/tmp/gluetun/ip')))
        except Exception:
            self.add('vpn:recorded-ip', 'WARN', 'Gluetun public-IP record unavailable')
        host_ip = None
        try:
            with urllib.request.urlopen(self.c['ip_url'], timeout=12) as r:
                host_ip = str(ipaddress.IPv4Address(r.read(100).decode().strip()))
        except Exception:
            self.add('vpn:host-ip', 'WARN', 'Could not obtain host public IP for comparison')
        for name in self.c['vpn_clients']:
            def client_check(name=name):
                actual_ns = self.dex(name, 'readlink', '/proc/self/ns/net')
                if actual_ns != ns:
                    self.add('vpn:namespace:' + name, 'FAIL', name + ': NOT in current Gluetun network namespace', True)
                    return
                self.add('vpn:namespace:' + name, 'PASS', name + ': shares live Gluetun network namespace')
                public = str(ipaddress.IPv4Address(self.dex(name, 'curl', '-4', '-fsS', '--max-time', '12', self.c['ip_url'])))
                if host_ip and public == host_ip:
                    self.add('vpn:egress:' + name, 'FAIL', name + ': exit IP matches host public IP; check VPN routing', True)
                elif gateway_ip and public != gateway_ip:
                    self.add('vpn:egress:' + name, 'WARN', name + ': exit IP differs from Gluetun recorded IP')
                elif not host_ip or not gateway_ip:
                    self.add('vpn:egress:' + name, 'WARN', name + ': egress works, but IP comparison incomplete')
                else:
                    self.add('vpn:egress:' + name, 'PASS', name + ': exits through ' + public + ', different from host')
            self.attempt('vpn:probe:' + name, client_check)
        # An installed wg utility is optional; health + egress + namespace are independent checks.
        try:
            raw = self.dex(gateway, 'wg', 'show', self.c['vpn_interface'], 'latest-handshakes')
            stamps = [int(line.split()[-1]) for line in raw.splitlines() if line.strip()]
            age = time.time() - max(stamps) if stamps and max(stamps) else float('inf')
            self.add('vpn:handshake', 'PASS' if age < 300 else 'WARN',
                     'WireGuard latest handshake age: %s' % ('never' if age == float('inf') else '%ds' % age))
        except Exception:
            self.add('vpn:handshake', 'INFO', 'wg utility unavailable; verified live health, namespace and egress instead')

    def qbit_checks(self):
        name = self.c['qbit_container']
        prefs = json.loads(self.dex(name, 'curl', '-fsS', '--max-time', '10',
                                  'http://127.0.0.1:8080/api/v2/app/preferences'))
        binding = prefs.get('current_network_interface', '')
        self.add('qbit:binding', 'PASS' if binding == self.c['vpn_interface'] else 'FAIL',
                 'qBittorrent interface: ' + (binding or 'ANY/unset'), binding != self.c['vpn_interface'])
        port = int(self.dex(self.c['vpn_container'], 'cat', '/tmp/gluetun/forwarded_port'))
        match = 1 <= port <= 65535 and prefs.get('listen_port') == port
        self.add('qbit:port', 'PASS' if match else 'FAIL', 'Forwarded port %d; qBittorrent listening port %s' % (port, prefs.get('listen_port')))
        safe = prefs.get('random_port') is False and prefs.get('upnp') is False
        self.add('qbit:port-settings', 'PASS' if safe else 'WARN', 'Random port and UPnP disabled' if safe else 'Disable random port and UPnP')
        if prefs.get('queueing_enabled'):
            self.add('qbit:queue', 'WARN', 'Torrent queueing enabled; some books may not be seeding')
        else:
            self.add('qbit:queue', 'PASS', 'Torrent queueing disabled')
        info = json.loads(self.dex(name, 'curl', '-fsS', '--max-time', '10',
                                 'http://127.0.0.1:8080/api/v2/transfer/info'))
        self.add('qbit:connection', 'PASS' if info.get('connection_status') == 'connected' else 'WARN',
                 'qBittorrent connection status: ' + str(info.get('connection_status', 'unknown')))
        torrents = json.loads(self.dex(name, 'curl', '-fsS', '--max-time', '10',
                                     'http://127.0.0.1:8080/api/v2/torrents/info'))
        bad = [t for t in torrents if t.get('state') in ('error', 'missingFiles')]
        queued = sum(t.get('state') == 'queuedUP' for t in torrents)
        self.add('qbit:torrents', 'WARN' if bad else 'PASS', '%d torrents; %d errored/missing; %d queued for seeding' % (len(torrents), len(bad), queued))
        self.add('qbit:tracker-auth', 'INFO', 'Tracker authentication is not tested with a forced announce; consult MAM/Prowlarr if downloads fail')

    def prowlarr_checks(self):
        # Read only the API key; never include XML/key/app error text in a report.
        root = ET.fromstring(self.dex('prowlarr', 'cat', '/config/config.xml'))
        key = root.findtext('ApiKey')
        if not key:
            raise RuntimeError('Prowlarr API key not found')
        base = self.c['prowlarr_url'].rstrip('/')
        health = http_json(base + '/api/v1/health', headers={'X-Api-Key': key})
        # App health messages can contain sensitive tracker URLs; report source/type only.
        for item in health:
            source = re.sub(r'[^A-Za-z0-9_.-]', '', str(item.get('source', 'unknown')))
            level = 'FAIL' if item.get('type') == 'error' else 'WARN'
            self.add('prowlarr:health:' + source, level, 'Prowlarr health issue: ' + source + ' (details in Prowlarr UI)')
        if not health:
            self.add('prowlarr:health', 'PASS', 'Prowlarr reports no health issues')
        statuses = http_json(base + '/api/v1/indexerstatus', headers={'X-Api-Key': key})
        blocked = 0
        for item in statuses:
            value = item.get('disabledTill')
            if value:
                try:
                    stamp = dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
                    blocked += stamp > time.time()
                except ValueError:
                    pass
        self.add('prowlarr:indexers', 'WARN' if blocked else 'PASS', '%d indexer(s) in failure cooldown' % blocked)

    def app_check(self):
        with urllib.request.urlopen(self.c['audiobookshelf_url'], timeout=12) as r:
            if r.status != 200:
                raise RuntimeError('Audiobookshelf HTTP check failed')
        self.add('audiobookshelf:http', 'PASS', 'Audiobookshelf HTTP endpoint responds')

    def mam_check(self):
        name = self.c.get('mam_container')
        if not name:
            return
        # Parse privately; DEBUG can expose session credentials. Never echo raw logs.
        # docker logs often uses stderr, so separately capture both without emitting it.
        p = subprocess.run(['docker', 'logs', '--since', '35m', '--tail', '300', name],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
        logs = p.stdout
        if p.returncode:
            raise RuntimeError('MAM logs unavailable')
        failures = list(re.finditer(r'Invalid session|IP mismatch|No Session Cookie|cookie file is invalid', logs, re.I))
        successes = list(re.finditer(r'"Success"\s*:\s*true', logs))
        if failures and (not successes or failures[-1].start() > successes[-1].start()):
            self.add('mam:session', 'FAIL', 'MAM updater reported an authentication/session error')
        elif re.search(r'"Success"\s*:\s*true', logs):
            self.add('mam:session', 'PASS', 'Recent MAM API success recorded')
        else:
            self.add('mam:session', 'WARN', 'No success confirmation in last 35 minutes of MAM updater logs')

    def disks(self):
        paths = {str(self.project), '/'}
        for obj in self.containers.values():
            for mount in obj.get('Mounts', []):
                if mount.get('Type') == 'bind':
                    paths.add(mount['Source'])
        seen = set()
        for path in sorted(paths):
            if not Path(path).exists():
                self.add('disk:missing:' + path, 'FAIL', 'Missing bind mount: ' + path)
                continue
            dev = os.stat(path).st_dev
            if dev in seen:
                continue
            seen.add(dev)
            s = os.statvfs(path)
            total, avail = s.f_blocks * s.f_frsize, s.f_bavail * s.f_frsize
            level, used, inode_used = disk_result(total, avail, s.f_favail, s.f_files,
                self.c['disk_warn_percent'], self.c['disk_critical_percent'], self.c['disk_min_free_gib'])
            key = 'disk:' + str(dev)
            prev = self.old.get('metrics', {}).get(key)
            growth = ''
            if prev:
                growth = '; used change %+.2f GiB since previous check' % ((prev['available'] - avail) / 2**30)
            self.new_metrics[key] = dict(available=avail, time=time.time())
            self.add(key, level, '%s: %.1f%% used; %.2f GiB available; %.1f%% inodes used%s' % (path, used, avail / 2**30, inode_used, growth))

    def dns_check(self):
        if not self.c.get('check_pihole_dns'):
            return
        ident = os.urandom(2)
        labels = b''.join(bytes([len(v)]) + v.encode() for v in 'example.com'.split('.')) + b'\0'
        packet = ident + struct.pack('!HHHHH', 0x100, 1, 0, 0, 0) + labels + struct.pack('!HH', 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(packet, ('127.0.0.1', 53))
            data, _ = s.recvfrom(4096)
        valid = len(data) >= 12 and data[:2] == ident and data[3] & 15 == 0 and struct.unpack('!H', data[6:8])[0] > 0
        self.add('pihole:dns', 'PASS' if valid else 'FAIL', 'Local DNS query succeeded' if valid else 'Local DNS response unsuccessful')

    def daily_checks(self):
        rows_before = len(self.rows)
        for name, obj in self.containers.items():
            def update_check(name=name, obj=obj):
                image = obj['Config']['Image']
                manifest = json.loads(command(['docker', 'buildx', 'imagetools', 'inspect', image,
                                               '--format', '{{json .Manifest}}'], timeout=45))
                digest = manifest.get('digest')
                if not digest:
                    raise RuntimeError('remote digest unavailable')
                local = json.loads(command(['docker', 'image', 'inspect', obj['Image']]))[0]
                known = {x.rsplit('@', 1)[-1] for x in local.get('RepoDigests', [])}
                if not known:
                    raise RuntimeError('local image digest unavailable')
                candidates = {digest}
                for m in manifest.get('manifests', []):
                    platform = m.get('platform', {})
                    if platform.get('os') == local.get('Os') and platform.get('architecture') == local.get('Architecture'):
                        candidates.add(m.get('digest'))
                newer = not known.intersection(candidates)
                self.add('update:' + name, 'INFO' if newer else 'PASS', name + (': different registry image available (not installed)' if newer else ': running image matches registry tag'))
            self.attempt('update:' + name, update_check)
        def os_updates():
            raw = command(['apt', 'list', '--upgradable'], timeout=30)
            packages = [line.split('/')[0] for line in raw.splitlines() if '[upgradable from:' in line]
            self.add('os:updates', 'INFO' if packages else 'PASS', '%d OS package update(s), based on local APT cache; nothing installed' % len(packages))
            stamps = list(Path('/var/lib/apt/lists').glob('*InRelease'))
            age = (time.time() - max(x.stat().st_mtime for x in stamps)) / 86400 if stamps else 999
            self.add('os:apt-cache', 'WARN' if age > 3 else 'PASS', 'APT repository metadata age: %.1f days (daily checker does not run apt update)' % age)
            self.add('os:reboot', 'WARN' if Path('/var/run/reboot-required').exists() else 'PASS',
                     'OS requests a reboot' if Path('/var/run/reboot-required').exists() else 'No OS reboot marker')
        self.attempt('os:probe', os_updates)
        backup = self.c.get('backup_path')
        if not backup:
            self.add('backup:config', 'WARN', 'No backup_path configured; backup freshness not monitored')
        else:
            def backup_check():
                path = Path(backup).expanduser()
                files = [x for x in path.rglob('*') if x.is_file()] if path.is_dir() else ([path] if path.is_file() else [])
                if not files:
                    self.add('backup:age', 'FAIL', 'Configured backup location contains no files')
                    return
                age = (time.time() - max(x.stat().st_mtime for x in files)) / 86400
                self.add('backup:age', 'WARN' if age > self.c['backup_max_days'] else 'PASS', 'Newest backup file age %.1f days; contents/restore not verified' % age)
            self.attempt('backup:probe', backup_check)
        self.cache = dict(time=time.time(), rows=self.rows[rows_before:])

    def run(self):
        self.container_checks()
        for key, fn in [('vpn:probe', self.vpn_checks), ('qbit:api', self.qbit_checks),
                        ('prowlarr:api', self.prowlarr_checks), ('audiobookshelf:http', self.app_check),
                        ('mam:probe', self.mam_check), ('disk:probe', self.disks), ('pihole:probe', self.dns_check)]:
            self.attempt(key, fn)
        if self.daily:
            self.daily_checks()
        elif self.cache:
            self.rows.extend(self.cache['rows'])
            if time.time() - self.cache['time'] > 36 * 3600:
                self.add('daily:stale', 'WARN', 'Daily update/backup checks older than 36 hours')
        else:
            self.add('daily:missing', 'INFO', 'Daily update/backup checks have not run yet')
        return self.rows


def render(rows):
    severity = max((LEVEL[r['level']] for r in rows), default=0)
    title = ['OK', 'WARNING', 'FAILURE'][severity]
    return 'Media stack: %s\n%s\n\n%s\n' % (title, dt.datetime.now().astimezone().isoformat(timespec='seconds'),
        '\n'.join('[%s] %s' % (r['level'], r['detail']) for r in rows))


def send_email(config, body, subject):
    if not config.get('enabled'):
        raise RuntimeError('SMTP delivery is not configured')
    message = email.message.EmailMessage()
    message['From'], message['To'], message['Subject'] = config['from'], config['to'], subject
    message.set_content(body)
    context = ssl.create_default_context()
    mode = config.get('security', 'starttls')
    if mode not in ('starttls', 'ssl'):
        raise RuntimeError('SMTP security must be starttls or ssl')
    cls = smtplib.SMTP_SSL if mode == 'ssl' else smtplib.SMTP
    kwargs = dict(host=config['host'], port=config['port'], timeout=20)
    if mode == 'ssl':
        kwargs['context'] = context
    with cls(**kwargs) as server:
        if mode == 'starttls':
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
        if config.get('username'):
            server.login(config['username'], config['password'])
        server.send_message(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=str(Path(__file__).with_name('health-config.json')))
    parser.add_argument('--daily', action='store_true')
    parser.add_argument('--dry-run', action='store_true', help='Read-only probes; no state writes, webhooks or email')
    parser.add_argument('--print-report', action='store_true')
    args = parser.parse_args()
    config_path = Path(args.config).expanduser()
    if config_path.stat().st_mode & 0o077:
        raise RuntimeError('config must be private: chmod 600 health-config.json')
    config = json.loads(config_path.read_text())
    state_dir = Path(config['state_dir']).expanduser()
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    with (state_dir / 'run.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | (0 if args.daily else fcntl.LOCK_NB))
        except BlockingIOError:
            return 0
        state_path = state_dir / 'state.json'
        old = json.loads(state_path.read_text()) if state_path.exists() else {}
        monitor = Monitor(config, old, args.daily)
        rows = monitor.run()
        body = render(rows)
        if args.print_report or args.dry_run:
            print(body)
        if args.dry_run:
            return max((LEVEL[r['level']] for r in rows), default=0)
        counts, active = new_issues(rows, old.get('counts', {}), config.get('failure_checks', 2))
        sig = signature(active)
        last = old.get('delivered_signature', signature({}))
        changed = sig != last
        title = 'Media stack recovered' if not active else 'Media stack needs attention'
        active_rows = [r for r in rows if r['id'] in active]
        alert = '\n'.join('[%s] %s' % (r['level'], r['detail']) for r in active_rows) if active else 'Previously reported problems have cleared.'
        delivery = []
        webhook = config.get('ha_webhook_url')
        if webhook:
            try:
                http_json(webhook, dict(notify=changed, title=title, message=alert), {'Content-Type': 'application/json'})
                # Webhook HTTP 200 is only HTTP acceptance, not proof HA automation exists.
                last = sig
            except Exception:
                delivery.append('Home Assistant webhook failed; retry next check')
        else:
            delivery.append('Home Assistant webhook is not configured')
        if args.daily:
            try:
                send_email(config.get('smtp', {}), body, 'Daily ' + body.splitlines()[0])
            except Exception:
                delivery.append('Daily email delivery failed or is not configured; see private SMTP config')
        for text in delivery:
            rows.append(dict(id='delivery', level='WARN', detail=text))
            print(text, file=sys.stderr)
        atomic_json(state_dir / 'latest-report.json', dict(time=time.time(), checks=rows))
        report_path = state_dir / 'latest-report.txt'
        report_path.write_text(render(rows))
        os.chmod(report_path, 0o600)
        atomic_json(state_path, dict(counts=counts, delivered_signature=last,
                    metrics=monitor.new_metrics, daily_cache=monitor.cache))
        return max((LEVEL[r['level']] for r in rows), default=0)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        # Fail loudly for scheduler/deadman detection but do not leak config data.
        print('Monitor failed: ' + (str(e) if isinstance(e, RuntimeError) else type(e).__name__), file=sys.stderr)
        sys.exit(3)
