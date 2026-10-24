# Media stack health monitor

Prepared for the supplied Compose file: audiobookshelf, vpn_gateway, qbittorrent,
prowlarr, mam_sync_agent. Runs on the Pi host, outside the VPN. Python standard
library only; requires python3, Docker CLI, Docker Buildx, and user Docker access.
Do not add this monitor to Gluetun's network namespace: the independent host-IP
comparison would no longer be useful.

## Behavior

- Every 15 minutes: local/app/VPN/storage checks and a quiet Home Assistant
  heartbeat. Healthy checks do not create notifications or emails.
- New persistent problems or changed severity: one Home Assistant notification.
  Most problems require two consecutive failing checks (15–30 minutes detection).
  Wrong VPN namespace, host-matching egress, wrong qBittorrent interface, and
  newly observed restarts notify immediately. Disk FAIL at under 2 GiB free,
  >=90% blocks or inodes; WARN at >=80%. Thresholds are configurable.
- Same unresolved problem: no repeated alerts. Clearing an alerted problem or
  changing the active set of problems sends an updated/recovery notification.
- Daily at 08:00 America/New_York: fresh image/OS/backup checks and one email
  containing the full report. Timers catch up after downtime. Registry changes
  are INFO in the daily report, not push alarms; registry-check failures are WARN.
- Separate HA watchdog: after 35 minutes without a heartbeat, reports one missed
  monitor alert (evaluated every five minutes), and reports heartbeat recovery.
- Local latest-report.txt and latest-report.json are updated on every normal run.
- No container restarts, image pulls, package installation, torrent changes,
  forced tracker announces, pruning, or backup creation. No raw logs, torrent
  names, MAM cookies, app keys, or container environments in reports.

## Install on the Pi

Download media-stack-health.zip to your computer and copy it to the Pi, e.g.:

```powershell
scp "$env:USERPROFILE\Downloads\media-stack-health.zip" elohip@192.168.1.252:~/
```

Then SSH into the Pi:

```bash
python3 -m zipfile -e ~/media-stack-health.zip ~/media-stack-health-package
bash ~/media-stack-health-package/media-stack-health/install.sh
nano ~/media-stack-health/health-config.json
```

The installer prepares files and user systemd units; it enables no timers and
sends no messages. It creates a random webhook ID locally, inserts the matching
ID into the HA package and private config. It leaves an existing private config
alone. Do not rerun the installer to change a webhook; edit both matching files.
Reinstall preserves the generated HA package when a private config already exists.

Edit these private settings:

- ha_webhook_url: replace YOUR_HA_IP with HA's current reachable LAN/IoT IP.
  Keep the generated final path unchanged. No HA access token is needed.
- smtp: set enabled=true, host, port, security (starttls/587 or ssl/465), from,
  to, username and password/app-password. Passwords stay in this chmod-600 JSON
  file, not in Compose or command arguments. Many providers require an app
  password or SMTP relay; providers requiring OAuth-only auth are not supported
  by this small sender. Ask for provider-specific setup before entering secrets.
- backup_path: an existing backup file or folder. Empty produces a warning.
  Freshness is based on newest file mtime, not on backup integrity or restoreability.
- If you have intentionally removed the MAM updater, remove mam_sync_agent from
  containers and set mam_container to null. The supplied Compose includes it.
- check_pihole_dns: true queries example.com via 127.0.0.1:53. Set false if local
  Pi-hole DNS was intentionally removed or is not listening on loopback.

Never share health-config.json, .env, generated webhook URL, or SMTP credentials.
The included health-config.example.json is safe to share. Do not use an
untrusted SMTP server: reports contain operational information and VPN exit IPs.

## Home Assistant setup

Copy the generated ~/media-stack-health/home-assistant-package.yaml to HA's
/config/packages/media_stack_health.yaml using your normal HA file editor/share.
If package loading is not already enabled, merge the following into the EXISTING
homeassistant block in /config/configuration.yaml (do not create a duplicate):

```yaml
homeassistant:
  packages: !include_dir_named packages
```

The package creates two helpers, one notification script, and two automations.
Use HA's configuration check and restart HA to load the package and helpers.
The webhook is POST-only and local_only=true. Your current LAN-to-IoT allowance
should permit Pi-to-HA port 8123; verify connectivity after any VLAN move.

By default messages appear in HA's Notifications panel. For iPhone push, find
your exact notify.mobile_app_* action in Developer Tools > Actions. Uncomment
and replace the optional notify action in the notification script in the package.
Keep the persistent notification too. Do not guess the mobile action name.

Test real end-to-end notification delivery: from the private config, copy the
webhook URL LOCALLY into a request. Easiest: run this Python on the Pi after HA
has loaded the package. It reads the secret without displaying it:

```bash
python3 - <<'PY'
import json, pathlib, urllib.request
c=json.loads((pathlib.Path.home()/'media-stack-health/health-config.json').read_text())
payload=json.dumps({'notify':True,'title':'Media health setup test','message':'Pi to Home Assistant notification test.'}).encode()
r=urllib.request.Request(c['ha_webhook_url'], data=payload, headers={'Content-Type':'application/json'})
with urllib.request.urlopen(r, timeout=10) as response:
    print('HTTP status:',response.status)
PY
```

Confirm an actual notification arrives and the helper's last-check time changes.
HA may return HTTP 200 for an unregistered webhook: HTTP acceptance alone is NOT
proof that the automation ran. This also starts the missed-heartbeat watchdog;
finish enabling the monitor within 35 minutes or expect a watchdog alert.

## First diagnostic run (no sends or saved health state)

```bash
python3 ~/media-stack-health/healthcheck.py --daily --dry-run
```

This uses read-only probes, creates the private state directory/lock file if
needed, and prints a report. It does not write reports/state, notify HA, or email.
WARN/FAIL until missing configuration is supplied is expected. Docker image
checks use buildx imagetools inspect and compare registry/index or native-platform
manifest digests to the RUNNING container image's RepoDigests, not to a newer
unused local image. This is a tag-change signal, not release-note/security analysis.
If Buildx is unavailable, the report explicitly warns; it never claims up-to-date.

The OS package list is based on the existing APT cache. Cache older than three
days warns; use your normal OS maintenance to refresh it (sudo apt-get update).
The monitor deliberately does not refresh privileged package metadata itself.

## Enable scheduling

First verify the report and end-to-end HA notification. Configure SMTP, then
run a deliberate first daily report (this SENDS the daily email):

```bash
python3 ~/media-stack-health/healthcheck.py --daily --print-report
```

After the email arrives:

```bash
sudo loginctl enable-linger "$USER"
systemctl --user daemon-reload
systemctl --user enable --now media-stack-health-check.timer media-stack-health-daily.timer
systemctl --user list-timers 'media-stack-health-*'
```

Linger lets user services run when SSH is disconnected and after reboot. These
units run as your user (which already has Docker access). They do not run as root.
Exit 1/2 means checks found WARN/FAIL and is accepted by the service; exit 3 is an
execution/configuration failure. Daily runs wait for an in-progress check's lock;
ordinary checks skip overlap. A 20-minute service timeout bounds stalled jobs.

Inspect:

```bash
cat ~/media-stack-health/state/latest-report.txt
journalctl --user -u media-stack-health-check.service -u media-stack-health-daily.service --since today
```

Stop scheduling:

```bash
systemctl --user disable --now media-stack-health-check.timer media-stack-health-daily.timer
```

## What this proves (and does not)

- Container status is supplemented by live app probes. qBittorrent preferences
  and transfer/torrent stats use its localhost authentication bypass. Prowlarr's
  API key is read internally from its config.xml, never copied to reports.
- Both qBittorrent and Prowlarr network namespaces must match the current
  Gluetun namespace. Their external IPv4 probes must match Gluetun's recorded
  public IP and differ from the host public IP. An unavailable probe is WARN,
  never silently a PASS. If the host itself intentionally uses a VPN this design
  needs adjustment. Every healthy run makes three small public IP lookups.
- WireGuard handshake checked when the wg executable is available; otherwise
  explicitly INFO with live health/namespace/egress checks as the evidence.
- qBittorrent must bind tun0, match the forwarded port, and disable random port
  and UPnP. Its own connectability status is included, but does not replace an
  external MAM connectivity test. Deliberate kill-switch/reconnect testing is a
  separate maintenance test and is not automatically disruptive every 15 minutes.
- MAM updater logs are scanned privately for recent success/auth failures. A lack
  of success text warns instead of claiming verified authentication. If logging
  changes, adjust the parser. DEBUG is currently enabled in supplied Compose;
  remove DEBUG entirely if you want to disable shell trace (DEBUG=0 can still
  count as enabled). Do not share updater logs without checking for cookies.
- Disk/inode checks cover project/root and container bind-mount filesystems,
  deduplicated by device. Unexpected root-disk fallback after an external drive
  disappears is not fully detected; use dedicated mount checks if you add a disk.
- HA can notice a missing Pi heartbeat, but a simultaneous HA outage prevents HA
  alerts. Email is sent by the Pi, so a dead Pi cannot send the daily report.
- SMTP/webhook failures go to local reports/journal; HA signature is not marked
  delivered after a failed HTTP request, so it retries next check. SMTP failures
  are not retried automatically until the next daily/manual daily run.
- Backup age is checked daily; no backup is created by this package. The first
  live report may therefore warn until you select an actual backup location.

## Validation performed

16 automated tests cover disk/inode/absolute thresholds, consecutive-failure
filtering, immediate routing alerts, severity signatures/recovery, namespace
mismatch, port mismatch, private atomic state, redacted subprocess errors,
SMTP-disabled behavior, dry-run no sends/state writes, and webhook delivery
retry. Live Pi, Proton, MAM, HA, registry, and email tests must run on your host.

## Primary references

- https://www.home-assistant.io/docs/automation/trigger/ (local POST webhooks)
- https://www.home-assistant.io/integrations/persistent_notification/
- https://www.home-assistant.io/integrations/input_datetime/
- https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/
- https://prowlarr.com/docs/api/
- https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-5.0)
- https://github.com/qdm12/gluetun-wiki/blob/main/setup/advanced/vpn-port-forwarding.md
