#!/usr/bin/env bash
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_dir="$HOME/media-stack-health"
mkdir -p "$install_dir" "$HOME/.config/systemd/user"
chmod 700 "$install_dir"
for name in healthcheck.py health-config.example.json home-assistant-package.yaml README.md; do
  if [[ "$name" == "home-assistant-package.yaml" && -f "$install_dir/health-config.json" && -f "$install_dir/$name" ]]; then
    continue
  fi
  if [[ "$source_dir/$name" != "$install_dir/$name" ]]; then
    cp "$source_dir/$name" "$install_dir/$name"
  fi
done
python3 - "$install_dir" <<'PY'
import json, os, pathlib, secrets, sys
root = pathlib.Path(sys.argv[1])
config_path = root / 'health-config.json'
if not config_path.exists():
    config = json.loads((root/'health-config.example.json').read_text())
    config['project_dir'] = str(pathlib.Path.home()/'audiobookshelf')
    config['state_dir'] = str(root/'state')
    secret = 'media_stack_health_' + secrets.token_hex(24)
    config['ha_webhook_url'] = 'http://YOUR_HA_IP:8123/api/webhook/' + secret
    config_path.write_text(json.dumps(config, indent=2)+'\n')
    (root/'home-assistant-package.yaml').write_text((root/'home-assistant-package.yaml').read_text().replace('REPLACE_WITH_RANDOM_WEBHOOK', secret))
os.chmod(config_path, 0o600)
units = pathlib.Path.home()/'.config/systemd/user'
for kind, flag in [('check',''), ('daily',' --daily')]:
    (units/('media-stack-health-%s.service'%kind)).write_text('''[Unit]
Description=Media stack health %s
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 "%s/healthcheck.py" --config "%s/health-config.json"%s
TimeoutStartSec=20min
SuccessExitStatus=1 2
UMask=0077
''' % (kind, root, root, flag))
(units/'media-stack-health-check.timer').write_text('''[Unit]
Description=Check media stack every 15 minutes
[Timer]
OnCalendar=*:0/15
Persistent=true
RandomizedDelaySec=30
[Install]
WantedBy=timers.target
''')
(units/'media-stack-health-daily.timer').write_text('''[Unit]
Description=Daily media stack email at 8 AM Eastern
[Timer]
OnCalendar=*-*-* 08:00:00 America/New_York
Persistent=true
[Install]
WantedBy=timers.target
''')
PY
printf '%s\n' 'Prepared monitor and timers. Nothing is enabled or sent yet.' 'Edit ~/media-stack-health/health-config.json and follow README.md.'
