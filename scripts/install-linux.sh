#!/bin/sh
set -eu

# Reviewed local artifacts only. Do not put credentials in command arguments.
if [ "$(id -u)" -ne 0 ]; then echo 'Run the installer as root.' >&2; exit 1; fi
if [ "$(uname -s)" != Linux ] || [ "$#" -ne 3 ]; then
  echo 'Usage: install-linux.sh /absolute/handkey /absolute/real/op AGENT_USER' >&2
  exit 1
fi
handkey_binary=$1
op_binary=$2
agent_user=$3
case "$handkey_binary:$op_binary" in /*:/*) ;; *) echo 'Executable paths must be absolute.' >&2; exit 1;; esac
test -f "$handkey_binary" && test -x "$handkey_binary"
test -f "$op_binary" && test -x "$op_binary"
id "$agent_user" >/dev/null
command -v systemctl >/dev/null

getent group handkey >/dev/null || groupadd --system handkey
id handkey >/dev/null 2>&1 || useradd --system --gid handkey --home-dir /var/lib/handkey --shell /usr/sbin/nologin handkey
usermod -a -G handkey "$agent_user"
install -d -o root -g root -m 0755 /opt/handkey
install -d -o root -g handkey -m 0750 /etc/handkey
install -d -o handkey -g handkey -m 0700 /var/lib/handkey
install -o root -g root -m 0555 "$handkey_binary" /opt/handkey/handkey
install -o root -g root -m 0555 "$op_binary" /opt/handkey/op

if [ ! -e /etc/handkey/server.env ]; then
  umask 027
  cat > /etc/handkey/server.env <<'ENV'
HANDKEY_LISTEN=
HANDKEY_TLS_CERT=
HANDKEY_TLS_KEY=
HANDKEY_ORIGINS=
# Set to --bootstrap only together with HANDKEY_LISTEN. Without a listen
# address, registration is served on the agent socket.
HANDKEY_BOOTSTRAP=
ENV
  chown root:handkey /etc/handkey/server.env
  chmod 0640 /etc/handkey/server.env
fi

cat > /etc/systemd/system/handkey.service <<'UNIT'
[Unit]
Description=Handkey approval broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=handkey
Group=handkey
EnvironmentFile=/etc/handkey/server.env
RuntimeDirectory=handkey
RuntimeDirectoryMode=0750
UMask=0077
ExecStart=/opt/handkey/handkey serve --state-dir /var/lib/handkey --op /opt/handkey/op --socket /run/handkey/agent.sock --socket-mode 0660 --listen ${HANDKEY_LISTEN} --tls-cert ${HANDKEY_TLS_CERT} --tls-key ${HANDKEY_TLS_KEY} --origins ${HANDKEY_ORIGINS} $HANDKEY_BOOTSTRAP
Restart=on-failure
RestartSec=5
LimitCORE=0
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/handkey

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/handkey.service
systemctl daemon-reload
printf '%s\n' 'Installed. Configure /etc/handkey/server.env, then start handkey.service.'
printf '%s\n' 'Start a new login session for the agent user to apply socket group access.'
