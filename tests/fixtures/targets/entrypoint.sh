#!/bin/bash
# Target container entrypoint: put the target into its initial state (which starts the daemonized webserver),
# then run sshd in the foreground so a test can stop or kill the webserver without losing SSH.
set -euo pipefail

install -d -m 0755 /run/sshd
/usr/local/bin/target-reset
exec /usr/sbin/sshd -D -e
