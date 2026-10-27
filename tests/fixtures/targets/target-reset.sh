#!/bin/bash
# Restore the target's initial state (idempotent; also what the entrypoint runs at every container start):
# host key, authorized key, committed webserver config tree, initial TLS material, empty backup tree, no
# inventory repository copy, a freshly started webserver. The reset stamp is touched last, so
# `find /etc /var/backups -newer /run/target-reset.stamp` lists only what a test changed afterwards.
set -euo pipefail

webserver=$(cat /opt/target/webserver)
config=/opt/target/config/${TARGET_CONFIG:?TARGET_CONFIG is not set}
port=${TARGET_TLS_PORT:?TARGET_TLS_PORT is not set}
fixture=/fixture

case "$webserver" in
    nginx) process=nginx; root=/etc/nginx ;;
    apache) process=apache2; root=/etc/apache2 ;;
    *) echo "unknown webserver: $webserver" >&2; exit 1 ;;
esac

# 1. Stop the webserver whatever its state (a SIGSTOPped master only dies from SIGKILL).
pkill -KILL -x "$process" || true
for _ in $(seq 100); do
    pgrep -x "$process" >/dev/null || break
    sleep 0.1
done
rm -f /run/nginx.pid /run/apache2/apache2.pid

# 2. SSH identity.
install -d -m 0755 -o root -g root /etc/ssh/authorized_keys
install -m 0600 -o root -g root "$fixture/ssh_host_ed25519_key" /etc/ssh/ssh_host_ed25519_key
install -m 0644 -o root -g root "$fixture/authorized_keys" /etc/ssh/authorized_keys/cdeploy

# 3. The committed config tree: the pristine package tree plus this service's vhosts and TLS material.
rm -rf "$root"
cp -a "/opt/target/pristine/$(basename "$root")" "$root"
install -d -m 0755 -o root -g root "$root/ssl"
case "$webserver" in
    nginx)
        install -m 0644 -o root -g root -t /etc/nginx/conf.d "$config"/*.conf
        ;;
    apache)
        install -m 0644 -o root -g root -t /etc/apache2/sites-available "$config"/*.conf
        for site in "$config"/*.conf; do
            ln -s "../sites-available/$(basename "$site")" "/etc/apache2/sites-enabled/$(basename "$site")"
        done
        ;;
esac
for source in "$fixture"/tls/*; do
    name=$(basename "$source")
    mode=0644
    case "$name" in *.key) mode=0600 ;; esac
    install -m "$mode" -o root -g root "$source" "$root/ssl/$name"
done

# 4. Everything a test may have left outside the config tree.
rm -rf /var/backups/cert-dashboard /home/cdeploy/inventory.git
install -d -m 0700 -o root -g root /var/backups/cert-dashboard

# 5. Start the webserver daemonized (sshd stays the foreground process of the container).
case "$webserver" in
    nginx)
        nginx -t
        nginx
        ;;
    apache)
        # envvars is written for non-strict shells (it reads unset variables and unsets HOME): keep it in a subshell.
        (
            set +u
            # shellcheck disable=SC1091
            . /etc/apache2/envvars
            mkdir -p "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR" "$APACHE_LOG_DIR"
            chown "$APACHE_RUN_USER:$APACHE_RUN_GROUP" "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR"
        )
        apache2ctl configtest
        apache2ctl start
        ;;
esac
ready=0
for _ in $(seq 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" != 1 ]; then
    echo "$webserver is not listening on 127.0.0.1:$port" >&2
    exit 1
fi

touch /run/target-reset.stamp
