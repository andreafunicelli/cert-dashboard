# Test-only SSH-enabled webserver target (docker-compose.test.yml, profile "ssh-targets"); never shipped.
# One image per webserver (--build-arg WEBSERVER=nginx|apache); the compose service picks its vhost set with
# TARGET_CONFIG and gets host key, authorized key and TLS material from the read-only /fixture bind.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

ARG WEBSERVER=nginx
ENV DEBIAN_FRONTEND=noninteractive

# Packages follow the pinned Debian base at build time (not individually pinned, to survive security updates).
RUN set -eux; \
    case "$WEBSERVER" in nginx) web=nginx ;; apache) web=apache2 ;; *) echo "unknown WEBSERVER" >&2; exit 1 ;; esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends openssh-server openssh-sftp-server sudo python3 openssl git procps "$web"; \
    rm -rf /var/lib/apt/lists/*

# The deploy user of the dedicated privilege-escalation rule (spec 6.4): key-only login, no password at all
# ("*" is not a valid hash, so no password matches, yet sshd does not treat the account as locked out).
RUN set -eux; \
    useradd --uid 2000 --create-home --home-dir /home/cdeploy --shell /bin/bash cdeploy; \
    usermod -p '*' cdeploy; \
    printf 'cdeploy ALL=(root) NOPASSWD: ALL\n' > /etc/sudoers.d/cdeploy; \
    chmod 0440 /etc/sudoers.d/cdeploy; \
    visudo -c; \
    rm -f /etc/ssh/ssh_host_*; \
    mkdir -p /etc/ssh/authorized_keys /run/sshd /opt/target/pristine
COPY sshd_config /etc/ssh/sshd_config

# Pristine webserver configuration (Debian layout kept, default sites removed); target-reset restores it
# exactly and then overlays the service's committed vhosts and TLS material.
RUN set -eux; \
    if [ "$WEBSERVER" = nginx ]; then \
        rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf; \
        cp -a /etc/nginx /opt/target/pristine/nginx; \
    else \
        a2enmod ssl; \
        rm -f /etc/apache2/sites-enabled/* /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/default-ssl.conf; \
        printf 'Listen 80\nListen 18445 https\n' > /etc/apache2/ports.conf; \
        printf 'ServerName localhost\n' > /etc/apache2/conf-available/servername.conf; \
        a2enconf servername; \
        cp -a /etc/apache2 /opt/target/pristine/apache2; \
    fi; \
    printf '%s\n' "$WEBSERVER" > /opt/target/webserver

COPY nginx /opt/target/config/nginx
COPY apache /opt/target/config/apache
COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint
COPY --chmod=0755 target-reset.sh /usr/local/bin/target-reset

ENTRYPOINT ["/usr/local/bin/entrypoint"]
