#!/bin/sh
# Set permissions on existing canonical files; never copy or print secret values.
set -eu
if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'Run this ownership installer as root on the Linux deployment host.' >&2
  exit 1
fi
secret_dir=${1:-/etc/cert-dashboard/secrets}
case "$secret_dir" in
  /*) ;;
  *) printf '%s\n' 'Secret directory must be an absolute path.' >&2; exit 1 ;;
esac
if [ ! -d "$secret_dir" ] || [ -L "$secret_dir" ]; then
  printf '%s\n' 'Create a real secret directory and provision its secret files first.' >&2
  exit 1
fi
for name in master_key session_secret db_password db_owner_password; do
  if [ ! -f "$secret_dir/$name" ] || [ -L "$secret_dir/$name" ]; then
    printf 'Required regular secret file missing: %s\n' "$name" >&2
    exit 1
  fi
done
for name in master_key session_secret db_password db_owner_password ansible_ssh_key ansible_vault_password inventory_git_token smtp_password; do
  if [ -L "$secret_dir/$name" ]; then
    printf 'Refusing symlink secret: %s\n' "$name" >&2
    exit 1
  fi
done
chown 0:0 "$secret_dir"
chmod 0711 "$secret_dir"
for name in master_key session_secret ansible_ssh_key ansible_vault_password inventory_git_token smtp_password; do
  if [ -f "$secret_dir/$name" ]; then
    chown 10001:10001 "$secret_dir/$name"
    chmod 0400 "$secret_dir/$name"
  fi
done
chown 10001:999 "$secret_dir/db_password"
chmod 0440 "$secret_dir/db_password"
chown 999:999 "$secret_dir/db_owner_password"
chmod 0400 "$secret_dir/db_owner_password"
printf '%s\n' 'Secret ownership and modes applied; no secret values were read or copied.'
