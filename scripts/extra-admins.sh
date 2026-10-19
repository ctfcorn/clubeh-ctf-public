#!/usr/bin/env bash
# Re-provision the extra admin seats (admin2..adminN) after a redeploy, or add
# new ones. Idempotent: signs any missing certs, (re)builds profiles, pushes CCD
# files to the gateway, and widens the gateway firewall's admin rule to
# ADMIN_VPN_RANGE. Reads the roster from ctf_secrets.env (ADMIN_SEATS /
# ADMIN_VPN_RANGE). Run from the repo root: ./scripts/extra-admins.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PKI_DIR=pki; PROFILE_DIR=profiles; STATE_FILE=ctf_state.json; SECRETS_FILE=ctf_secrets.env
KEY="${CTF_SSH_KEY:-$HOME/.ssh/ctf_ed25519}"; KH=.ssh_known_hosts
CERT_DAYS="$(grep -E '^CERT_DAYS=' ctf_manager.sh | head -1 | sed 's/[^0-9]//g')"; CERT_DAYS="${CERT_DAYS:-120}"
GW_PUB="$(jq -r '.nodes.gateway.public_ip' "$STATE_FILE")"
SEATS="$(sed -n 's/^ADMIN_SEATS="\(.*\)"$/\1/p' "$SECRETS_FILE")"
RANGE="$(sed -n 's/^ADMIN_VPN_RANGE="\(.*\)"$/\1/p' "$SECRETS_FILE")"
[ -n "$GW_PUB" ] && [ -n "$SEATS" ] && [ -n "$RANGE" ] || { echo "missing state/roster" >&2; exit 1; }
sshg() { ssh -i "$KEY" -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 root@"$GW_PUB" "$@"; }

prof() { # build profiles/<name>.ovpn
  local n="$1"
  { printf 'client\ndev tun\nproto udp\nremote %s 1194\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nauth SHA256\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM:AES-128-GCM\ntls-version-min 1.2\nverb 3\n' "$GW_PUB"
    echo "<ca>"; cat "$PKI_DIR/ca/ca.crt"; echo "</ca>"
    echo "<cert>"; openssl x509 -in "$PKI_DIR/clients/$n.crt"; echo "</cert>"
    echo "<key>"; cat "$PKI_DIR/clients/$n.key"; echo "</key>"
    echo "<tls-crypt>"; cat "$PKI_DIR/tls-crypt.key"; echo "</tls-crypt>"
  } > "$PROFILE_DIR/$n.ovpn"; chmod 600 "$PROFILE_DIR/$n.ovpn"
}

for seat in $SEATS; do
  name="${seat%%:*}"; ip="${seat##*:}"
  [ "$name" = "admin" ] && continue   # primary admin already provisioned by deploy
  if [ ! -f "$PKI_DIR/clients/$name.crt" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$PKI_DIR/clients/$name.key"; chmod 600 "$PKI_DIR/clients/$name.key"
    openssl req -new -key "$PKI_DIR/clients/$name.key" -out "$PKI_DIR/clients/$name.csr" -subj "/CN=$name" -sha256
    openssl ca -batch -config "$PKI_DIR/ca/openssl.cnf" -extensions client_cert -days "$CERT_DAYS" -notext \
      -in "$PKI_DIR/clients/$name.csr" -out "$PKI_DIR/clients/$name.crt" 2>/dev/null
    rm -f "$PKI_DIR/clients/$name.csr"; echo "signed $name"
  fi
  prof "$name"
  sshg "printf 'ifconfig-push %s 255.255.255.0\npush \"route 10.0.0.0 255.255.255.0\"\n' '$ip' > /etc/openvpn/server/ccd/$name"
  echo "provisioned $name -> $ip"
done

# widen the gateway firewall admin rule to the range, persistently
sshg "cp -a /usr/local/sbin/ctf-firewall.sh /usr/local/sbin/ctf-firewall.sh.bak-\$(date +%s) 2>/dev/null; \
      sed -i 's|^define VPN_ADMIN  = .*|define VPN_ADMIN  = $RANGE|' /usr/local/sbin/ctf-firewall.sh; \
      systemctl restart ctf-firewall.service; sleep 1; grep -E 'define VPN_ADMIN' /etc/nftables.conf"
echo "done: admin range = $RANGE; profiles in $PROFILE_DIR/"
