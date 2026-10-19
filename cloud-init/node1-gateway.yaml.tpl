#cloud-config
# =============================================================================
# NODE 1 - GATEWAY / VPN / EGRESS PROXY
#   VPC 10.0.0.2 (+1:1 NAT public)  |  OpenVPN 1194/udp  |  nftables choke point
#   Roles: player VPN entry, HTTP proxy + DNS for the VPC-only nodes, bastion.
#   Linode VPC routes at L3 and will NOT transit packets through a member
#   Linode (verified: forwarded packets never reach this host). So the private
#   nodes get out via a proxy whose destination IS this host, which does work.
# Placeholders __X__ are substituted by ctf_manager.sh before base64 encoding.
# =============================================================================
hostname: ctf-gateway
fqdn: ctf-gateway.ctf.local
preserve_hostname: false
manage_etc_hosts: true

package_update: true
package_upgrade: true
packages:
  - openvpn
  - nftables
  - curl
  - jq
  - chrony
  - unattended-upgrades
  - rsyslog
  - gnupg
  - tinyproxy
  - dnsmasq

users:
  - name: root
    lock_passwd: false

write_files:
  # ---- Operator SSH allow-list. Read by ctf-firewall.sh; rewritten by
  # ---- `ctf_manager.sh status` when you move to a new network.
  - path: /etc/ctf/admin_src_v4
    permissions: '0644'
    content: __ADMIN_SRC_V4__
  - path: /etc/ctf/admin_src_v6
    permissions: '0644'
    content: __ADMIN_SRC_V6__

  # ---- Shared secret the instance-ACL poller uses to read the isolation map
  # ---- from CTFd. Root-only; never leaves this host.
  - path: /etc/ctf/isolation.token
    encoding: b64
    permissions: '0600'
    owner: root:root
    content: __ISOLATION_TOKEN_B64__

  # ---- Egress proxy for the VPC-only nodes. Bound to the VPC address only.
  # ---- The challenge host's access is cut by nftables after bootstrap.
  - path: /etc/tinyproxy/tinyproxy.conf
    permissions: '0644'
    content: |
      Port 3128
      Listen __GW_VPC_IP__
      Allow __CHAL_VPC_IP__
      Allow __SIEM_VPC_IP__
      ConnectPort 443
      ConnectPort 80
      MaxClients 50
      Timeout 600
      LogLevel Warning
      LogFile "/var/log/tinyproxy/tinyproxy.log"
      DisableViaHeader Yes

  # ---- DNS forwarder for the VPC-only nodes (they cannot reach 1.1.1.1). ---
  - path: /etc/dnsmasq.d/ctf.conf
    permissions: '0644'
    content: |
      listen-address=__GW_VPC_IP__
      bind-interfaces
      no-resolv
      server=1.1.1.1
      server=8.8.8.8
      cache-size=1000

  # ---- NTP for the VPC-only nodes, which have no other time source --------
  - path: /etc/chrony/conf.d/ctf.conf
    permissions: '0644'
    content: |
      allow __VPC_CIDR__
      local stratum 10

  # ---- PKI: signed locally, CA PRIVATE KEY IS NEVER SHIPPED TO ANY NODE ------
  - path: /etc/openvpn/server/ca.crt
    encoding: b64
    permissions: '0644'
    owner: root:root
    content: __CA_CRT_B64__
  - path: /etc/openvpn/server/server.crt
    encoding: b64
    permissions: '0644'
    owner: root:root
    content: __SERVER_CRT_B64__
  - path: /etc/openvpn/server/server.key
    encoding: b64
    permissions: '0600'
    owner: root:root
    content: __SERVER_KEY_B64__
  - path: /etc/openvpn/server/tls-crypt.key
    encoding: b64
    permissions: '0600'
    owner: root:root
    content: __TLS_CRYPT_B64__
  - path: /etc/openvpn/server/crl.pem
    encoding: b64
    permissions: '0644'
    owner: root:root
    content: __CRL_B64__

  # ---- Patch policy: security origin only, never auto-reboot mid-event. ----
  - path: /etc/apt/apt.conf.d/52ctf-unattended
    permissions: '0644'
    content: |
      Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
      };
      Unattended-Upgrade::Automatic-Reboot "false";
      Unattended-Upgrade::Remove-Unused-Dependencies "true";

  # ---- OpenVPN server ------------------------------------------------------
  - path: /etc/openvpn/server/server.conf
    permissions: '0600'
    owner: root:root
    content: |
      port 1194
      proto udp
      dev tun
      topology subnet
      server __VPN_NET__ __VPN_MASK__

      ca   /etc/openvpn/server/ca.crt
      cert /etc/openvpn/server/server.crt
      key  /etc/openvpn/server/server.key
      dh   none
      tls-crypt /etc/openvpn/server/tls-crypt.key

      # Revocation: `ctf_manager.sh -> [4] Revoke Player` regenerates this file
      # and SIGHUPs the daemon, kicking the certificate mid-event.
      crl-verify /etc/openvpn/server/crl.pem

      # ANTI-CHEAT RULE 2.1: client-to-client is NOT enabled. With this
      # directive absent, OpenVPN routes every client packet through the
      # kernel, where the nftables forward chain drops VPN->VPN traffic.
      # Do not add `client-to-client` - it would bypass nftables entirely.

      # ccd-exclusive: a client whose CN has no ccd file is REJECTED. This
      # makes the static-IP map authoritative - no unmapped client gets on.
      client-config-dir /etc/openvpn/server/ccd
      ccd-exclusive

      # Routes pushed to every client. Deliberately NOT redirect-gateway:
      # players' general internet traffic must not transit this host.
      push "route __CTFD_VPC_IP__ 255.255.255.255"
      push "route __CHAL_VPC_IP__ 255.255.255.255"

      keepalive 10 120
      cipher AES-256-GCM
      data-ciphers AES-256-GCM:AES-128-GCM
      auth SHA256
      tls-version-min 1.2
      tls-cert-profile preferred
      remote-cert-tls client

      max-clients __MAX_CLIENTS__
      user nobody
      group nogroup
      persist-key
      persist-tun
      explicit-exit-notify 1

      # Localhost-only management socket. `[4] Revoke Player` uses this to
      # disconnect a cheater's live session immediately; the CRL alone would
      # only stop them at their next handshake.
      management 127.0.0.1 7505

      script-security 2
      client-connect    /usr/local/sbin/ovpn-connect.sh
      client-disconnect /usr/local/sbin/ovpn-disconnect.sh

      status /var/log/openvpn/status.log 10
      log-append /var/log/openvpn/openvpn.log
      verb 3

  # ---- Attribution hooks: CN <-> VPN IP, shipped to Wazuh via syslog -------
  - path: /usr/local/sbin/ovpn-connect.sh
    permissions: '0755'
    owner: root:root
    content: |
      #!/bin/bash
      logger -t ctf-vpn -p auth.notice \
        "VPN_CONNECT cn=${common_name} vpn_ip=${ifconfig_pool_remote_ip} src=${trusted_ip}:${trusted_port}"
      exit 0
  - path: /usr/local/sbin/ovpn-disconnect.sh
    permissions: '0755'
    owner: root:root
    content: |
      #!/bin/bash
      logger -t ctf-vpn -p auth.notice \
        "VPN_DISCONNECT cn=${common_name} vpn_ip=${ifconfig_pool_remote_ip} rx=${bytes_received} tx=${bytes_sent}"
      exit 0

  # ---- Static VPN IP map (client-config-dir) -------------------------------
  - path: /usr/local/sbin/ctf-gen-ccd.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/bash
      # RULE 2.4: admin pinned to __VPN_ADMIN_IP__; players pinned into the
      # __PLAYER_FIRST__-.. block. nftables keys its ACLs off these addresses,
      # so this map IS the access-control policy.
      set -euo pipefail
      CCD=/etc/openvpn/server/ccd
      rm -rf "$CCD"; mkdir -p "$CCD"

      # Admin: static IP + a route to the whole VPC (incl. Wazuh 10.0.0.5).
      cat > "$CCD/admin" <<EOF
      ifconfig-push __VPN_ADMIN_IP__ __VPN_MASK__
      push "route __VPC_CIDR_NET__ __VPN_MASK__"
      EOF

      # Players: static IP only. They receive no VPC-wide route; the pushed
      # routes in server.conf limit them to CTFd + the challenge host.
      BASE_LAST=__PLAYER_BASE_LAST__
      for i in $(seq 1 __PLAYER_COUNT__); do
        n=$(printf '%02d' "$i")
        printf 'ifconfig-push __VPN_OCTETS__.%d __VPN_MASK__\n' "$((BASE_LAST + i - 1))" \
          > "$CCD/player$n"
      done
      chmod 0644 "$CCD"/*
      logger -t ctf-vpn "ccd map regenerated: 1 admin + __PLAYER_COUNT__ players"

  # ---- The firewall. Generated at boot so the WAN iface is detected, not -----
  # ---- guessed. Node 1 runs no Docker, so a policy-drop forward chain is safe.
  - path: /usr/local/sbin/ctf-firewall.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/bash
      set -euo pipefail
      WAN=$(ip -4 route show default | awk '{print $5; exit}')
      [ -n "$WAN" ] || { echo "no default route yet" >&2; exit 1; }
      ADM4=$(tr -d '\n' < /etc/ctf/admin_src_v4)
      ADM6=$(tr -d '\n' < /etc/ctf/admin_src_v6)
      # Bootstrap-only WAN forwarding for the challenge host. Once
      # ctf_manager.sh drops the flag file this rule is never emitted again,
      # so a gateway reboot cannot silently restore challenge internet access.
      # Per-team instance ACL. When the flag file exists, players may reach ONLY
      # the instance ports their own team owns (the poller fills the set); the
      # rest of the range is dropped. Without it, the old blanket rule applies.
      ISO_TCP='ip saddr $VPN_PLAYERS ip daddr $CTFD tcp dport $FRP_PORTS accept'
      ISO_UDP='ip saddr $VPN_PLAYERS ip daddr $CTFD udp dport $FRP_PORTS accept'
      if [ -f /etc/ctf/instance-isolation ]; then
        # Two rules per protocol. `limit` is a MATCHER: if the log rule also
        # carried the drop verdict, packets over the rate would stop matching
        # and be ACCEPTED. So rule one logs (rate-limited, no verdict, falls
        # through) and rule two drops unconditionally.
        ISO_TCP='ip saddr $VPN_PLAYERS ip daddr $CTFD tcp dport $FRP_PORTS limit rate 10/second burst 20 packets log prefix "ctf-drop NOT_YOUR_INSTANCE "
          ip saddr $VPN_PLAYERS ip daddr $CTFD tcp dport $FRP_PORTS counter drop comment "NOT_YOUR_INSTANCE"'
        ISO_UDP='ip saddr $VPN_PLAYERS ip daddr $CTFD udp dport $FRP_PORTS limit rate 10/second burst 20 packets log prefix "ctf-drop NOT_YOUR_INSTANCE "
          ip saddr $VPN_PLAYERS ip daddr $CTFD udp dport $FRP_PORTS counter drop comment "NOT_YOUR_INSTANCE"'
      fi
      CHAL_WAN_RULE='ip saddr $CHAL tcp dport 3128 accept comment "CHAL_WAN_BOOTSTRAP"'
      CHAL_DNS_RULE='ip saddr $CHAL udp dport 53 accept comment "CHAL_DNS_BOOTSTRAP"'
      if [ -f /etc/ctf/chal-wan-revoked ]; then
        CHAL_WAN_RULE='# challenge-host proxy access revoked post-deploy'
        CHAL_DNS_RULE='# challenge-host DNS access revoked post-deploy'
      fi

      cat > /etc/nftables.conf <<EOF
      #!/usr/sbin/nft -f
      # Generated by ctf-firewall.sh - do not edit by hand.
      flush ruleset

      define WAN        = "$WAN"
      define VPN_NET    = __VPN_NET__/24
      define VPN_ADMIN  = __VPN_ADMIN_IP__
      define VPN_PLAYERS= __PLAYER_FIRST__-__PLAYER_LAST__
      define VPC_NET    = __VPC_CIDR__
      define CTFD       = __CTFD_VPC_IP__
      define CHAL       = __CHAL_VPC_IP__
      define SIEM       = __SIEM_VPC_IP__
      define CHAL_PORTS = __CHAL_PORT_LO__-__CHAL_PORT_HI__
      define FRP_PORTS  = __FRP_PORT_LO__-__FRP_PORT_HI__

      table inet ctf_filter {
        # (source address . instance port) pairs the poller keeps in sync with
        # CTFd. `timeout` means a missed teardown expires on its own instead of
        # leaving a hole open.
        set player_instance {
          type ipv4_addr . inet_service
          flags timeout
        }

        chain input {
          type filter hook input priority filter; policy drop;
          ct state established,related accept
          ct state invalid drop
          iif lo accept

          icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
          icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, packet-too-big, destination-unreachable, time-exceeded } accept

          # OpenVPN: the one public service on this box.
          udp dport 1194 accept

          # SSH: operator source IPs (Linode Cloud Firewall enforces this too,
          # outside the instance, so a host-level flush cannot open it up).
          tcp dport 22 ip  saddr { $ADM4 } accept
          tcp dport 22 ip6 saddr { $ADM6 } accept
          # Services this host provides to the VPC-only nodes: NTP, DNS, and
          # the egress proxy. Challenge-host lines are omitted once revoked.
          ip saddr \$VPC_NET udp dport 123 accept
          ip saddr \$SIEM udp dport 53 accept
          ip saddr \$SIEM tcp dport 3128 accept comment "SIEM_WAN"
          $CHAL_DNS_RULE
          $CHAL_WAN_RULE
          # SSH over the tunnel, admin profile only.
          tcp dport 22 ip saddr \$VPN_ADMIN accept

          # VPC peers may reach nothing on this host except ICMP (above).
          counter drop
        }

        chain forward {
          type filter hook forward priority filter; policy drop;
          ct state established,related accept
          ct state invalid drop

          # ---- RULE 2.2: METADATA BLACKHOLE ---------------------------------
          # Nothing transiting this gateway may reach cloud metadata, v4 or v6.
          ip  daddr 169.254.0.0/16 limit rate 5/second burst 10 packets log prefix "ctf-drop METADATA "
          ip  daddr 169.254.0.0/16 counter drop
          ip6 daddr fe80::/10 counter drop
          ip6 daddr fd00:a9fe:a9fe::/48 counter drop

          # ---- RULE 2.1: PLAYER-TO-PLAYER ISOLATION -------------------------
          # Source AND destination both inside the VPN pool => drop. This is
          # the backstop that makes lateral movement between players impossible
          # even if client-to-client were ever re-enabled by mistake.
          ip saddr \$VPN_NET ip daddr \$VPN_NET counter drop

          # ---- RULE 2.4: ADMIN vs PLAYER ------------------------------------
          # Deny-first: no VPN client except the admin address may touch the
          # SIEM or any management port. Ordered before the allows below.
          ip saddr \$VPN_NET ip daddr \$SIEM ip saddr != \$VPN_ADMIN counter drop
          tcp dport 22 ip saddr \$VPN_NET ip saddr != \$VPN_ADMIN counter drop

          # Admin (10.8.0.50): full reach into the VPC, including Wazuh.
          ip saddr \$VPN_ADMIN ip daddr \$VPC_NET accept

          # Players: challenge host on challenge ports, and CTFd web. Nothing else.
          ip saddr \$VPN_PLAYERS ip daddr \$CHAL tcp dport \$CHAL_PORTS accept
          ip saddr \$VPN_PLAYERS ip daddr \$CHAL udp dport \$CHAL_PORTS accept
          ip saddr \$VPN_PLAYERS ip daddr \$CTFD tcp dport { 80, 443 } accept
          # Per-player (whale) instances are fronted by frps on the CTFd node.
          ip daddr \$CTFD ip saddr . tcp dport @player_instance accept
          ip daddr \$CTFD ip saddr . udp dport @player_instance accept
          $ISO_TCP
          $ISO_UDP

          # Players get NO internet through the tunnel (bandwidth + liability).
          ip saddr \$VPN_NET oifname \$WAN counter drop

          # No transit forwarding for VPC nodes: Linode's fabric would not
          # deliver such packets anyway, and nothing here should rely on it.
          counter drop
        }

        chain output {
          type filter hook output priority filter; policy accept;
          # Metadata is reachable from this host's own root context by design:
          # cloud-init re-reads it on every boot, and blocking it here bricks
          # the node on reboot. Container/VPN access is killed in forward.
        }
      }

      table inet ctf_nat {
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
          # VPN clients reaching VPC hosts: the VPC fabric has no route back to
          # 10.8.0.0/24, so translate. Per-player attribution is preserved by
          # the ovpn-connect.sh CN<->IP log shipped to Wazuh.
          ip saddr \$VPN_NET ip daddr \$VPC_NET masquerade
        }
      }
      EOF

      nft -c -f /etc/nftables.conf
      nft -f /etc/nftables.conf
      systemctl enable nftables >/dev/null 2>&1 || true
      logger -t ctf-fw "nftables applied (wan=$WAN)"

  - path: /etc/sysctl.d/99-ctf-gateway.conf
    permissions: '0644'
    content: |
      net.ipv4.ip_forward=1
      net.ipv4.conf.all.rp_filter=2
      net.ipv4.conf.all.accept_redirects=0
      net.ipv4.conf.all.send_redirects=0
      net.ipv4.conf.all.accept_source_route=0
      net.ipv4.tcp_syncookies=1
      net.ipv6.conf.all.accept_ra=0
      net.ipv6.conf.all.accept_redirects=0

  - path: /etc/ssh/sshd_config.d/99-ctf.conf
    permissions: '0644'
    content: |
      PermitRootLogin prohibit-password
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      ChallengeResponseAuthentication no
      X11Forwarding no
      MaxAuthTries 3
      AllowTcpForwarding yes
      ClientAliveInterval 120

  # ---- Instance ACL poller: reconciles the nftables set with CTFd's live
  # ---- instance map every few seconds. Reconciling (not event hooks) means a
  # ---- missed event self-heals on the next pass.
  - path: /usr/local/sbin/ctf-instance-acl.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/sh
      # One pass: fetch the allow-map, rewrite the set atomically.
      TOKEN=$(cat /etc/ctf/isolation.token 2>/dev/null) || exit 0
      [ -n "$TOKEN" ] || exit 0
      json=$(curl -sk -m 5 -H "Authorization: Bearer $TOKEN" \
               https://__CTFD_VPC_IP__/vpn/isolation-map 2>/dev/null) || exit 0
      # A failed fetch leaves the current set alone: players keep the access
      # they have, and nothing NEW is opened. Never flush on an error.
      printf '%s' "$json" | grep -q '^\[' || exit 0
      elems=$(printf '%s' "$json" | jq -r '.[] | "\(.ip) . \(.port)"' 2>/dev/null | paste -sd, -)
      {
        echo "flush set inet ctf_filter player_instance"
        [ -n "$elems" ] && echo "add element inet ctf_filter player_instance { $elems }"
      } | nft -f -

  - path: /etc/systemd/system/ctf-instance-acl.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Sync per-team instance ACL from CTFd into nftables
      After=network-online.target ctf-firewall.service
      Wants=ctf-firewall.service
      [Service]
      Type=simple
      ExecStart=/bin/sh -c 'while :; do /usr/local/sbin/ctf-instance-acl.sh; sleep __ISOLATION_POLL_SECS__; done'
      Restart=always
      RestartSec=10
      [Install]
      WantedBy=multi-user.target

  - path: /etc/systemd/system/ctf-firewall.service
    permissions: '0644'
    content: |
      [Unit]
      Description=CTF nftables policy
      After=network-online.target
      Wants=network-online.target
      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/usr/local/sbin/ctf-firewall.sh
      [Install]
      WantedBy=multi-user.target

  - path: /root/.ctf-authd.pass
    encoding: b64
    permissions: '0600'
    owner: root:root
    content: __WAZUH_AUTHD_PASS_B64__

  - path: /usr/local/sbin/ctf-wazuh-enroll.sh
    permissions: '0700'
    content: |
      #!/bin/bash
      # Retried by systemd until the manager on __SIEM_VPC_IP__ answers. This
      # removes the deploy-order race between this node and the SIEM node.
      set -euo pipefail
      [ -f /var/ossec/etc/client.keys ] && [ -s /var/ossec/etc/client.keys ] && exit 0
      /var/ossec/bin/agent-auth -m __SIEM_VPC_IP__ -p 1515 \
        -A "$(hostname)" -P "$(cat /root/.ctf-authd.pass)"
      systemctl restart wazuh-agent
      # Enrolled: the shared secret has no further purpose on this host.
      shred -u /root/.ctf-authd.pass 2>/dev/null || rm -f /root/.ctf-authd.pass

  - path: /etc/systemd/system/ctf-wazuh-enroll.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Enroll Wazuh agent (retries until SIEM is reachable)
      After=network-online.target wazuh-agent.service
      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/ctf-wazuh-enroll.sh
      Restart=on-failure
      RestartSec=30
      [Install]
      WantedBy=multi-user.target

runcmd:
  - [ bash, -lc, "sysctl --system" ]
  - [ bash, -lc, "mkdir -p /var/log/openvpn && chown nobody:nogroup /var/log/openvpn" ]
  - [ bash, -lc, "/usr/local/sbin/ctf-gen-ccd.sh" ]
  - [ bash, -lc, "__ISOLATION_FLAG_CMD__" ]
  - [ bash, -lc, "systemctl enable --now ctf-firewall.service" ]
  - [ bash, -lc, "systemctl enable --now ctf-instance-acl.service || true" ]
  - [ bash, -lc, "systemctl restart chrony && systemctl enable chrony" ]
  - [ bash, -lc, "systemctl restart ssh || systemctl restart sshd" ]
  - [ bash, -lc, "systemctl enable --now openvpn-server@server" ]
  # Wazuh agent (installer needs WAN, which this node has directly).
  - [ bash, -lc, "curl -sSf https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg" ]
  - [ bash, -lc, "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list && apt-get update" ]
  - [ bash, -lc, "WAZUH_MANAGER='__SIEM_VPC_IP__' WAZUH_AGENT_NAME=\"$(hostname)\" DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y wazuh-agent" ]
  - [ bash, -lc, "sed -i 's|<address>.*</address>|<address>__SIEM_VPC_IP__</address>|' /var/ossec/etc/ossec.conf || true" ]
  - [ bash, -lc, "systemctl daemon-reload && systemctl enable --now wazuh-agent && systemctl enable --now ctf-wazuh-enroll.service || true" ]
  # Ship OpenVPN + VPN attribution logs to Wazuh.
  - [ bash, -lc, "printf '<ossec_config><localfile><log_format>syslog</log_format><location>/var/log/openvpn/openvpn.log</location></localfile><localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile></ossec_config>\\n' >> /var/ossec/etc/ossec.conf && systemctl restart wazuh-agent || true" ]
  # SECRET HYGIENE: user-data held the server key + tls-crypt key. Scrub it so
  # a challenge-host compromise pivoting here cannot re-read the material.
  - [ bash, -lc, "shred -u /var/lib/cloud/instance/user-data.txt* 2>/dev/null; rm -f /var/lib/cloud/instances/*/user-data.txt* /var/lib/cloud/instance/cloud-config.txt 2>/dev/null; true" ]
  # Readiness sentinel: ctf_manager.sh blocks on this before creating nodes
  # 2/3/4, because they depend on this host for NAT. No race, no retry storm.
  # FAIL CLOSED: cloud-init runcmd does not abort on error, so the sentinel is
  # gated on the ruleset and the VPN actually being live. If either failed, the
  # sentinel is never written, ctf_manager.sh blocks and reports it, and no
  # further nodes are created behind an unfirewalled gateway.
  - [ bash, -lc, "systemctl restart tinyproxy dnsmasq && systemctl enable tinyproxy dnsmasq" ]
  - [ bash, -lc, "nft list table inet ctf_filter >/dev/null 2>&1 && systemctl is-active --quiet openvpn-server@server && systemctl is-active --quiet tinyproxy && systemctl is-active --quiet dnsmasq && sysctl -n net.ipv4.ip_forward | grep -q 1 && touch /run/ctf-nat-ready && logger -t ctf 'NAT + VPN ready' || logger -t ctf 'GATEWAY NOT READY: firewall, openvpn or forwarding check failed'" ]

