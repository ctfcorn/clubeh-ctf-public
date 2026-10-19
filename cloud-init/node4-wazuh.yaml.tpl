#cloud-config
# =============================================================================
# NODE 4 - WAZUH SIEM  (VPC 10.0.0.5, NO PUBLIC INTERFACE)
#   Single-node Wazuh 4.14 (indexer + manager + dashboard) on a 16GB Linode.
#   Reachable only from the VPC. Player VPN addresses are dropped at the
#   gateway's forward chain before they ever get here (rule 2.4).
# =============================================================================
hostname: ctf-wazuh
fqdn: ctf-wazuh.ctf.local
preserve_hostname: false
manage_etc_hosts: true

apt:
  proxy: http://__GW_VPC_IP__:3128
  https_proxy: http://__GW_VPC_IP__:3128

package_update: true
package_upgrade: true
packages:
  - nftables
  - curl
  - jq
  - chrony
  - tar
  - gnupg

write_files:
  # Egress via the gateway's HTTP proxy (Linode VPC does not transit-forward).
  - path: /etc/profile.d/ctf-proxy.sh
    permissions: '0644'
    content: |
      export http_proxy=http://__GW_VPC_IP__:3128 https_proxy=http://__GW_VPC_IP__:3128
      export HTTP_PROXY=$http_proxy HTTPS_PROXY=$https_proxy
      export no_proxy=localhost,127.0.0.1,__VPC_CIDR__ NO_PROXY=localhost,127.0.0.1,__VPC_CIDR__

  - path: /etc/chrony/conf.d/ctf.conf
    permissions: '0644'
    content: |
      server __GW_VPC_IP__ iburst prefer

  - path: /etc/systemd/resolved.conf.d/ctf.conf
    permissions: '0644'
    content: |
      [Resolve]
      DNS=__GW_VPC_IP__
      # ~. makes the gateway the preferred resolver for every name; the
      # DHCP-supplied Linode resolvers are unreachable from a VPC-only node.
      Domains=~.
      DNSStubListener=yes

  - path: /usr/local/sbin/ctf-firewall.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/bash
      set -euo pipefail
      cat > /etc/nftables.conf <<'EOF'
      #!/usr/sbin/nft -f
      flush ruleset

      define GW    = __GW_VPC_IP__
      define CTFD  = __CTFD_VPC_IP__
      define CHAL  = __CHAL_VPC_IP__
      define AGENTS = { __GW_VPC_IP__, __CTFD_VPC_IP__, __CHAL_VPC_IP__ }

      table inet ctf_filter {
        chain input {
          type filter hook input priority filter; policy drop;
          ct state established,related accept
          ct state invalid drop
          iif lo accept
          icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept

          # Agent enrolment (1515/tcp) and agent event flow (1514/tcp+udp),
          # from the three known VPC peers only.
          ip saddr $AGENTS tcp dport { 1514, 1515 } accept
          ip saddr $AGENTS udp dport 1514 accept

          # Dashboard + indexer API. Only from the gateway: admin VPN traffic
          # is source-NAT'd to $GW on its way in, so this address is the ONLY
          # legitimate source. Admin-vs-player separation is enforced upstream
          # in the gateway's forward chain, which drops every VPN source except
          # __VPN_ADMIN_IP__ before the packet is ever translated.
          ip saddr $GW tcp dport { 443, 9200 } accept
          ip saddr $GW tcp dport 22 accept

          # 10.0.0.4 is the untrusted challenge host: it may submit agent
          # events (above) and nothing else. No dashboard, no SSH, no API.
          ip saddr $CHAL counter drop

          # RULE 2.2: metadata blackhole for anything transiting or leaving.
          counter drop
        }
        chain forward {
          type filter hook forward priority filter; policy drop;
          ip daddr 169.254.0.0/16 counter drop
          counter drop
        }
        chain output {
          type filter hook output priority filter; policy accept;
        }
      }
      EOF
      nft -c -f /etc/nftables.conf
      nft -f /etc/nftables.conf
      systemctl enable nftables >/dev/null 2>&1 || true
      logger -t ctf-fw "wazuh node rules applied"

  # ---- Enable password-protected agent enrolment --------------------------
  - path: /usr/local/sbin/ctf-wazuh-authd.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/bash
      set -euo pipefail
      CONF=/var/ossec/etc/ossec.conf
      # Require the pre-shared enrolment secret. Without this, anything that
      # can reach 1515 could register itself as an agent.
      # Every edit is scoped to the <auth> block. An unscoped sed here once
      # flipped <disabled> inside <cluster> too, and clusterd took the manager
      # down with a "Configuration error" (live deploy, attempt 5).
      if sed -n '/<auth>/,/<\/auth>/p' "$CONF" | grep -q '<use_password>'; then
        sed -i '/<auth>/,/<\/auth>/ s|<use_password>.*</use_password>|<use_password>yes</use_password>|' "$CONF"
      else
        sed -i 's|<auth>|<auth>\n    <use_password>yes</use_password>|' "$CONF"
      fi
      sed -i '/<auth>/,/<\/auth>/ s|<disabled>yes</disabled>|<disabled>no</disabled>|' "$CONF"
      install -m 0640 -o root -g wazuh /root/.ctf-authd.pass /var/ossec/etc/authd.pass
      shred -u /root/.ctf-authd.pass 2>/dev/null || rm -f /root/.ctf-authd.pass
      chmod 640 /var/ossec/etc/authd.pass
      systemctl restart wazuh-manager
      logger -t ctf "wazuh authd enabled (password required)"

  # ---- Called by ctf_manager.sh after all agents have enrolled ------------
  - path: /usr/local/sbin/ctf-wazuh-seal.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/bash
      # Closes the enrolment window once the fleet is registered, so a later
      # compromise of any node cannot register rogue agents or re-read the key.
      set -euo pipefail
      sed -i '/<auth>/,/<\/auth>/ s|<disabled>no</disabled>|<disabled>yes</disabled>|' /var/ossec/etc/ossec.conf
      shred -u /var/ossec/etc/authd.pass 2>/dev/null || rm -f /var/ossec/etc/authd.pass
      systemctl restart wazuh-manager
      logger -t ctf "wazuh enrolment sealed"
      echo "sealed"

  - path: /root/.ctf-authd.pass
    encoding: b64
    permissions: '0600'
    owner: root:root
    content: __WAZUH_AUTHD_PASS_B64__

  - path: /etc/sysctl.d/99-ctf-wazuh.conf
    permissions: '0644'
    content: |
      vm.max_map_count=262144
      net.ipv4.conf.all.accept_redirects=0
      net.ipv4.conf.all.send_redirects=0
      net.ipv4.tcp_syncookies=1
      net.ipv6.conf.all.disable_ipv6=1
      net.ipv6.conf.default.disable_ipv6=1

  - path: /etc/ssh/sshd_config.d/99-ctf.conf
    permissions: '0644'
    content: |
      PermitRootLogin prohibit-password
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      X11Forwarding no
      MaxAuthTries 3
      ClientAliveInterval 120

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

  - path: /usr/local/sbin/ctf-wazuh-install.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/bash
      set -euo pipefail
      . /etc/profile.d/ctf-proxy.sh
      cd /root
      # Wait for the gateway proxy before attempting a ~2GB install.
      for i in $(seq 1 60); do
        # Probe the installer itself: the bucket root returns 403 and would
        # make this loop burn its whole budget for nothing.
        curl -sf -m 5 https://packages.wazuh.com/__WAZUH_BRANCH__/wazuh-install.sh -o /dev/null && break
        sleep 10
      done
      curl -sO https://packages.wazuh.com/__WAZUH_BRANCH__/wazuh-install.sh
      bash ./wazuh-install.sh -a -i 2>&1 | tee /root/wazuh-install.log

      # 16GB plan: give the indexer half of RAM, leave the rest to the
      # manager, dashboard and page cache. The stock installer guesses low.
      sed -i 's/^-Xms.*/-Xms8g/; s/^-Xmx.*/-Xmx8g/' /etc/wazuh-indexer/jvm.options
      systemctl restart wazuh-indexer
      sleep 20
      systemctl restart wazuh-manager wazuh-dashboard || true

      # Stash the generated credentials for ctf_manager.sh to collect over SSH.
      tar -xf /root/wazuh-install-files.tar -C /root 2>/dev/null || true
      cp /root/wazuh-install-files/wazuh-passwords.txt /root/wazuh-credentials.txt 2>/dev/null || true
      chmod 600 /root/wazuh-credentials.txt 2>/dev/null || true
      /usr/local/sbin/ctf-wazuh-authd.sh || true
      # The installer echoes the generated admin password to stdout, which
      # cloud-init captures. Neither log may stay world-readable.
      chmod 600 /var/log/cloud-init-output.log /root/wazuh-install.log 2>/dev/null || true
      logger -t ctf "wazuh single-node install complete"

runcmd:
  - [ bash, -lc, "systemctl restart systemd-resolved" ]
  - [ bash, -lc, "sysctl --system" ]
  - [ bash, -lc, "fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab" ]
  - [ bash, -lc, "systemctl enable --now ctf-firewall.service" ]
  - [ bash, -lc, "sed -i 's/^pool /#pool /; s/^server /#server /' /etc/chrony/chrony.conf; systemctl restart chrony && systemctl enable chrony" ]
  - [ bash, -lc, "systemctl restart ssh || systemctl restart sshd" ]
  - [ bash, -lc, "/usr/local/sbin/ctf-wazuh-install.sh" ]
  - [ bash, -lc, "shred -u /var/lib/cloud/instance/user-data.txt* 2>/dev/null; rm -f /var/lib/cloud/instances/*/user-data.txt* 2>/dev/null; true" ]
  - [ bash, -lc, "nft list table inet ctf_filter >/dev/null 2>&1 && systemctl is-active --quiet wazuh-manager && touch /run/ctf-node-ready && logger -t ctf 'wazuh node ready' || logger -t ctf 'WAZUH NOT READY: firewall or manager down'" ]
