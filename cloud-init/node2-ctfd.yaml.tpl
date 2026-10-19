#cloud-config
# =============================================================================
# NODE 2 - CTFd PLATFORM  (VPC 10.0.0.3 + 1:1 NAT public)
#   CTFd + MariaDB + Redis + Caddy, Docker Swarm MANAGER, private registry.
#   The registry lets the challenge host pull images over the VPC, so node 3
#   needs no internet at all once bootstrapped.
# =============================================================================
hostname: ctf-ctfd
fqdn: ctf-ctfd.ctf.local
preserve_hostname: false
manage_etc_hosts: true

package_update: true
package_upgrade: true
packages:
  - nftables
  - rsyslog
  - curl
  - jq
  - chrony
  - ca-certificates
  - gnupg
  - apache2-utils
  - unattended-upgrades
  - git

write_files:
  - path: /etc/ctf/admin_src_v4
    permissions: '0644'
    content: __ADMIN_SRC_V4__
  - path: /etc/ctf/admin_src_v6
    permissions: '0644'
    content: __ADMIN_SRC_V6__

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
      // A Docker restart stops every challenge container. Patch these by hand
      // between rounds, not automatically at 06:00 on event day.
      Unattended-Upgrade::Package-Blacklist {
        "docker-ce"; "docker-ce-cli"; "containerd.io"; "docker-compose-plugin";
      };
  # Placeholder so CTFd starts before the real plugin arrives over SSH. CTFd
  # refuses to boot if a plugin directory exists without a load(). Overwritten
  # by ctf_manager.sh post_provision, then CTFd is restarted.
  - path: /opt/ctf/plugins/vpn_handout/__init__.py
    permissions: '0644'
    content: |
      def load(app):
          pass

  - path: /opt/ctf/.env
    encoding: b64
    permissions: '0600'
    owner: root:root
    content: __CTFD_ENV_B64__

  # CTFd installs plugin requirements at IMAGE BUILD time, so whale needs a
  # derived image. Whale's own pins are from 2019 and clash with CTFd 3.8's
  # urllib3 2.x; these are the modern equivalents its code actually uses.
  - path: /opt/ctf/ctfd-image/Dockerfile
    permissions: '0644'
    content: |
      FROM ctfd/ctfd:__CTFD_IMAGE_TAG__
      USER root
      COPY ctfd-whale /opt/CTFd/CTFd/plugins/ctfd-whale
      # --no-deps on the Flask extensions: their metadata would otherwise pull
      # Flask 3 / Werkzeug 3 and break CTFd (pinned to Flask 2.1.3). The assert
      # makes the build fail loudly if that ever happens again.
      RUN pip install --no-cache-dir "docker>=7.1,<8" "APScheduler>=3.10,<4" \
       && pip install --no-cache-dir --no-deps "Flask-APScheduler==1.13.1" "flask-redis==0.4.0" \
       && python -c "import flask, flask_apscheduler, flask_redis, docker; assert flask.__version__.startswith('2.1'), flask.__version__" \
       && chown -R 1001:1001 /opt/CTFd/CTFd/plugins/ctfd-whale
      USER 1001

  - path: /opt/ctf/Caddyfile
    encoding: b64
    permissions: '0644'
    owner: root:root
    content: __CADDYFILE_B64__

  - path: /opt/ctf/docker-compose.yml
    permissions: '0644'
    owner: root:root
    content: |
      services:
        ctfd:
          image: ctfd-whale-local:__CTFD_IMAGE_TAG__
          build: ./ctfd-image
          restart: unless-stopped
          environment:
            UPLOAD_FOLDER: /var/uploads
            DATABASE_URL: mysql+pymysql://ctfd:${MYSQL_PASSWORD}@db/ctfd
            REDIS_URL: redis://cache:6379
            WORKERS: 4
            LOG_FOLDER: /var/log/CTFd
            ACCESS_LOG: '-'
            ERROR_LOG: '-'
            REVERSE_PROXY: 'true'
            SECRET_KEY: ${CTFD_SECRET_KEY}
            # read by the vpn_handout plugin to guard /vpn/isolation-map,
            # which the gateway polls to build per-team instance rules
            VPN_ISOLATION_TOKEN: ${VPN_ISOLATION_TOKEN}
          volumes:
            - ./data/CTFd/logs:/var/log/CTFd
            - ./data/CTFd/uploads:/var/uploads
            # Delivered by ctf_manager.sh over SSH after boot: 51 private keys
            # are far too large for the 64KB cloud-init user-data limit.
            - ./plugins/vpn_handout:/opt/CTFd/CTFd/plugins/vpn_handout:ro
            - ./vpn_profiles:/opt/ctf/vpn_profiles:ro
          depends_on:
            - db
            - cache
            - frpc
            - docker-proxy
          networks: [ctf_web, ctf_internal, frp_connect]

        # Whale drives Swarm through this proxy, never the raw socket: only the
        # endpoints it needs (services, networks, tasks, nodes, info, containers).
        # No exec, no volumes, no images, no secrets, no host-level calls.
        docker-proxy:
          image: tecnativa/docker-socket-proxy:__SOCKET_PROXY_TAG__
          restart: unless-stopped
          environment:
            SERVICES: '1'
            NETWORKS: '1'
            TASKS: '1'
            NODES: '1'
            INFO: '1'
            CONTAINERS: '1'
            POST: '1'
          volumes:
            - /var/run/docker.sock:/var/run/docker.sock:ro
          networks: [ctf_internal]

        # frankli0324/frp is a from-scratch image configured by FLAGS (its -c is
        # ignored - verified live). Secrets come from .env via compose interpolation.
        frps:
          image: __FRPS_IMAGE__
          restart: unless-stopped
          command: ["--bind_addr=0.0.0.0", "--bind_port=7000", "--token=${FRP_TOKEN}", "--vhost_http_port=8001", "--subdomain_host=__FRP_SUBDOMAIN_HOST__", "--log_level=warn"]
          ports:
            # VPC address ONLY - never the public interface. Players arrive via the
            # gateway (masqueraded to 10.0.0.2), which is inside the VPC.
            - "__CTFD_VPC_IP__:__FRP_PORT_LO__-__FRP_PORT_HI__:__FRP_PORT_LO__-__FRP_PORT_HI__/tcp"
            - "__CTFD_VPC_IP__:__FRP_PORT_LO__-__FRP_PORT_HI__:__FRP_PORT_LO__-__FRP_PORT_HI__/udp"
          # Must sit on a NON-internal network too, or Docker cannot publish ports.
          networks: [frp_connect, ctf_web]

        frpc:
          image: __FRPC_IMAGE__
          restart: unless-stopped
          command: ["--server_addr=frps", "--server_port=7000", "--token=${FRP_TOKEN}", "--admin_addr=0.0.0.0", "--admin_port=7400", "--admin_user=whale", "--admin_pwd=${FRPC_ADMIN_PASSWORD}", "--login_fail_exit=false", "--log_level=warn"]
          depends_on:
            - frps
          # frp_connect: talks to frps. ctf_challenges: reaches instances by service
          # name over the overlay. frpc dials INTO instances - they never dial out.
          networks: [frp_connect, ctf_challenges]

        db:
          image: mariadb:__MARIADB_TAG__
          restart: unless-stopped
          environment:
            MARIADB_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
            MARIADB_USER: ctfd
            MARIADB_PASSWORD: ${MYSQL_PASSWORD}
            MARIADB_DATABASE: ctfd
            MARIADB_AUTO_UPGRADE: '1'
          volumes:
            - ./data/mysql:/var/lib/mysql
          networks: [ctf_web]
          command:
            - mysqld
            - --character-set-server=utf8mb4
            - --collation-server=utf8mb4_unicode_ci
            - --wait_timeout=28800

        cache:
          image: redis:__REDIS_TAG__
          restart: unless-stopped
          volumes:
            - ./data/redis:/data
          networks: [ctf_web]

        caddy:
          image: caddy:__CADDY_TAG__
          restart: unless-stopped
          ports:
            - "80:80"
            - "443:443"
          volumes:
            - ./Caddyfile:/etc/caddy/Caddyfile:ro
            - ./data/caddy:/data
            - ./data/caddy-config:/config
          depends_on:
            - ctfd
          networks: [ctf_web]

      networks:
        ctf_web:
          driver: bridge
        ctf_internal:
          driver: bridge
          internal: true
        frp_connect:
          driver: bridge
          internal: true
        ctf_challenges:
          external: true

  - path: /etc/docker/daemon.json
    permissions: '0644'
    content: |
      {
        "insecure-registries": ["__CTFD_VPC_IP__:5000"],
        "live-restore": false,
        "log-driver": "json-file",
        "log-opts": { "max-size": "20m", "max-file": "5" }
      }

  # ---- Firewall. Docker owns `ip filter/FORWARD`; we add a guard table at a
  # ---- lower priority and never flush the ruleset out from under it.
  - path: /usr/local/sbin/ctf-firewall.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/bash
      set -euo pipefail
      WAN=$(ip -4 route show default | awk '{print $5; exit}')
      ADM4=$(tr -d '\n' < /etc/ctf/admin_src_v4)
      ADM6=$(tr -d '\n' < /etc/ctf/admin_src_v6)
      cat > /etc/nftables.conf <<'EOF'
      #!/usr/sbin/nft -f
      table inet ctf_guard
      delete table inet ctf_guard

      table inet ctf_guard {
        define WAN  = "WAN_IFACE_HERE"
        define GW   = __GW_VPC_IP__
        define CHAL = __CHAL_VPC_IP__
        define SIEM = __SIEM_VPC_IP__
        define CONTAINER_NETS = { 172.16.0.0/12, 192.168.0.0/16, 10.255.0.0/16 }

        chain guard_input {
          type filter hook input priority -150; policy drop;
          ct state established,related accept
          ct state invalid drop
          iif lo accept
          icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept

          # A compromised CTFd/DB container must not reach host management
          # services through the bridge gateway. Ordered before the accepts.
          ip saddr $CONTAINER_NETS tcp dport { 22, 2375, 2376, 2377, 5000 } counter drop
          iifname { "docker0", "docker_gwbridge" } accept
          iifname "br-*" accept

          # Public web. The only ports open to the internet on this host.
          tcp dport { 80, 443 } accept

          # SSH: operator source addresses and the gateway (bastion path).
          tcp dport 22 ip  saddr { ADMIN_SRC_V4_HERE } accept
          tcp dport 22 ip6 saddr { ADMIN_SRC_V6_HERE } accept
          tcp dport 22 ip  saddr $GW accept

          # Whale 'direct' instance ports: players arrive as the gateway address.
          ip saddr $GW tcp dport __FRP_PORT_LO__-__FRP_PORT_HI__ accept
          ip saddr $GW udp dport __FRP_PORT_LO__-__FRP_PORT_HI__ accept

          # Swarm control plane + private registry: challenge host only.
          ip saddr $CHAL tcp dport { 2377, 7946, 5000 } accept
          ip saddr $CHAL udp dport { 7946, 4789 } accept

          counter drop
        }

        chain guard_forward {
          type filter hook forward priority -150; policy accept;
          ct state established,related accept
          # RULE 2.2: no container on this host may read cloud metadata.
          ip  daddr 169.254.0.0/16 counter drop
          ip6 daddr fd00:a9fe:a9fe::/48 counter drop
          # Platform containers have no business reaching the challenge host
          # or the SIEM directly.
          ip saddr $CONTAINER_NETS ip daddr $CHAL counter drop
          ip saddr $CONTAINER_NETS ip daddr $SIEM counter drop
          # Backstop: challenge/instance ports must never answer to the internet
          # (ingress-mode mistake, or frps mis-bound). Keyed on SOURCE, not
          # interface: on a 1:1-NAT Linode the VPC and the public traffic share
          # eth0, and an iifname rule dropped the gateway's traffic too (live).
          ip saddr != __VPC_CIDR__ tcp dport __CHAL_PORT_LO__-__CHAL_PORT_HI__ counter drop
          ip saddr != __VPC_CIDR__ udp dport __CHAL_PORT_LO__-__CHAL_PORT_HI__ counter drop
          ip saddr != __VPC_CIDR__ tcp dport __FRP_PORT_LO__-__FRP_PORT_HI__ counter drop
          ip saddr != __VPC_CIDR__ udp dport __FRP_PORT_LO__-__FRP_PORT_HI__ counter drop
        }
      }
      EOF
      sed -i "s|WAN_IFACE_HERE|$WAN|; s|ADMIN_SRC_V4_HERE|$ADM4|; s|ADMIN_SRC_V6_HERE|$ADM6|" /etc/nftables.conf
      nft -c -f /etc/nftables.conf
      nft -f /etc/nftables.conf
      systemctl enable nftables >/dev/null 2>&1 || true
      logger -t ctf-fw "ctfd node rules applied"

  - path: /etc/sysctl.d/99-ctf-ctfd.conf
    permissions: '0644'
    content: |
      net.ipv4.conf.all.accept_redirects=0
      net.ipv4.conf.all.send_redirects=0
      net.ipv4.conf.all.accept_source_route=0
      net.ipv4.tcp_syncookies=1
      net.ipv6.conf.all.accept_ra=0

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
      Description=CTF nftables guard rules
      After=network-online.target
      Wants=network-online.target
      Before=docker.service
      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/usr/local/sbin/ctf-firewall.sh
      [Install]
      WantedBy=multi-user.target

  # ---- Scoreboard backups. Losing the DB mid-event is unrecoverable. ------
  - path: /usr/local/sbin/ctf-backup.sh
    permissions: '0700'
    content: |
      #!/bin/bash
      set -euo pipefail
      cd /opt/ctf
      . ./.env
      mkdir -p backups
      TS=$(date -u +%Y%m%dT%H%M%SZ)
      docker compose exec -T db mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" \
        --single-transaction --routines ctfd | gzip > "backups/ctfd-$TS.sql.gz"
      find backups -name 'ctfd-*.sql.gz' -mtime +7 -delete
      logger -t ctf "scoreboard backup written: ctfd-$TS.sql.gz"

  - path: /etc/cron.d/ctf-backup
    permissions: '0644'
    content: |
      0 * * * * root /usr/local/sbin/ctf-backup.sh >/dev/null 2>&1

  - path: /root/.ctf-authd.pass
    encoding: b64
    permissions: '0600'
    owner: root:root
    content: __WAZUH_AUTHD_PASS_B64__

  - path: /usr/local/sbin/ctf-wazuh-enroll.sh
    permissions: '0700'
    content: |
      #!/bin/bash
      set -euo pipefail
      [ -s /var/ossec/etc/client.keys ] && exit 0
      /var/ossec/bin/agent-auth -m __SIEM_VPC_IP__ -p 1515 \
        -A "$(hostname)" -P "$(cat /root/.ctf-authd.pass)"
      systemctl restart wazuh-agent
      shred -u /root/.ctf-authd.pass 2>/dev/null || rm -f /root/.ctf-authd.pass

  - path: /etc/systemd/system/ctf-wazuh-enroll.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Enroll Wazuh agent (retries until SIEM answers)
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
  - [ bash, -lc, "mkdir -p /opt/ctf/data/CTFd/logs /opt/ctf/data/CTFd/uploads /opt/ctf/data/mysql /opt/ctf/data/redis /opt/ctf/data/caddy /opt/ctf/data/caddy-config /opt/ctf/vpn_profiles /opt/ctf/plugins/vpn_handout /opt/ctf/registry /opt/ctf/backups /opt/ctf/challenges" ]
  # The CTFd image runs as uid 1001. Directories it must read or write are
  # owned by it with tight modes; root-owned 0700 made the plugin see nothing.
  - [ bash, -lc, "chown -R 1001:1001 /opt/ctf/data/CTFd /opt/ctf/vpn_profiles && chmod 700 /opt/ctf/vpn_profiles" ]
  - [ bash, -lc, "install -m 0755 -d /etc/apt/keyrings && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && chmod a+r /etc/apt/keyrings/docker.asc" ]
  - [ bash, -lc, "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable\" > /etc/apt/sources.list.d/docker.list && apt-get update" ]
  - [ bash, -lc, "DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" ]
  - [ bash, -lc, "systemctl enable --now ctf-firewall.service" ]
  - [ bash, -lc, "systemctl enable --now docker" ]
  - [ bash, -lc, "systemctl enable --now chrony" ]
  - [ bash, -lc, "systemctl restart ssh || systemctl restart sshd" ]
  # Swarm manager. Bound to the VPC address so the control plane is never
  # reachable on the public interface.
  - [ bash, -lc, "docker swarm init --advertise-addr __CTFD_VPC_IP__ --listen-addr __CTFD_VPC_IP__:2377 || true" ]
  # NOT drained: whale's frpc must attach to the overlay from this node, which
  # needs a schedulable manager. Challenges stay off it via placement constraints
  # (node.labels.name==linux-1 for whale, node.role==worker for static stacks)
  # plus the WAN-side drop of every challenge port range in ctf_guard.
  # Overlay network for challenges. Not IPsec-encrypted: Linode Cloud Firewall
  # cannot pass ESP (proto 50), so `--opt encrypted` would break the overlay.
  # The VPC is an isolated private network; nothing outside it can see this traffic.
  - [ bash, -lc, "docker network create -d overlay --attachable --subnet __CHAL_NET__ __CHAL_NET_NAME__ || true" ]
  # Private registry, bound to the VPC IP ONLY - never the public interface.
  - [ bash, -lc, "docker run -d --name registry --restart always -p __CTFD_VPC_IP__:5000:5000 -v /opt/ctf/registry:/var/lib/registry registry:__REGISTRY_TAG__ || true" ]
  - [ bash, -lc, "PUB=$(curl -4 -fsS -m 10 https://ifconfig.me || curl -4 -fsS -m 10 https://api.ipify.org); [ -n \"$PUB\" ] && sed -i \"s|CTFD_PUBLIC_IP_AT_BOOT|$PUB|g\" /opt/ctf/Caddyfile; grep -q CTFD_PUBLIC_IP_AT_BOOT /opt/ctf/Caddyfile && logger -t ctf 'WARNING: could not resolve public IP for Caddy'; true" ]
  # ctfd-whale, pinned to a reviewed commit. Cloned at build time; baked into the image.
  - [ bash, -lc, "git clone -q __WHALE_REPO__ /opt/ctf/ctfd-image/ctfd-whale && git -C /opt/ctf/ctfd-image/ctfd-whale checkout -q __WHALE_COMMIT__ && rm -rf /opt/ctf/ctfd-image/ctfd-whale/.git" ]
  - [ bash, -lc, "cd /opt/ctf && docker compose pull --ignore-buildable && docker compose build -q && docker compose up -d" ]
  # Wazuh agent
  - [ bash, -lc, "curl -sSf https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg" ]
  - [ bash, -lc, "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list && apt-get update" ]
  - [ bash, -lc, "WAZUH_MANAGER='__SIEM_VPC_IP__' DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y wazuh-agent" ]
  - [ bash, -lc, "sed -i 's|<address>.*</address>|<address>__SIEM_VPC_IP__</address>|' /var/ossec/etc/ossec.conf || true" ]
  - [ bash, -lc, "systemctl daemon-reload && systemctl enable --now wazuh-agent && systemctl enable --now ctf-wazuh-enroll.service || true" ]
  # user-data carried the DB password and CTFd secret key. Scrub it.
  - [ bash, -lc, "shred -u /var/lib/cloud/instance/user-data.txt* 2>/dev/null; rm -f /var/lib/cloud/instances/*/user-data.txt* 2>/dev/null; true" ]
  - [ bash, -lc, "cd /opt/ctf && for i in $(seq 1 12); do n=$(docker compose ps --status running --services 2>/dev/null | grep -cE '^(ctfd|frps|frpc|docker-proxy|caddy)$'); [ \"$n\" = 5 ] && break; sleep 10; done; nft list table inet ctf_guard >/dev/null 2>&1 && [ \"$n\" = 5 ] && touch /run/ctf-node-ready && logger -t ctf 'ctfd node ready' || logger -t ctf \"CTFD NOT READY: guard rules missing or only $n/5 core services running\"" ]
