#!/bin/bash
# Install club.eh CTF Wazuh content.
#   on the MANAGER (node 4):  install.sh manager
#   on an AGENT   (1,2,3):    install.sh agent <node1|node2|node3>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

case "${1:-}" in
  manager)
    install -m 0640 -o wazuh -g wazuh "$here/local_decoders.xml" /var/ossec/etc/decoders/local_decoder.xml
    install -m 0640 -o wazuh -g wazuh "$here/local_rules.xml"    /var/ossec/etc/rules/local_rules.xml
    # Refuse to restart on a bad ruleset - a manager that will not start is
    # worse than one with no custom rules.
    if /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
      systemctl restart wazuh-manager
      echo "wazuh: rules+decoders installed, manager restarted"
    else
      echo "wazuh: RULESET REJECTED by wazuh-analysisd - not restarting" >&2
      /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -20 >&2
      exit 1
    fi
    ;;
  agent)
    node="${2:?need node1|node2|node3}"
    src="$here/agent-${node}"*.conf
    # shellcheck disable=SC2086
    cat $src >> /var/ossec/etc/ossec.conf
    systemctl restart wazuh-agent
    echo "wazuh: $node log sources added, agent restarted"
    ;;
  *) echo "usage: $0 manager | agent <node1|node2|node3>" >&2; exit 2;;
esac
