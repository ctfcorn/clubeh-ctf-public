#!/bin/bash
# Import the SOC Triage investigations from the soc-triage-ctf repo into this
# range's challenge set (category "SOC Triage"). Safe to re-run after editing the
# source repo: it tests, validates and rebuilds there, then refreshes ONLY each
# challenges/soc-<name>/src/site/ bundle and its questions.json here. The
# hand-written challenge.yml / Dockerfile / README.md / WRITEUP.md are left alone.
#
# usage: challenges/_lib/import_soc_triage.sh [path-to-soc-triage-ctf]
# then:  ./ctf_manager.sh challenges   (rebuild + register)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAL="$(cd "$HERE/.." && pwd)"
SOC="${1:-$HOME/Documents/soc-triage-ctf/soc-triage-ctf-main}"
[ -f "$SOC/tools/assemble.mjs" ] || { echo "not a soc-triage-ctf checkout: $SOC" >&2; exit 1; }

echo "[*] tests"
( cd "$SOC" && node --test tests/*.test.js >/dev/null ) || { echo "[x] soc-triage-ctf tests fail - fix them first" >&2; exit 1; }
echo "[*] validate"
for d in "$SOC"/challenges/*/; do
  ( cd "$SOC" && node tools/validate.mjs "${d}challenge" ) || exit 1
done
echo "[*] assemble"
( cd "$SOC" && rm -rf dist && node tools/assemble.mjs >/dev/null )

for d in "$SOC"/dist/*/; do
  name="$(basename "$d")"
  dest="$CHAL/soc-$name"
  [ -f "$dest/challenge.yml" ] || { echo "[!] no $dest/challenge.yml - create the wrapper for $name first; skipped" >&2; continue; }
  rm -rf "$dest/src/site"
  mkdir -p "$dest/src/site"
  cp -R "$d". "$dest/src/site/"
  cp "$HERE/static_tree_serve.py" "$dest/src/"
  cp "$SOC/challenges/$name/questions.json" "$dest/questions.json"
  echo "[+] soc-$name: $(find "$dest/src/site" -type f | wc -l | tr -d ' ') files, $(python3 -c "import json;print(len(json.load(open('$dest/questions.json'))))") questions"
done
