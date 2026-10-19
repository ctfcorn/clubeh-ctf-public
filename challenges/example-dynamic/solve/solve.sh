#!/bin/bash
# Usage: ./solve.sh HOST PORT  (HOST:PORT is shown in CTFd after pressing Start)
printf 'open-sesame\n' | nc -w 5 "$1" "$2" | grep -o 'clubeh{[^}]*}'
