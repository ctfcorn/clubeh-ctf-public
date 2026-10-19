#!/bin/bash
# Usage: ./solve.sh HOST PORT  — must print the flag
curl -s "http://$1:$2/"
