#!/usr/bin/env bash
# Stop the sample services, confirming they are gone.
set -u
alive() { pgrep -x go-api >/dev/null 2>&1 || pgrep -f 'app\.py' >/dev/null 2>&1 || pgrep -f 'server\.js' >/dev/null 2>&1; }
for attempt in 1 2 3 4 5; do
  alive || break
  sig=""
  [ "$attempt" -ge 3 ] && sig="-9"
  pkill $sig -x go-api        2>/dev/null
  pkill $sig -f 'app\.py'     2>/dev/null
  pkill $sig -f 'server\.js'  2>/dev/null
  sleep 1
done
if alive; then
  echo ">> WARNING: a service is still running (possibly owned by another user)"
  pgrep -a -x go-api; pgrep -af 'app\.py'; pgrep -af 'server\.js'
  exit 1
fi
echo ">> stopped"
