#!/bin/sh
# Start both Meterless engines, wait until they answer, then the API (which seeds the campaign graph).
set -e
cd /app
node engines/world-model/node_modules/tsx/dist/cli.mjs engines/world-model/src/server.ts &
node engines/scout-intent/node_modules/tsx/dist/cli.mjs engines/scout-intent/src/server.ts &
for i in $(seq 1 30); do
  python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8790/health'); u.urlopen('http://127.0.0.1:8791/health')" 2>/dev/null && break
  sleep 1
done
exec python run.py serve
