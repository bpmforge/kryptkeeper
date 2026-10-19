#!/bin/sh
# Add every corpus address to eth0, then hand over to corpusd.
set -e
for ip in $CORPUS_IPS; do
  ip addr add "$ip/24" dev eth0
done
exec corpusd -truth /ground-truth.json -out /out/served.json
