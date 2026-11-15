#!/bin/sh
# Pull-deploy, run by a TrueNAS cron job every 5 minutes from the clone at /mnt/SSD/sidedrop/repo.
# Rebuilds and redeploys only when origin/main moved; -f forces it.
set -e
cd "$(dirname "$0")"
git fetch -q origin main
[ "$1" != -f ] && [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] && exit 0
git reset -q --hard origin/main
docker build -q -t sidedrop:latest .
midclt call -j app.redeploy sidedrop >/dev/null
echo "deployed $(git log --oneline -1)"
