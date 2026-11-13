#!/bin/sh
# Put the committed code on Home Assistant as a local app and build it there.
#
#   ./deploy.sh            copy HEAD, then install, update or rebuild the app
#   ./deploy.sh --copy     copy HEAD and refresh the app list only
#
# Only what is committed is copied (git archive), so local.env, data/ and
# uncommitted edits never reach Home Assistant. The app's own data (the
# Telegram session) is kept by the Supervisor elsewhere and is not touched.
#
# A new version in config.yaml is an update; the same version is a rebuild.
# The first install does not start the app: it needs api_id and api_hash.
set -eu
HOST=hassio
SLUG=local_air_threat_monitor
DIR=/local_apps/air_threat_monitor
COPY_ONLY=false
[ "${1:-}" = "--copy" ] && COPY_ONLY=true

cd "$(dirname "$0")"
[ -z "$(git status --porcelain)" ] || { echo "Uncommitted changes here; commit first."; exit 1; }
version=$(sed -n 's/^version: *"\([^"]*\)".*/\1/p' config.yaml)
[ -n "$version" ] || { echo "No version in config.yaml."; exit 1; }

echo "Copying $(git rev-parse --short HEAD) (version $version) to $HOST:$DIR"
git archive HEAD | ssh -o BatchMode=yes "$HOST" "rm -rf $DIR && mkdir -p $DIR && tar -x -C $DIR"
ssh -o BatchMode=yes "$HOST" 'ha store reload'
$COPY_ONLY && exit 0

# `ha apps info` also answers for an app that is only in the store, with no
# installed version ("version":null); it fails when the Supervisor rejected
# config.yaml. Supervisor 2026.11 has no "installed" field, so the version decides.
if ! info=$(ssh -o BatchMode=yes "$HOST" "ha apps info $SLUG --raw-json"); then
  echo "The Supervisor does not list $SLUG: see 'ha supervisor logs' for what is wrong with config.yaml."
  exit 1
fi

case $info in
  *'"version":"'*) ;;
  *)
    ssh -o BatchMode=yes "$HOST" "ha apps install $SLUG"
    echo "Installed, not started. In Home Assistant: Settings → Apps → Air Threat Monitor:"
    echo "  Configuration: set api_id and api_hash;  Info: turn on 'Show in sidebar', then Start."
    echo "Then open the page from the sidebar and log in to Telegram by QR code."
    exit 0 ;;
esac

case $info in
  *"\"version\":\"$version\""* | *"\"version\": \"$version\""*)
    ssh -o BatchMode=yes "$HOST" "ha apps rebuild $SLUG" ;;
  *)
    ssh -o BatchMode=yes "$HOST" "ha apps update $SLUG" ;;
esac
ssh -o BatchMode=yes "$HOST" "ha apps logs $SLUG" | tail -n 20
