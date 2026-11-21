#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/build.sh >/dev/null
exec java -cp "out:lib/*" keyservice.KeyServiceServer "$@"
