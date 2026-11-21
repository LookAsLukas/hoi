#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p out
mapfile -t sources < <(find src -name '*.java' -print | sort)
javac --release 21 -cp "lib/*" -d out "${sources[@]}"
echo "Compiled ${#sources[@]} source file(s) into out/"
