#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
BC_VERSION="${BC_VERSION:-1.87}"
mkdir -p lib
for artifact in bcprov-jdk18on bcpkix-jdk18on bcutil-jdk18on; do
    target="lib/${artifact}-${BC_VERSION}.jar"
    if [[ ! -f "$target" ]]; then
        echo "Downloading ${artifact} ${BC_VERSION}"
        curl -fL --retry 3 --max-time 120 -o "$target" \
            "https://repo1.maven.org/maven2/org/bouncycastle/${artifact}/${BC_VERSION}/${artifact}-${BC_VERSION}.jar"
    fi
done
echo "Dependencies are in lib/"
