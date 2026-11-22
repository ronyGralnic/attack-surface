#!/usr/bin/env bash
# Restores kit/fonts/ (not stored in the project-doc archive). Needs npm.
set -e; cd "$(dirname "$0")"; mkdir -p fonts; T=$(mktemp -d); cd "$T"
npm pack @fontsource-variable/heebo@5.3.0 @fontsource/frank-ruhl-libre@5.3.0 @fontsource/ibm-plex-mono@5.3.0 >/dev/null
for f in *.tgz; do mkdir -p "${f%.tgz}"; tar xzf "$f" -C "${f%.tgz}"; done
K="$OLDPWD/fonts"
cp fontsource-variable-heebo-*/package/files/heebo-{hebrew,latin}-wght-normal.woff2 "$K/"
for w in 400 700; do for s in hebrew latin; do cp fontsource-frank-ruhl-libre-*/package/files/frank-ruhl-libre-$s-$w-normal.woff2 "$K/"; done; done
cp fontsource-ibm-plex-mono-*/package/files/ibm-plex-mono-latin-{400,600}-normal.woff2 "$K/"
rm -rf "$T"; echo "fonts restored in $K"
