#!/bin/sh
set -eu
VERSION=3.9.11
BASE="${HOME}/.m2/wrapper/dists/apache-maven-${VERSION}"
MAVEN_HOME="${BASE}/apache-maven-${VERSION}"
if [ ! -x "${MAVEN_HOME}/bin/mvn" ]; then
  mkdir -p "${BASE}"
  ARCHIVE="${BASE}/apache-maven-${VERSION}-bin.tar.gz"
  URL="https://archive.apache.org/dist/maven/maven-3/${VERSION}/binaries/apache-maven-${VERSION}-bin.tar.gz"
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$URL" -o "$ARCHIVE"
  elif command -v wget >/dev/null 2>&1; then wget -q "$URL" -O "$ARCHIVE"
  else echo "curl or wget is required to bootstrap Maven." >&2; exit 1; fi
  tar -xzf "$ARCHIVE" -C "$BASE"
fi
exec "${MAVEN_HOME}/bin/mvn" "$@"
