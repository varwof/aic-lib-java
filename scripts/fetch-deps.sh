#!/usr/bin/env bash
# Re-download the library jars this project needs into ./lib.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p lib
cd lib

BC=1.78.1
JACKSON=2.17.1
JUNIT=5.10.2
PLATFORM=1.10.2

urls=(
  "org/bouncycastle/bcprov-jdk18on/$BC/bcprov-jdk18on-$BC.jar"
  "org/bouncycastle/bcpkix-jdk18on/$BC/bcpkix-jdk18on-$BC.jar"
  "org/bouncycastle/bcutil-jdk18on/$BC/bcutil-jdk18on-$BC.jar"
  "com/fasterxml/jackson/core/jackson-databind/$JACKSON/jackson-databind-$JACKSON.jar"
  "com/fasterxml/jackson/core/jackson-core/$JACKSON/jackson-core-$JACKSON.jar"
  "com/fasterxml/jackson/core/jackson-annotations/$JACKSON/jackson-annotations-$JACKSON.jar"
  "org/junit/jupiter/junit-jupiter/$JUNIT/junit-jupiter-$JUNIT.jar"
  "org/junit/jupiter/junit-jupiter-api/$JUNIT/junit-jupiter-api-$JUNIT.jar"
  "org/junit/jupiter/junit-jupiter-engine/$JUNIT/junit-jupiter-engine-$JUNIT.jar"
  "org/junit/jupiter/junit-jupiter-params/$JUNIT/junit-jupiter-params-$JUNIT.jar"
  "org/junit/platform/junit-platform-commons/$PLATFORM/junit-platform-commons-$PLATFORM.jar"
  "org/junit/platform/junit-platform-engine/$PLATFORM/junit-platform-engine-$PLATFORM.jar"
  "org/junit/platform/junit-platform-launcher/$PLATFORM/junit-platform-launcher-$PLATFORM.jar"
  "org/junit/platform/junit-platform-console-standalone/$PLATFORM/junit-platform-console-standalone-$PLATFORM.jar"
  "org/opentest4j/opentest4j/1.3.0/opentest4j-1.3.0.jar"
)

for u in "${urls[@]}"; do
  f=$(basename "$u")
  if [ -f "$f" ]; then
    echo "  exists  $f"
    continue
  fi
  echo "  fetch   $f"
  curl -sS -fO "https://repo1.maven.org/maven2/$u" || { echo "FAILED: $u"; exit 1; }
done