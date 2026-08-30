#!/usr/bin/env bash
# Build & run the Java AIC SDK without Maven.
# Downloads dependencies into ./lib the first time (see fetch-deps.sh),
# compiles src/main + src/test into ./target and runs JUnit.

set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p target/classes target/test-classes

LIBS=$(find lib -name '*.jar' ! -name '*console-standalone*' ! -name '*junit*' ! -name '*opentest4j*' ! -name '*platform-*' | tr '\n' ':')

COMPILE_CP="target/classes:$LIBS"

echo "== compiling main sources =="
find src/main/java -name '*.java' > target/main-sources.txt
javac --release 17 -encoding UTF-8 -cp "$COMPILE_CP" -d target/classes @target/main-sources.txt

echo "== compiling test sources =="
find src/test/java -name '*.java' > target/test-sources.txt
javac --release 17 -encoding UTF-8 -cp "target/test-classes:target/classes:$(find lib -name '*.jar' | tr '\n' ':')" \
  -d target/test-classes @target/test-sources.txt

echo "== running tests =="
java -jar lib/junit-platform-console-standalone-1.10.2.jar \
  --class-path "target/classes:target/test-classes:$(find lib -name '*.jar' | tr '\n' ':')" \
  --scan-class-path