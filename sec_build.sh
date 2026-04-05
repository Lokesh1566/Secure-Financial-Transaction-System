#!/bin/bash

# build and run the secure transaction system
# usage:
#   ./build.sh          → compile + run demo
#   ./build.sh bench    → compile + run 10,000 tx benchmark

set -e

echo "Compiling..."
mkdir -p out
javac -d out $(find src/main/java -name "*.java")
echo "Build successful."
echo ""

if [ "$1" = "bench" ]; then
    echo "Running benchmark (10,000 transactions)..."
    java -cp out com.securepay.Main --benchmark 10000
else
    echo "Running demo..."
    java -cp out com.securepay.Main
fi
