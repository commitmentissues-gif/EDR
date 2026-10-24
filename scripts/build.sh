#!/usr/bin/env bash
# LocalEDR Production Build Script
set -e

echo "=== Building LocalEDR Production Artifacts ==="
echo "[1/3] Running TypeScript validation..."
npm run lint

echo "[2/3] Executing unit test suite..."
bash scripts/test.sh

echo "[3/3] Compiling dashboard client bundle..."
npm run build

echo "=== Build Complete! Ready for Windows Service deployment ==="
