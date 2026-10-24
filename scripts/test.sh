#!/usr/bin/env bash
# LocalEDR Foundation Test Suite
set -e

echo "[LocalEDR] Executing modular test suite..."
npx tsx tests/run-all.ts
