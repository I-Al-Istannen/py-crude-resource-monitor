#!/usr/bin/env bash
# Builds the profiler in a Linux container and runs the stress-test suite against it.
# Arguments are passed to suite.py, e.g. `./run.sh memory_steps --interval 100`.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -f stress-tests/Dockerfile -t py-crude-resource-monitor-stress .
# py-spy needs ptrace permissions to read the memory of the profiled processes
docker run --rm --init --cap-add SYS_PTRACE \
    -v "$PWD/stress-tests:/stress-tests" \
    py-crude-resource-monitor-stress "$@"
