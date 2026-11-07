#!/usr/bin/env bash
# Builds the profiler in a Linux container and runs the stress-test suite against it.
# Arguments are passed to suite.py, e.g. `./run.sh memory_steps --interval 100`.
# Extra `docker run` arguments, e.g. resource limits, go in $DOCKER_RUN_ARGS.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -f stress-tests/Dockerfile -t py-crude-resource-monitor-stress .
# py-spy needs ptrace permissions to read the memory of the profiled processes
# shellcheck disable=SC2086
docker run --rm --init --cap-add SYS_PTRACE ${DOCKER_RUN_ARGS:-} \
    -v "$PWD/stress-tests:/stress-tests" \
    py-crude-resource-monitor-stress "$@"
