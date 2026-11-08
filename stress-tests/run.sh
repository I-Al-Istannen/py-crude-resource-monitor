#!/usr/bin/env bash
# Builds the profiler in a Linux container and runs the stress-test suite against it.
# Arguments are passed to suite.py, e.g. `./run.sh memory_steps --interval 100`.
# Extra `docker run` arguments, e.g. resource limits, go in $DOCKER_RUN_ARGS.
# `--realworld` runs real projects, which need more packages and are built on top of the image.
set -euo pipefail
cd "$(dirname "$0")/.."

image=py-crude-resource-monitor-stress
docker build -f stress-tests/Dockerfile -t "$image" .
for argument in "$@"; do
    if [ "$argument" = "--realworld" ]; then
        # Without a build context: it only needs the packages and the projects to download
        docker build --build-arg "BASE=$image" -t "$image-realworld" - < stress-tests/Dockerfile.realworld
        image="$image-realworld"
    fi
done
# py-spy needs ptrace permissions to read the memory of the profiled processes
# shellcheck disable=SC2086
docker run --rm --init --cap-add SYS_PTRACE ${DOCKER_RUN_ARGS:-} \
    -v "$PWD/stress-tests:/stress-tests" \
    "$image" "$@"
