# Linux environment for the stress-test suite. Build from the repository root:
#   docker build -f stress-tests/Dockerfile -t py-crude-resource-monitor-stress .
FROM node:22-bookworm-slim AS frontend
RUN npm install -g pnpm@12
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM rust:1-bookworm AS build
# For py-spy's `unwind` feature, which the native stacks scenario needs
RUN apt-get update && apt-get install -y --no-install-recommends libunwind-dev liblzma-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
COPY --from=frontend /src/frontend/dist frontend/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    SKIP_FRONTEND_BUILD=1 cargo build --release --features unwind && \
    cp target/release/py-crude-resource-monitor /usr/local/bin/

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libunwind8 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/py-crude-resource-monitor /usr/local/bin/
# The suite itself is mounted at runtime, so it can be changed without rebuilding the image
WORKDIR /stress-tests
ENTRYPOINT ["python3", "suite.py"]
