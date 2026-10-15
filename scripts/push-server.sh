#!/usr/bin/env bash
# Build the server image here and push it to the GitHub Container Registry.
# Usage: scripts/push-server.sh   (log in once first: docker login ghcr.io -u <user>,
#        with a personal access token that has write:packages as the password)
# Env: IMAGE (default ghcr.io/asszackwards/netbooty-server),
#      PLATFORMS (default linux/amd64; e.g. linux/amd64,linux/arm64 with QEMU binfmt set up).
set -euo pipefail
cd "$(dirname "$0")/.."

image=${IMAGE:-ghcr.io/asszackwards/netbooty-server}
platforms=${PLATFORMS:-linux/amd64}

rev=$(git rev-parse --short HEAD)
if [ -n "$(git status --porcelain)" ]; then
    echo "warning: uncommitted changes; tagging as $rev-dirty and not moving :latest" >&2
    tags=(-t "$image:$rev-dirty")
else
    tags=(-t "$image:$rev" -t "$image:latest")
fi

docker buildx build \
    -f server/Dockerfile \
    --platform "$platforms" \
    --label org.opencontainers.image.source=https://github.com/asszackwards/netbooty \
    --annotation index:org.opencontainers.image.source=https://github.com/asszackwards/netbooty \
    --label org.opencontainers.image.revision="$(git rev-parse HEAD)" \
    "${tags[@]}" \
    --push \
    .
