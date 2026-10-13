# NetBooty responder: a static binary in an empty image. Build from the repo root:
#   docker build -f server/responder.Dockerfile -t netbooty-responder .
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# Use the image's toolchain (the repo's toolchain file also lists UEFI targets this build doesn't need).
ENV RUSTUP_TOOLCHAIN=1.99.0
RUN cargo build --release --locked -p netbooty-server \
 && mkdir -p /out/data/key /out/data/state \
 && cp target/release/netbooty-server /out/

FROM scratch
COPY --from=build /out/netbooty-server /netbooty-server
# Named volumes are created with these owners, so no chown is needed on the host.
COPY --from=build --chown=10001:10001 /out/data /data
USER 10001:10001
ENV NETBOOTY_DATA=/data
ENTRYPOINT ["/netbooty-server"]
CMD ["serve"]
