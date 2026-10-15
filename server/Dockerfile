# NetBooty server: the UDP responder and the web app in one image. Build from the repo root:
#   docker build -f server/Dockerfile -t netbooty-server .
# They run as two users (see netbooty_web/launch.py): only the responder can read the key.
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# Use the image's toolchain (the repo's toolchain file also lists UEFI targets this build doesn't need).
ENV RUSTUP_TOOLCHAIN=1.99.0
RUN cargo build --release --locked -p netbooty-server

FROM python:3-alpine
# uid 10001 matches the former responder image, so existing volumes keep working.
RUN apk add --no-cache su-exec \
 && addgroup -g 10000 netbooty \
 && adduser -D -H -u 10001 -G netbooty responder \
 && adduser -D -H -u 10002 -G netbooty web \
 && mkdir -p /data/key /data/state
COPY server/web/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore -r /app/requirements.txt
COPY --from=build /src/target/release/netbooty-server /usr/local/libexec/netbooty-server
COPY server/netbooty-server.sh /usr/local/bin/netbooty-server
COPY server/web/netbooty_web /app/netbooty_web
WORKDIR /app
ENV NETBOOTY_DATA=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8470 47000/udp
# Starts as root only to fix up /data, then drops to the two users.
CMD ["python", "-m", "netbooty_web.launch"]
