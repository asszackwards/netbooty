#!/bin/sh
# `docker compose exec netbooty netbooty-server …`: run the CLI as the responder
# user, so the files it writes stay usable by both processes.
umask 002
if [ "$(id -u)" = 0 ]; then
    exec su-exec responder:netbooty /usr/local/libexec/netbooty-server "$@"
fi
exec /usr/local/libexec/netbooty-server "$@"
