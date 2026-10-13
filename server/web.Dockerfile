# NetBooty web app: Python standard library only. Build from the repo root:
#   docker build -f server/web.Dockerfile -t netbooty-web .
FROM python:3-alpine
RUN mkdir -p /data/state && chown 10001:10001 /data/state
COPY server/web/netbooty_web /app/netbooty_web
WORKDIR /app
USER 10001:10001
ENV NETBOOTY_DATA=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8470
CMD ["python", "-m", "netbooty_web"]
