FROM python:3.14.10-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN mkdir -p /host/storage /host/sys/class/hwmon /host/sys/devices \
    && touch /host/stat /host/meminfo /host/loadavg /host/uptime /host/hostname /host/net-dev /host/cpuinfo /host/os-release /host/storage/ssd-probe /host/storage/hdd-probe \
    && chown -R 10002:10002 /app /host
COPY --chown=10002:10002 agent.py ./agent.py
USER 10002:10002
EXPOSE 9000
CMD ["python", "agent.py"]
