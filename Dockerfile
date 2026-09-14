# Sentinel-E — hardware-free demo in a container.
# Builds a self-contained image that runs the entire platform (ingestion,
# detection engine, alert store, dashboard) with the demo telemetry generator.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Sentinel-E" \
      org.opencontainers.image.description="Real-time SOC detection platform & IoT cyber range (hardware-free demo)" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY . .

# The only runtime dependency.
RUN pip install --no-cache-dir aiohttp

# Run the hardware-free demo profile: local telemetry generator -> real engine.
ENV SENTINEL_CONFIG=config/demo.conf.json
EXPOSE 8770

CMD ["python", "detection/server.py"]
