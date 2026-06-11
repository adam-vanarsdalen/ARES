# syntax=docker/dockerfile:1
FROM python:3.12.13-slim-bookworm AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 ares
WORKDIR /app
RUN chown ares:ares /app

COPY requirements.txt constraints.txt ./
RUN python -m pip install --no-cache-dir --upgrade "pip==26.1.2" && \
    python -m pip install --no-cache-dir -r requirements.txt -c constraints.txt

COPY --chown=ares:ares . .

RUN mkdir -p /app/reports && chown ares:ares /app/reports

USER ares

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf -H "X-ARES-Key: ${ARES_API_KEY}" \
        http://localhost:${ARES_PORT:-8001}/health || exit 1

EXPOSE 8001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARES_ENV=prod

CMD ["python", "-m", "uvicorn", "server:app", \
     "--host", "0.0.0.0", "--port", "8001", \
     "--workers", "1", "--no-access-log"]
