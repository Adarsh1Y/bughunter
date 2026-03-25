# Dockerfile - BugHunter
# Multi-stage build for optimized image size

FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

COPY . .

RUN mkdir -p /app/data/output /app/logs

ENV PYTHONUNBUFFERED=1
ENV BUGHUNTER_MODE=normal

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
