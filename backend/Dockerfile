FROM python:3.13-slim

WORKDIR /app

# Install system deps for docker SDK and curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Shared lab volume is mounted at /shared (see docker-compose.yml)
RUN mkdir -p /shared /app/data

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
