FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir locust==2.24.0 requests

COPY locustfile.py .

EXPOSE 8089

CMD ["locust", "--headless", "--users", "50", "--spawn-rate", "5", \
     "--run-time", "5m", "--host", "http://nginx:8080", \
     "--exit-code-on-error", "0"]
