# Dockerfile for hybrid malware detector
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for pefile and LightGBM
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential python3-dev libglib2.0-0 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
