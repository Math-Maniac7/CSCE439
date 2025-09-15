FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements from the correct location and install Python dependencies
COPY defender/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your entire project structure
COPY . .

# Set environment variables for your model
ENV DF_MODEL_PATH="defender/defender/models/nfs_full.pickle"
ENV DF_PORT=8080

# Create non-root user for security
RUN useradd -m -u 1000 defender && chown -R defender:defender /app
USER defender

# Expose the port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health')" || exit 1

# Set working directory to defender and run the module
WORKDIR /app/defender
CMD ["python", "defender/__main__.py", "8080"]
