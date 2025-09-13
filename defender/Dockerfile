# Multi-stage build for optimized malware detection service
FROM python:3.8-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

#############################
# Production image
#############################
FROM python:3.8-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY defender /opt/defender/defender

# Setup environment
EXPOSE 8080

# Create non-root user for security
RUN groupadd -r defender && useradd --no-log-init -r -g defender defender
USER defender

# Set working directory
WORKDIR /opt/defender/

# Environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"
ENV DF_MODEL_PATH="models/nfs_full.pickle"
ENV DF_PORT=8080

# Memory optimization settings
ENV PYTHONHASHSEED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Run the optimized application
CMD ["python", "-m", "defender.optimized_flask_app"]