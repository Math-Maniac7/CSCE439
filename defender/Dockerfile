FROM python:3.8-slim

#############################
# INSTALL SYSTEM DEPENDENCIES
#############################

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libgomp1 \
 && rm -rf /var/lib/apt/lists/*

#############################
# INSTALL PYTHON DEPENDENCIES
#############################

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install
COPY docker-requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r docker-requirements.txt

#############################
# COPY APPLICATION CODE
#############################

# Copy the defender application
COPY defender /opt/defender/defender

# Copy utility scripts
COPY create_dummy_models.py /opt/defender/

#############################
# SETUP APPLICATION
#############################

WORKDIR /opt/defender

# Create dummy models if real ones don't exist
RUN python create_dummy_models.py

# Create non-root user
RUN groupadd -r defender && useradd --no-log-init -r -g defender defender
RUN chown -R defender:defender /opt/defender
USER defender

#############################
# CONFIGURE RUNTIME
#############################

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"
ENV DF_MODEL_NAME="nfs"
ENV DF_MODEL_THRESH=0.9

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

#############################
# START APPLICATION
#############################

CMD ["python", "-m", "defender"]