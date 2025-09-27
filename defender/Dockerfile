# ---------- Builder ----------
FROM python:3.11-slim AS builder

# System packages needed for wheels from git and any build steps
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
 && apt-get install -y --no-install-recommends build-essential git \
 && rm -rf /var/lib/apt/lists/*

# Isolated venv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python deps
# If your file is named docker_requirements.txt, change this COPY and pip line accordingly
COPY docker-requirements.txt .
RUN pip install --no-cache-dir -r docker-requirements.txt

# ---------- Runtime ----------
FROM python:3.11-slim

# LightGBM uses OpenMP at runtime; libgomp1 is the GNU OpenMP runtime
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
 && apt-get -y --no-install-recommends install libgomp1 \
 && rm -rf /var/lib/apt/lists/*

# Copy the ready-to-run venv from the builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy your defender package into the image
# Your model file (pe_lgbm_ember.txt) should live at defender/models/ so it gets copied too
COPY defender /opt/defender/defender

# Non-root user
RUN groupadd -r defender && useradd --no-log-init -r -g defender defender
USER defender

WORKDIR /opt/defender
ENV PYTHONPATH="/opt/defender"

# Default model settings (you can override with -e at runtime)
# Your __main__.py uses a path relative to defender/, so keep the model under defender/models/
ENV MODEL_PATH="models/pe_lgbm_ember.txt"
ENV THRESHOLD="0.974798"

EXPOSE 8080

CMD ["python","-m","defender"]
