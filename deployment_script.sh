#!/bin/bash
# Competition deployment script for malware detection system

set -e  # Exit on any error

echo "=== Malware Detection Competition Deployment ==="
echo "Requirements: FPR ≤ 1%, TPR ≥ 95%, Memory ≤ 1GB, Response ≤ 5s"
echo

# Configuration
PROJECT_DIR="/opt/defender"
MODEL_DIR="${PROJECT_DIR}/models"
DOCKER_IMAGE="competition-malware-detector"
CONTAINER_NAME="malware-detector-service"
PORT=8080

# Create necessary directories
echo "1. Setting up directories..."
mkdir -p ${MODEL_DIR}
mkdir -p ${PROJECT_DIR}/logs

# Check if model exists
if [ ! -f "${MODEL_DIR}/nfs_full.pickle" ]; then
    echo "WARNING: Model file not found at ${MODEL_DIR}/nfs_full.pickle"
    echo "Please ensure your trained model is available before deployment."
fi

# Build Docker image
echo "2. Building Docker image..."
docker build -t ${DOCKER_IMAGE} .

# Stop existing container if running
echo "3. Stopping existing container..."
docker stop ${CONTAINER_NAME} 2>/dev/null || true
docker rm ${CONTAINER_NAME} 2>/dev/null || true

# Run container with memory limits
echo "4. Starting container with memory limits..."
docker run -d \
    --name ${CONTAINER_NAME} \
    --memory="1g" \
    --memory-swap="1g" \
    --cpus="2.0" \
    -p ${PORT}:8080 \
    -v ${MODEL_DIR}:/opt/defender/models:ro \
    -v ${PROJECT_DIR}/logs:/opt/defender/logs \
    -e DF_MODEL_PATH="models/nfs_full.pickle" \
    -e PYTHONHASHSEED=1 \
    ${DOCKER_IMAGE}

echo "5. Waiting for service to start..."
sleep 10

# Test the service
echo "6. Testing service..."
curl -f http://localhost:${PORT}/health || {
    echo "ERROR: Service health check failed"
    docker logs ${CONTAINER_NAME}
    exit 1
}

echo "7. Getting model info..."
curl -s http://localhost:${PORT}/model | python3 -m json.tool

echo
echo "=== Deployment Complete ==="
echo "Service running on http://localhost:${PORT}"
echo "Container name: ${CONTAINER_NAME}"
echo "Memory limit: 1GB"
echo
echo "Test with:"
echo "curl -XPOST --data-binary @sample.exe http://localhost:${PORT}/ -H \"Content-Type: application/octet-stream\""
echo
echo "Monitor with:"
echo "docker logs -f ${CONTAINER_NAME}"
echo "docker stats ${CONTAINER_NAME}"