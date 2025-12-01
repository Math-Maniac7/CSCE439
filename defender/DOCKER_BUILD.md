# Docker Build Instructions for Model1

## Overview

The Docker image has been updated to use **Model1 RandomForest Deep** as the default defense model. The model file is automatically downloaded during the Docker build process.

## Changes Made

1. **Default Model**: Changed from `ember` to `model1`
2. **Model Download**: Added automatic download of `model1_best.pickle` during build
3. **Dependencies**: Added `gdown` for downloading from Google Drive

## Building the Docker Image

### Standard Build

```bash
cd defender
docker build -t malware-defense .
```

### Build with Custom Tag

```bash
docker build -t your-username/malware-defense:latest .
```

## Running the Container

```bash
docker run --memory=1g -p 8080:8080 malware-defense
```

Or with custom memory limit:
```bash
docker run --memory=1.5g --cpus=1 -p 8080:8080 malware-defense
```

## Verifying the Model

Once the container is running, verify the model is loaded:

```bash
curl -X GET http://localhost:8080/model
```

Expected response should show:
- `"name": "model1_rf_deep"`
- Model information including number of trees, max depth, etc.

## Testing

Test with a sample file:

```bash
curl -X POST --data-binary @sample.exe http://localhost:8080/ -H "Content-Type: application/octet-stream"
```

## Model File Download

The model file (`model1_best.pickle`) is automatically downloaded from:
- **Google Drive**: https://drive.google.com/file/d/1GEsn_imO1m1c4on5UiJmP0S7Ku8PkqJu/view?usp=sharing

If the download fails during build, the container will fall back to dummy models if available.

## Image Size

The Docker image should remain under 1GB when uncompressed. To check size:

```bash
docker images malware-defense
```

## Troubleshooting

### Model Download Fails

If the model download fails during build:
1. Check internet connectivity
2. Verify Google Drive link is accessible
3. The build will continue but may use fallback models

### Model Not Loading

If the model doesn't load at runtime:
1. Check container logs: `docker logs <container-id>`
2. Verify model file exists: `docker exec <container-id> ls -lh /opt/defender/defender/models/`
3. Check environment variables: `docker exec <container-id> env | grep DF_MODEL`

## Exporting for Submission

```bash
# Save the image
docker save malware-defense -o malware-defense.tar

# Compress
gzip malware-defense.tar

# Verify size (must be < 1GB uncompressed)
ls -lh malware-defense.tar.gz
```

## Notes

- The model file is downloaded during build, not included in the repository
- Model size: ~[TO_BE_FILLED] MB
- Total image size should remain under 1GB uncompressed
- Uses scikit-learn RandomForest (no LightGBM dependency for Model1)

