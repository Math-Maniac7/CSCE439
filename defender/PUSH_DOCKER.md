# Push Docker Image to Docker Hub

## Quick Push Commands

Replace `<your-dockerhub-username>` with your actual Docker Hub username:

```bash
# 1. Login to Docker Hub (if not already logged in)
docker login

# 2. Tag the image
docker tag malware-defense:latest <your-dockerhub-username>/malware-defense:latest

# 3. Push the image
docker push <your-dockerhub-username>/malware-defense:latest
```

## Example

If your Docker Hub username is `math-maniac7`:

```bash
docker login
docker tag malware-defense:latest math-maniac7/malware-defense:latest
docker push math-maniac7/malware-defense:latest
```

## After Pushing

Once pushed, others can pull with:

```bash
docker pull <your-dockerhub-username>/malware-defense:latest
docker run --memory=1g -p 8080:8080 <your-dockerhub-username>/malware-defense:latest
```

## Verify

Check your image on Docker Hub:
- https://hub.docker.com/r/<your-dockerhub-username>/malware-defense

