Defense:
*How To Run:*

1. Install Docker Desktop

2. Open Powershell

docker pull ubuntu:22.04

docker run -it --privileged -v /var/run/docker.sock:/var/run/docker.sock ubuntu:22.04 bash

apt update

apt install -y docker.io curl

git clone -b extra_defence https://github.com/Math-Maniac7/CSCE439.git

cd CSCE439

cd defender

docker build -t malware-defense .

# Or pull from Docker Hub:
docker pull felix945/malware-defense:latest

docker run --memory=1g -p 8080:8080 malware-defense
# Or using Docker Hub image:
# docker run --memory=1g -p 8080:8080 felix945/malware-defense:latest

*On seperate bash console:*

curl -X GET http://localhost:8080/model

*Testing files:*

curl -X POST --data-binary @10_modified.exe http://localhost:8080/ -H "Content-Type: application/octet-stream"

**Model Information:**
- Model1 RandomForest Deep is the defense model, runs using model1_rf_deep.py
- Model file (model1_best.pickle) is downloaded automatically during Docker build
- Download link: https://drive.google.com/file/d/1GEsn_imO1m1c4on5UiJmP0S7Ku8PkqJu/view?usp=sharing
- Performance: 93.20% accuracy, 99.06% AUC-ROC

**Docker Hub:**
- Image available at: https://hub.docker.com/r/felix945/malware-defense
- Pull command: `docker pull felix945/malware-defense:latest`
- Run command: `docker run --memory=1g -p 8080:8080 felix945/malware-defense:latest`

Attack files delivered separately 
