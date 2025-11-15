Defense:
*How To Run:*

1. Install Docker Desktop

2. Open Powershell

docker pull ubuntu:22.04

docker run -it --privileged -v /var/run/docker.sock:/var/run/docker.sock ubuntu:22.04 bash

apt update

apt install -y docker.io curl

git clone -b main https://github.com/Math-Maniac7/CSCE439.git

cd CSCE439

cd defender

docker build -t malware-defense .

docker run --memory=1g -p 8080:8080 malware-defense

*On seperate bash console:*

curl -X GET http://localhost:8080/model

*Testing files:*


curl -X POST --data-binary @10_modified.exe http://localhost:8080/ -H "Content-Type: application/octet-stream"

ember_model.txt.gz is the defense model, runs using ember_model.py
attack files delivered separately 
