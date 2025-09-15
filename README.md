How To Run:

Install Docker Desktop

Open Powershell

docker pull ubuntu:22.04

docker run -it --privileged -v /var/run/docker.sock:/var/run/docker.sock ubuntu:22.04 bash

apt update

apt install -y docker.io curl

git clone -b FreshInstall https://github.com/Math-Maniac7/CSCE439.git

cd CSCE439

cd defender

docker build -t malware-defense .

docker run --memory=1g -p 8080:8080 malware-defense

On seperate bash console:

curl -X GET http://localhost:8080/model
