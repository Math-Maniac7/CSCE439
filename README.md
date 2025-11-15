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

for i in {1..100}; do
  file="${i}.exe"
  if [ -f "$file" ]; then
    echo ">>> Processing: $file"
    curl -s -X POST --data-binary @"$file" http://localhost:8080/ -H "Content-Type: application/octet-stream"
    echo -e "\n------------------------------------"
  fi
done

Note for graders: the competition report only included the original Colab snippets for Model1, but per the submission requirements I reintroduced the cleaned scripts into this repository—please review `attacker/model1` for the full code, as the report still references the Colab versions due to the deadline/late-submission rules.
