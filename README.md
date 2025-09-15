<<<<<<< HEAD
<!--
---
page_type: sample
languages:
- python
description: "2020 Machine Learning Security Evasion Competition Sample Code"
urlFragment: "Azure/2020-machine-learning-security-evasion-competition"
---
-->

# This is a fork/copy version of the original repository.

# 2020 Machine Learning Security Evasion Competition

<!-- 
Guidelines on README format: https://review.docs.microsoft.com/help/onboard/admin/samples/concepts/readme-template?branch=master

Guidance on onboarding samples to docs.microsoft.com/samples: https://review.docs.microsoft.com/help/onboard/admin/samples/process/onboarding?branch=master

Taxonomies for products and languages: https://review.docs.microsoft.com/new-hope/information-architecture/metadata/taxonomies?branch=master
-->

This repository contains code samples for the 2020 Machine Learning Security Evasion Competition.  Participants must register at [https://mlsec.io](https://mlsec.io) and accept the terms of service in order to participate.

## Dates
| Challenge         | Start Date                  |  End Date          |
|-------------------|-----------------------------|--------------------|
| [defender](https://github.com/Azure/2020-machine-learning-security-evasion-competition/tree/master/defender)   | Jun 15, 2020 (AoE) | Jul 23, 2020 (AoE) |
| [attacker](https://github.com/Azure/2020-machine-learning-security-evasion-competition/tree/master/attacker)   | Aug 6, 2020 (AoE) | Sep 18, 2020 (AoE) |

*start and end times are Anywhere on Earth (AoE)


## Contents

Outline the file contents of the repository. It helps users navigate the codebase, build configuration and any related assets.

| File/folder       | Description                                    |
|-------------------|------------------------------------------------|
| `defender`        | Sample source code for the defender challenge. |
| `attacker`        | Sample source code for the attacker challenge. |
| `README.md`       | This README file.                              |
| `LICENSE`         | The license for the sample code.               |
| `CODE_OF_CONDUCT.md` | Microsoft's open source code of conduct. |
| `SECURITY.md` | Reporting security issues. |


## Contributing

This project welcomes contributions and suggestions, during or after the competition.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
=======
*How To Run:*

1. Install Docker Desktop

2. Open Powershell

docker pull ubuntu:22.04

docker run -it --privileged -v /var/run/docker.sock:/var/run/docker.sock ubuntu:22.04 bash

apt update

apt install -y docker.io curl

git clone -b FreshInstall https://github.com/Math-Maniac7/CSCE439.git

cd CSCE439

cd defender

docker build -t malware-defense .

docker run --memory=1g -p 8080:8080 malware-defense

*On seperate bash console:*

curl -X GET http://localhost:8080/model
>>>>>>> 7d866ed3194d8fd99f70794f4077561100465cd9
