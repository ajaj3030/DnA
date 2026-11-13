# Mercedes-Benz DnA: security remediation demo fork

This is a fork of [mercedes-benz/DnA](https://github.com/mercedes-benz/DnA),
Mercedes-Benz's open-source Data and Analytics platform (MIT). It is not a
Mercedes-Benz deployment and is not affiliated with Mercedes-Benz. The fork
is used to demonstrate event-driven vulnerability remediation with Devin:

- **The codebase** is the upstream platform as published: Java/Spring Boot
  services, a React/TypeScript frontend, Python tooling. Snyk reports about
  4,200 open-source findings across its 336 projects.
- **What this fork adds:** a GitHub Actions workflow,
  [`.github/workflows/snyk-fix-pr-to-devin.yml`](.github/workflows/snyk-fix-pr-to-devin.yml).
  When Snyk opens a fix pull request, it runs Snyk on the affected manifests,
  sends the reports to Devin Security as an ingestion scan, and has Devin
  remediate the findings for the packages Snyk's PR touches, with a Snyk
  re-scan and a build as evidence.
- **Demo change:** `axios 0.21.1` was added to `packages/frontend` to
  simulate a developer adding a vulnerable dependency.

The upstream README follows.

---

<!-- SPDX-License-Identifier: MIT -->

<p align="center">
<img alt="DnA Logo" src="./packages/frontend/public/images/solutionLogoImages/thumbnails/default.jpg" height="150" style="max-width:100%">
</p>
<h1 align="center">DnA Platform
<p align="center">
<a href="https://github.com/Daimler/DnA/blob/master/LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/Daimler/DnA?color=blue"></a>
<img alt="GitHub contributors" src="https://img.shields.io/github/contributors/Daimler/DnA?color=blue">
<a href="https://github.com/Daimler/DnA/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/Daimler/DnA?color=blue"></a>
<a href="https://github.com/Daimler/DnA/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/Daimler/DnA?color=blue"></a>
<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/Daimler/DnA?color=blue">  
</h1>
</p>

## DnA Platform (Data and Analytics Platform) and its Features

The idea of the DnA Platform originated from the common challenge every big company has - the need for transparency in the data and analytics area. In addition, several features were envisioned and realized, this time with the idea to facilitate a self-service and cloud-independent platform based holistically on open-source software. The goal is to simplify life and speed up the work of everyone working with data.

Please review our Wiki page for a full list of [features that the DnA Platform offers out of the box](https://github.com/mercedes-benz/DnA/wiki).

## Upcoming Features

Please have a look at our [upcoming features](https://github.com/mercedes-benz/DnA/wiki/Upcoming-features).

## Installation

If you would like to try our DnA Platform, please follow the [installation guide](./docs/Install.md) where we provide two ways to install this application:

1. Docker Compose
   * Please only use Docker Compose for local testing.
2. Helm
   * For a complete production installation, we recommend using the Helm method.

In our Helm and Docker Compose installations, we currently provide multiple services including the following:

* Airflow
* Dashboard
* DnA
* Jupyter Notebooks
* Malware Scanning
* Namespace as a Service (NaaS)
* Storage Services
* Vault Services

We will soon offer the Docker Compose and Helm charts for the Kubeflow Pipeline, Model Registry, and Trino, so please check back frequently.

## Architecture

If you're interested in getting a glimpse of how this all ties together, then please see [this short overview](./docs/DnAArchitecture.md).

## Security

If you're interested in learning how we're ensuring security on our DnA platform, then please see [this short overview](./docs/DnASecurity.md).

## Contributing

We welcome any contributions.

*Please Note*:

* We may need a few weeks to settle and review your ideas or contributions efficiently.
* If you would like to contribute to the project, please read the [contributing guide](CONTRIBUTING.md).

## Code of Conduct

Please read our [Code of Conduct](https://github.com/mercedes-benz/foss/blob/master/CODE_OF_CONDUCT.md) as it is our base for interaction.

## License

This project is licensed under the [MIT LICENSE](LICENSE).

## Provider Information

Please visit (https://www.mercedes-benz-techinnovation.com/en/imprint/) for information on the provider.

*Notice*:

Before using the DnA program in production, please take all of the necessary
precautions such as testing and verifying the program regarding your specific use case.
The source code has been tested solely for our own use cases, which might differ from yours
