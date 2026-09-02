# Nova

**Nova** is a modular OSINT (Open-Source Intelligence) toolkit built with Python. It is designed to collect, analyze, correlate, and enrich publicly available information through a clean, extensible architecture.

> **Status:** Early development

## Overview

Nova aims to provide a unified framework for performing OSINT investigations across multiple intelligence sources.

The project is organized into independent modules so that individual intelligence capabilities can be developed, tested, and extended without tightly coupling the entire application.

Current modules include:

* IP intelligence
* Domain intelligence
* ASN intelligence
* DNS intelligence
* Certificate intelligence
* TLS analysis
* HTTP intelligence
* Username intelligence
* Data enrichment
* Cross-source correlation

Nova also includes a core data model layer and a command-line interface.

## Features

### Modular Architecture

Nova separates intelligence capabilities into individual modules:

```text
nova/
├── core/
│   └── models.py
│
├── modules/
│   ├── asn.py
│   ├── certificate.py
│   ├── correlation.py
│   ├── dns.py
│   ├── domain.py
│   ├── enrichment.py
│   ├── httpintel.py
│   ├── ip.py
│   ├── tls.py
│   └── username.py
│
└── cli.py
```

This makes the toolkit easier to maintain and allows new intelligence sources to be added independently.

### Correlation

Nova includes correlation functionality for connecting information collected from different intelligence sources.

The goal is to transform isolated observations into useful relationships between entities.

### Enrichment

Collected intelligence can be enriched and combined to provide additional context around discovered entities.

### Testing

Nova currently has automated tests covering core functionality, correlation, enrichment, and TLS analysis.

Current test status:

```text
10 passed
```

Tests are written using `pytest`.

## Installation

Clone the repository:

```bash
git clone https://github.com/FarzanLabs/Nova.git
cd Nova
```

Create a virtual environment:

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project dependencies:

```bash
pip install -e .
```

## Usage

Nova is currently under active development, so the CLI and module interfaces may change.

Run the CLI with:

```bash
python -m nova.cli
```

For development and testing:

```bash
python -m pytest
```

## Project Structure

```text
Nova/
│
├── nova/
│   ├── __init__.py
│   ├── cli.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   └── models.py
│   │
│   └── modules/
│       ├── __init__.py
│       ├── asn.py
│       ├── certificate.py
│       ├── correlation.py
│       ├── dns.py
│       ├── domain.py
│       ├── enrichment.py
│       ├── httpintel.py
│       ├── ip.py
│       ├── tls.py
│       └── username.py
│
├── tests/
│   ├── test_core.py
│   ├── test_correlation.py
│   ├── test_enrichment.py
│   └── test_tls.py
│
├── pyproject.toml
├── .gitignore
└── README.md
```

## Development

Nova is built with Python and follows a modular approach intended to make future expansion straightforward.

To run the test suite:

```bash
python -m pytest
```

A successful run should report:

```text
10 passed
```

Before submitting changes, make sure the test suite passes.

## Roadmap

Planned areas of development include:

* [ ] Expand OSINT collection modules
* [ ] Improve CLI experience
* [ ] Add structured investigation workflows
* [ ] Expand entity correlation
* [ ] Improve enrichment pipelines
* [ ] Add persistent investigation storage
* [ ] Add visualization capabilities
* [ ] Add configurable data sources
* [ ] Improve error handling and logging
* [ ] Expand automated test coverage
* [ ] Documentation and usage examples
* [ ] Production-ready release

## Responsible Use

Nova is intended for **legitimate security research, defensive security, education, and authorized investigations**.

Only collect and analyze information that you are legally permitted to access. Respect applicable laws, terms of service, privacy requirements, and the rights of individuals and organizations.

Nova should not be used for harassment, stalking, unauthorized access, credential theft, or other malicious activity.

## Contributing

Contributions, improvements, bug reports, and ideas are welcome.

For substantial changes, consider opening an issue first to discuss the proposed direction.

## License

License information will be added as the project approaches its first public release.

---

**Nova — Open-source intelligence, connected.**
