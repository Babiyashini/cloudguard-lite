---
title: CloudGuard Lite
colorFrom: blue
colorTo: red
sdk: docker
pinned: false
app_port: 7860
---

# CloudGuard Lite ??? Cloud Security Scanner

A simple rule-based cloud security scanner built with Python and Flask. It checks sample AWS-style configuration data for selected security risks and displays findings and recommendations on a web dashboard.

## Features

- Detects SSH access open to the internet.
- Detects disabled S3 Block Public Access settings in sample configuration.
- Detects overly broad IAM permissions.
- Displays security findings and recommendations in a Flask web dashboard.
- Includes automated tests using pytest.
- Uses GitHub Actions to run tests automatically.

## Technologies Used

- Python
- Flask
- HTML
- JSON
- Pytest
- Git and GitHub
- GitHub Actions

## How It Works

1. `sample_config.json` stores sample cloud configuration data.
2. `scanner.py` checks the configuration against predefined security rules.
3. `test_scanner.py` tests the scanner's behavior.
4. `app.py` runs the Flask web application.
5. `templates/index.html` displays security findings and recommendations.
6. GitHub Actions automatically runs tests when code is pushed or a pull request is opened.

## Security Rules

| Rule ID | Security Check | Severity |
|---|---|---|
| CG-001 | SSH access open to the internet | HIGH |
| CG-002 | S3 public access protection disabled | HIGH |
| CG-003 | Broad IAM permissions | HIGH |

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Babiyashini/cloudguard-lite.git
cd cloudguard-lite
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Run the tests

```powershell
python -m pytest -v
```

### 5. Start the application

```powershell
python app.py
```

Open your browser at:

http://127.0.0.1:5000

## Example Results

The scanner initially detected three findings in the sample configuration. After changing the sample settings to address the three implemented rules, the dashboard displayed zero findings.

## Current Limitations

- Scans sample JSON configuration only.
- Does not connect to a live AWS account.
- Does not directly scan Terraform files yet.
- Checks only the security rules implemented in the project.
- Does not confirm whether unauthorized access has occurred.

## Future Improvements

- Add Terraform configuration scanning.
- Add more cloud security rules.
- Explore secure, read-only AWS integration.
- Improve dashboard interactivity and reporting.

## Disclaimer

CloudGuard Lite is an educational project and is not a complete cloud security auditing tool. Zero findings means only that the current configuration passed the implemented checks.


