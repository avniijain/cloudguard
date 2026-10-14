# CloudGuard Sample Application

This repository contains a minimal Python Flask application used to validate the **CloudGuard** DevSecOps CI/CD pipeline. It provides a small HTTP service with health checks, unit tests, Docker packaging, and a basic GitHub Actions workflow—without SonarQube, Trivy, the Risk Gate, or deployment (those come in later phases).

## Endpoints

| Method | Path     | Description                          |
|--------|----------|--------------------------------------|
| GET    | `/`      | JSON welcome payload                 |
| GET    | `/health`| `{"status": "healthy"}`              |

## Run locally

From the repository root:

```bash
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_APP = "app.app:app"
python -m flask run --host 0.0.0.0 --port 5000
```

**Linux / macOS:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.app:app
flask run --host 0.0.0.0 --port 5000
```

Alternatively, run the module directly:

```bash
pip install -r requirements.txt
python -m app.app
```

Then open `http://localhost:5000/` and `http://localhost:5000/health`.

## Run tests

With dependencies installed and the virtual environment active:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

## Docker

Build the image:

```bash
docker build -t cloudguard-app .
```

Run the container:

```bash
docker run --rm -p 5000:5000 cloudguard-app
```

Verify:

```bash
curl http://localhost:5000/health
```

## CI

On every push and pull request, GitHub Actions (`.github/workflows/ci.yml`) installs Python 3.11, installs dependencies, and runs `pytest`.

## Project layout

```
.
├── app/
│   ├── app.py          # Flask application
│   └── test_app.py     # pytest tests
├── .github/workflows/
│   └── ci.yml          # Basic CI (test only)
├── Dockerfile
├── requirements.txt
└── README.md
```
