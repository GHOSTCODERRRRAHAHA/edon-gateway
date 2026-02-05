# CI workflows

- **ci.yml**: Runs on push/PR to `main`. Python 3.11, install from `requirements.txt` (or `pyproject.toml`), starts uvicorn, polls `/docs`, runs `python test_regression.py`. On failure prints last 200 lines of `uvicorn.log`.
- **Uvicorn entrypoint**: `edon_gateway.main:app` (app is in `edon_gateway/edon_gateway/main.py`).
