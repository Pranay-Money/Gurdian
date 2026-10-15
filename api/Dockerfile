FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GUARDIAN_HOME=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY api/pyproject.toml ./pyproject.toml
COPY README.md ./README.md
COPY ml/pyproject.toml ml/README.md ./ml/
COPY ml/src/ ./ml/src/

RUN python -m pip install --no-cache-dir --upgrade pip==26.2.1 setuptools==84.0.0 \
    && python -m pip install --no-cache-dir -e ".[dev,ml]" \
    && python -m pip install --no-cache-dir ./ml \
    && python -m pip install --no-cache-dir pip-audit==2.10.1

COPY api/ ./

RUN mkdir -p /app/models

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
