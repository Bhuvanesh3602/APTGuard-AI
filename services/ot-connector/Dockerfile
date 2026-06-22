FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.8.2 \
    && poetry config virtualenvs.create false

COPY pyproject.toml ./

RUN set -eux; \
    if poetry install --no-interaction --no-ansi --only main; then \
        echo "[ot-connector] poetry install succeeded"; \
    else \
        pip install --no-cache-dir \
            "fastapi>=0.109,<0.110" \
            "uvicorn[standard]>=0.27,<0.28" \
            "pydantic>=2.5,<3" \
            "pydantic-settings>=2.1,<3" \
            "httpx>=0.26,<0.27" \
            "structlog>=24.1,<25" \
            "aiokafka>=0.10,<0.11" \
            "apscheduler>=3.10.4,<4" \
            "pymodbus>=3.6.4,<4"; \
    fi

COPY app ./app

EXPOSE 8009

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8009"]
