FROM node:22-slim AS dashboard
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TP_DATA_DIR=/data
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY backend/pyproject.toml ./
COPY --from=dashboard /build/dist /frontend/dist
RUN useradd --system --uid 10001 --create-home threatpolish \
    && mkdir -p /data && chown -R threatpolish:threatpolish /data /app /frontend
USER threatpolish
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/ready', timeout=4).status == 200 else 1)"
# One worker: schema migrations run at startup, and concurrent workers would
# race on the same migration table. Scale by running the API behind a proxy with
# a migration lock before adding replicas.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
