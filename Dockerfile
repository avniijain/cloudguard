FROM python:3.13-slim

# Pick up Debian security fix for liblzma5 (5.8.1-1+deb13u2 or later)
RUN apt-get update \
 && apt-get install -y --only-upgrade liblzma5 \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY requirements.txt .
# Hash-locked, wheels only; then remove packaging tools not needed at runtime
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.txt \
 && pip uninstall -y pip setuptools wheel

COPY app/ ./app/
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2)"]

CMD ["python", "-m", "app.app"]