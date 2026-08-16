# SurfaceWatch - Attack Surface Monitor for SMBs
# -------------------------------------------
# Everything in this image is free and open source.
#
#   docker build -t surfacewatch .
#   docker run -p 5000:5000 --env-file .env surfacewatch
#
# Screenshots need a browser, which roughly doubles the image size. Build
# without it if you do not want that:
#
#   docker build --build-arg INCLUDE_BROWSER=false -t surfacewatch .

FROM python:3.11-slim

LABEL org.opencontainers.image.title="SurfaceWatch"
LABEL org.opencontainers.image.description="Attack surface monitoring for small businesses"
LABEL org.opencontainers.image.licenses="MIT"

# Set to false for a much smaller image without website screenshots.
ARG INCLUDE_BROWSER=true

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# --- System packages -------------------------------------------------------
# nmap  : the port scanner SurfaceWatch drives through python-nmap
# ca-certificates : so HTTPS requests to the NVD and Shodan work
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
    && if [ "$INCLUDE_BROWSER" = "true" ]; then \
         apt-get install -y --no-install-recommends chromium chromium-driver; \
       fi \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Selenium finds the browser through these.
ENV CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver

# --- Python dependencies ---------------------------------------------------
# Copied on their own first so that editing application code does not
# invalidate the cached dependency layer on every rebuild.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# --- Application -----------------------------------------------------------
COPY . .

# Scan history and screenshots live here. Both are mounted as volumes in
# docker-compose.yml so the data survives the container being replaced.
RUN mkdir -p /app/scans /app/static/screenshots

EXPOSE 5000

# A container with no working web server should be reported as unhealthy
# rather than sitting there quietly doing nothing.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/').status" || exit 1

CMD ["python", "run.py"]
