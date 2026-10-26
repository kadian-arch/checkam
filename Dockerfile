# CheckAm in one image: Python agents + the three Meterless engines (Node) + the phone app.
# Runs in sample mode with an empty .env. Set ZETARIS_* and MODEL_API_KEY to use the real services.
#   docker build -t checkam .
#   docker run -p 8000:8000 --env-file .env checkam
# Inside Docker on your laptop, Zetaris is reached at host.docker.internal (WITH_JAVA=1 for JDBC).

FROM node:20-slim AS node
WORKDIR /build
COPY web/package*.json web/
RUN cd web && npm ci
COPY web web
RUN cd web && npm run build
COPY engines/world-model/package*.json engines/world-model/
COPY engines/scout-intent/package*.json engines/scout-intent/
COPY engines/h-mem/package*.json engines/h-mem/
RUN cd engines/world-model && npm ci && cd ../scout-intent && npm ci && cd ../h-mem && npm ci

FROM python:3.12-slim
ARG WITH_JAVA=0
RUN if [ "$WITH_JAVA" = "1" ]; then apt-get update && apt-get install -y --no-install-recommends default-jre-headless && rm -rf /var/lib/apt/lists/*; fi
# OCR for screenshots when the vision model cannot read them (English and French)
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng tesseract-ocr-fra && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
WORKDIR /app
COPY api/requirements.txt api/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt
COPY . .
COPY --from=node /build/web/dist web/dist
COPY --from=node /build/engines/world-model/node_modules engines/world-model/node_modules
COPY --from=node /build/engines/scout-intent/node_modules engines/scout-intent/node_modules
COPY --from=node /build/engines/h-mem/node_modules engines/h-mem/node_modules
ENV PORT=8000 WORLD_MODEL_URL=http://127.0.0.1:8790 SCOUT_URL=http://127.0.0.1:8791 HMEM_URL=http://127.0.0.1:8792 HMEM_DIR=/app/data/hmem \
    WORLD_MODEL_FILE=/app/data/world.json ZETARIS_REST_URL=http://host.docker.internal:8888/api/v1.0 \
    ZETARIS_JDBC_URL=jdbc:zetaris:lightning@host.docker.internal:10000 PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["sh", "deploy/start.sh"]
