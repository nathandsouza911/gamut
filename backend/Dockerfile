# SPDX-License-Identifier: AGPL-3.0-only

# --- Stage 1: build the React UI -------------------------------------------
FROM node:20-slim AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# AGPL-3.0 section 13: baked-in fallback for the footer "Source code" link, used if
# /api/meta cannot be reached. Set it with the GAMUT_SOURCE_URL build argument.
ARG GAMUT_SOURCE_URL=https://github.com/OWNER/gamut
ENV VITE_SOURCE_URL=$GAMUT_SOURCE_URL
RUN npm run build

# --- Stage 2: runtime image (web and worker) -------------------------------
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
RUN groupadd --gid 10001 gamut \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin gamut
WORKDIR /app
COPY backend/pyproject.toml /app/backend/pyproject.toml
COPY backend/app /app/backend/app
# Migrations ship in the image; they run as gamut_owner (GAMUT_MIGRATE_DATABASE_URL).
COPY backend/alembic.ini /app/backend/alembic.ini
COPY backend/migrations /app/backend/migrations
RUN pip install /app/backend \
 && mkdir -p /usr/share/doc/gam7 \
 && cp /usr/local/lib/python3.12/site-packages/gam7-*.dist-info/licenses/* /usr/share/doc/gam7/
COPY --from=frontend /frontend/dist /app/static
ENV GAMUT_STATIC_DIR=/app/static
USER 10001:10001
EXPOSE 8080
CMD ["gamut", "web"]

# --- Stage 3: dev image (tests, lint, type checks) -------------------------
FROM runtime AS dev
USER root
RUN pip install "/app/backend[dev]"
WORKDIR /src/backend
USER 10001:10001
CMD ["pytest"]
