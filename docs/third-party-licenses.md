# Third-party licenses

Runtime dependencies and their licenses. All are compatible with AGPL-3.0-only. GAM7 is installed from PyPI, not vendored; its license is shipped in the image at `/usr/share/doc/gam7/`.

## Backend (Python)

| Package | License |
| --- | --- |
| gam7 (7.52.3) | Apache-2.0 |
| fastapi | MIT |
| uvicorn | BSD-3-Clause |
| SQLAlchemy | MIT |
| psycopg (psycopg-binary) | LGPL-3.0 |
| alembic | MIT |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| Authlib | BSD-3-Clause |
| httpx | BSD-3-Clause |
| argon2-cffi | MIT |
| pydantic | MIT |
| pydantic-settings | MIT |
| python-multipart | Apache-2.0 |

## Frontend (built into the UI bundle)

| Package | License |
| --- | --- |
| react | MIT |
| react-dom | MIT |

Development-only tools (pytest, ruff, mypy, Vite, Vitest, ESLint, TypeScript) are not distributed in the runtime image.
