# Third-party licenses

GAMUT is licensed AGPL-3.0-only. This file lists the runtime dependencies that end up in the Docker image (Python packages in the image, JavaScript packages in the built UI) and their licenses, and records that each is compatible with AGPL-3.0. Development-only tools (pytest, ruff, mypy, Vite, Vitest, ESLint, TypeScript, Testing Library, jsdom) are not distributed in the runtime image and are not listed.

GAM7 is installed from PyPI (`gam7==7.52.3`), never vendored. Its Apache-2.0 license text is copied into the image at `/usr/share/doc/gam7/`. GAMUT runs GAM as a separate program (`gam`) through an argument list.

## How this list was generated (2026-11-15)

Backend: a clean virtual environment inside the dev image, with only GAMUT's runtime dependencies installed (`pip install /app/backend`), then:

```
pip install pip-licenses
pip-licenses --format=markdown --with-urls --order=name --ignore-packages pip-licenses prettytable wcwidth setuptools pip gamut
```

Frontend (production dependencies only):

```
cd frontend && npx license-checker --production --summary
```

Output: `MIT: 5` and `UNLICENSED: 1`. The unlicensed entry is `gamut-frontend` itself, which is GAMUT's own code under AGPL-3.0-only (a private package that is never published).

Regenerate this file with the same commands whenever dependencies change.

## Compatibility with AGPL-3.0

Every license below is compatible with AGPL-3.0-only (these components may be combined into an AGPL-3.0 work):

- MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, 0BSD, PSF-2.0: permissive.
- Apache-2.0: compatible with GPLv3 and AGPLv3.
- LGPL-3.0-only (psycopg, psycopg-binary): LGPLv3 may be combined with GPLv3 and AGPLv3. psycopg is used unmodified, as a library.
- MPL-2.0 (certifi): MPL 2.0 section 3.3 allows combination with GPL and AGPL works (a "Secondary License"). certifi is used unmodified.
- Combined expressions (`Apache-2.0 OR BSD-3-Clause`, `Apache-2.0 AND MIT`, `BSD 3-Clause OR Apache-2.0`, `Apache Software License; MIT License`) are each satisfied by licenses listed above.

No license that is incompatible with AGPL-3.0 (for example GPL-2.0-only, SSPL, or a field-of-use restriction) appears in the runtime set. pip-licenses reports some packages only as "BSD License" or "Apache Software License" (their trove classifiers); both families are compatible.

## Backend (Python, runtime image)

| Package | Version | License |
| --- | --- | --- |
| Authlib | 1.9.6 | BSD License |
| Mako | 1.4.3 | MIT |
| MarkupSafe | 3.0.4 | BSD-3-Clause |
| PySocks | 1.7.1 | BSD |
| PyYAML | 6.0.3 | MIT License |
| SQLAlchemy | 2.1.8 | MIT |
| alembic | 1.20.1 | MIT |
| annotated-doc | 0.0.6 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.16.0 | MIT |
| argon2-cffi | 25.1.0 | MIT |
| argon2-cffi-bindings | 26.2.0 | MIT |
| arrow | 1.4.0 | Apache Software License |
| certifi | 2026.10.23 | Mozilla Public License 2.0 (MPL 2.0) |
| cffi | 2.1.1 | MIT-0 |
| chardet | 7.7.0 | 0BSD |
| charset-normalizer | 3.5.2 | MIT |
| click | 8.5.1 | BSD-3-Clause |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| distro | 1.9.0 | Apache Software License |
| fastapi | 0.163.1 | MIT |
| filelock | 4.2.4 | MIT |
| gam7 | 7.52.3 | Apache License (2.0) |
| google-api-core | 2.44.0 | Apache Software License |
| google-api-python-client | 2.201.0 | Apache Software License |
| google-auth | 2.62.0 | Apache Software License |
| google-auth-httplib2 | 0.4.4 | Apache Software License |
| google-auth-oauthlib | 1.5.0 | Apache Software License |
| googleapis-common-protos | 1.76.0 | Apache-2.0 |
| h11 | 0.16.0 | MIT License |
| h2 | 4.4.1 | MIT |
| hpack | 4.2.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httplib2 | 0.32.1 | MIT License |
| httptools | 0.9.0 | MIT |
| httpx | 0.28.1 | BSD License |
| hyperframe | 6.1.0 | MIT License |
| idna | 3.20 | BSD-3-Clause |
| itsdangerous | 2.2.0 | BSD License |
| joserfc | 1.8.0 | BSD License |
| lxml | 6.1.3 | BSD-3-Clause |
| modern-httplib2 | 1.32.1.post1 | Apache-2.0 AND MIT |
| oauthlib | 4.0.1 | BSD-3-Clause |
| opentelemetry-api | 1.45.2 | Apache-2.0 |
| passlib | 1.7.4 | BSD |
| pathvalidate | 3.3.1 | MIT License |
| proto-plus | 1.29.0 | Apache Software License |
| protobuf | 7.36.2 | 3-Clause BSD License |
| psycopg | 3.3.9 | LGPL-3.0-only |
| psycopg-binary | 3.3.9 | LGPL-3.0-only |
| pyasn1 | 0.6.5 | BSD-2-Clause |
| pyasn1_modules | 0.4.2 | BSD License |
| pycparser | 3.12 | BSD-3-Clause |
| pydantic | 2.14.3 | MIT |
| pydantic-settings | 2.16.3 | MIT |
| pydantic_core | 2.50.4 | MIT |
| pyparsing | 3.3.3 | MIT |
| python-dateutil | 4.0.0 | BSD-3-Clause |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| python-multipart | 0.0.33 | Apache-2.0 |
| requests | 2.34.2 | Apache Software License |
| requests-oauthlib | 2.0.0 | BSD License |
| starlette | 1.10.0 | BSD-3-Clause |
| typing-inspection | 0.4.5 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| tzdata | 2026.6 | Apache-2.0 |
| uritemplate | 4.2.0 | BSD 3-Clause OR Apache-2.0 |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| uvloop | 0.23.0 | Apache Software License; MIT License |
| watchfiles | 1.3.0 | MIT License |
| websockets | 17.4 | BSD-3-Clause |

## Frontend (built into the UI bundle)

| Package | Version | License |
| --- | --- | --- |
| react | 18.3.1 | MIT |
| react-dom | 18.3.1 | MIT |
| scheduler | 0.23.2 | MIT |
| loose-envify | 1.4.0 | MIT |
| js-tokens | 4.0.0 | MIT |

## Other components

| Component | License |
| --- | --- |
| python:3.12-slim base image (Debian packages, CPython) | Debian package licenses; PSF-2.0 |
| postgres:16 image (a separate container, not linked into GAMUT) | PostgreSQL License |
