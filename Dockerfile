# Built by the Home Assistant Supervisor on the device (see config.yaml).
# The same Python as on the laptop where Telethon was tried; every dependency
# is pinned in pyproject.toml and has a wheel for Alpine on aarch64 and amd64 or is
# pure Python (pyaes), so no compiler is needed (checked 2026-11-12).
FROM python:3.14-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

CMD ["python", "-m", "air_threat_monitor", "app"]
