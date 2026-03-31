FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY vibee_hacker/ vibee_hacker/

RUN pip install --no-cache-dir .

ENTRYPOINT ["vibee-hacker"]
CMD ["--help"]
