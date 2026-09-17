FROM python:3.13-alpine

WORKDIR /app

RUN apk update \
    && apk upgrade \
    && rm -rf /var/cache/apk/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --upgrade setuptools msgpack

COPY main.py .

RUN adduser -D -s /bin/sh appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]