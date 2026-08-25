FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV GOOGLE_GENAI_USE_VERTEXAI=TRUE
ENV GOOGLE_CLOUD_LOCATION=global
# Cloud Run が $PORT を注入。uvicornで待受。
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
