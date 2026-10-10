FROM python:3.11-slim

WORKDIR /app

# Install shared domain package
COPY libs/ ./libs/
RUN pip install --no-cache-dir -e ./libs

# Install service dependencies
COPY services/log_collector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy service implementation
COPY services/log_collector/src/ ./src/

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]