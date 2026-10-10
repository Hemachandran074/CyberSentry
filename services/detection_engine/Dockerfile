FROM python:3.11-slim

WORKDIR /app

# Install shared domain package
COPY libs/ ./libs/
RUN pip install --no-cache-dir -e ./libs

# Install service dependencies
COPY services/detection_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy service implementation
COPY services/detection_engine/src/ ./src/

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "src.engine"]