FROM python:3.11-slim

WORKDIR /app

# Install OS-level dependencies first (useful for ml models or python-whois under the hood)
RUN apt-get update && apt-get install -y whois --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files into docker context
COPY . .

EXPOSE 5000

# Note: We keep app on the Python path
ENV PYTHONPATH=/app
WORKDIR /app/backend

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
