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

ENV PYTHONPATH=/app

CMD ["python", "backend/app.py"]
