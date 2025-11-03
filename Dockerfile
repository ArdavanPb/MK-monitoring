FROM python:3.9-slim

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Make startup scripts executable
RUN chmod +x docker-start.sh

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8080

CMD ["/bin/bash", "./docker-start.sh"]