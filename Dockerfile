FROM python:3.9-slim

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install schedule for background tasks
RUN pip install --no-cache-dir schedule

COPY . .

# Make startup scripts executable
RUN chmod +x start.sh && chmod +x docker-start.sh

# Create data directory with proper permissions
RUN mkdir -p /app/data && chmod 755 /app/data

EXPOSE 8080

# Use the Docker-specific startup script
CMD ["/bin/bash", "./docker-start.sh"]