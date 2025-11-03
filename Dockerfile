FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fix line endings and make script executable
RUN sed -i 's/\r$//' docker-start.sh && chmod +x docker-start.sh

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8080

CMD ["./docker-start.sh"]