FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install schedule for background tasks
RUN pip install --no-cache-dir schedule

COPY . .

EXPOSE 8080

# Start both services directly
CMD python bandwidth_collector.py & python app.py