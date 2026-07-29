#!/bin/sh

echo "Starting MK-Monitoring in Docker..."

export DB_PATH="${DB_PATH:-/app/data/routers.db}"
mkdir -p /app/data

python -c "from app import init_db; init_db()"

python snmp_collector.py &
SNMP_PID=$!

python alert_engine.py &
ALERT_PID=$!

(
while true; do
    if [ "$(date +%H)" = "03" ]; then
        python -c "
import os; os.environ['DB_PATH'] = '${DB_PATH}'
from app import run_router_backup, init_db
import sqlite3
init_db()
conn = sqlite3.connect(os.environ['DB_PATH'])
c = conn.cursor()
c.execute('SELECT id FROM routers')
for r in c.fetchall():
    print(f'Backup router {r[0]}: {run_router_backup(r[0])}')
conn.close()
"
        sleep 3600
    fi
    sleep 60
done
) &
BACKUP_PID=$!

cleanup() {
    echo "Shutting down..."
    kill $SNMP_PID $ALERT_PID $BACKUP_PID 2>/dev/null
    wait
    echo "All stopped"
}
trap cleanup TERM INT

echo "Starting Flask app..."
python app.py
