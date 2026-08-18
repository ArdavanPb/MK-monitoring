#!/bin/sh

echo "Starting MK-Monitoring in Docker..."

export DB_PATH="${DB_PATH:-/app/data/routers.db}"
mkdir -p /app/data

python -c "import db; db.init_db()"

python snmp_collector.py &
SNMP_PID=$!

python alert_engine.py &
ALERT_PID=$!

python bandwidth_collector.py &
BANDWIDTH_PID=$!

(
while true; do
    if [ "$(date +%H)" = "03" ]; then
        python -c "
import db
db.init_db()
from services import run_router_backup
import sqlite3
conn = db.get_connection()
rows = conn.execute('SELECT id FROM routers').fetchall()
conn.close()
for row in rows:
    print(f'Backup router {row[\"id\"]}: {run_router_backup(row[\"id\"])}')
"
        sleep 3600
    fi
    sleep 60
done
) &
BACKUP_PID=$!

cleanup() {
    echo "Shutting down..."
    kill $SNMP_PID $ALERT_PID $BANDWIDTH_PID $BACKUP_PID 2>/dev/null
    wait
    echo "All stopped"
}
trap cleanup TERM INT

echo "Starting Flask app..."
python app.py
