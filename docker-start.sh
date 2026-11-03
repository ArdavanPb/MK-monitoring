#!/bin/sh
set -eu
umask 077

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

python flow_collector.py &
FLOW_PID=$!

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
    kill $SNMP_PID $ALERT_PID $BANDWIDTH_PID $FLOW_PID $BACKUP_PID ${WEB_PID:-} 2>/dev/null || true
    wait
    echo "All stopped"
}
trap cleanup EXIT
trap 'exit 0' TERM INT

echo "Starting web server..."
gunicorn --bind "${HOST:-0.0.0.0}:${PORT:-8080}" --workers 1 --threads 4 --timeout 120 app:app &
WEB_PID=$!
wait "$WEB_PID"
