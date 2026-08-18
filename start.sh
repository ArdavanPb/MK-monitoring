#!/bin/bash

# Check dependencies
if ! python -c "import flask" 2>/dev/null; then
    echo "Dependencies not installed. Run: pip install -r requirements.txt"
    exit 1
fi

export DB_PATH="${DB_PATH:-data/routers.db}"

# Check if DB is writable; use /tmp if not (e.g. root-owned from Docker)
if ! python -c "open('$DB_PATH','a').close()" 2>/dev/null; then
    echo "WARNING: $DB_PATH not writable, using /tmp/routers.db"
    cp "$DB_PATH" /tmp/routers.db 2>/dev/null || true
    chmod 666 /tmp/routers.db 2>/dev/null || true
    export DB_PATH="/tmp/routers.db"
fi

python -c "import db; db.init_db()"
sleep 2

python -c "
import sqlite3, sys
import db
conn = db.get_connection()
try:
    row = conn.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='routers'\").fetchone()
    if row: print('Database OK')
    else: print('ERROR: no routers table'); sys.exit(1)
finally:
    conn.close()
"

python snmp_collector.py &
SNMP_PID=$!
echo "Started SNMP collector (PID: $SNMP_PID)"

python alert_engine.py &
ALERT_PID=$!
echo "Started alert engine (PID: $ALERT_PID)"

python bandwidth_collector.py &
BANDWIDTH_PID=$!
echo "Started bandwidth collector (PID: $BANDWIDTH_PID)"

(
while true; do
    if [ "$(date +%H)" = "03" ]; then
        python -c "
import db
db.init_db()
from services import run_router_backup
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
echo "Started backup scheduler (PID: $BACKUP_PID)"

cleanup() {
    echo "Shutting down..."
    kill $SNMP_PID $ALERT_PID $BANDWIDTH_PID $BACKUP_PID 2>/dev/null
    wait
    echo "All stopped"
}
trap cleanup TERM INT

echo "Starting Flask..."
python app.py
