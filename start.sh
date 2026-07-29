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

python -c "from app import init_db; init_db()"
sleep 2

python -c "
import sqlite3, sys
try:
    conn = sqlite3.connect('$DB_PATH')
    c = conn.cursor()
    c.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='routers'\")
    if c.fetchone(): print('Database OK')
    else: print('ERROR: no routers table'); sys.exit(1)
    conn.close()
except Exception as e: print(f'ERROR: {e}'); sys.exit(1)
"

python snmp_collector.py &
SNMP_PID=$!
echo "Started SNMP collector (PID: $SNMP_PID)"

python alert_engine.py &
ALERT_PID=$!
echo "Started alert engine (PID: $ALERT_PID)"

(
while true; do
    if [ "$(date +%H)" = "03" ]; then
        python -c "
from app import run_router_backup, init_db, db_path
import sqlite3
init_db()
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()
c.execute('SELECT id FROM routers')
for r in c.fetchall():
    result = run_router_backup(r[0])
    print(f'Backup router {r[0]}: {result}')
conn.close()
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
    kill $SNMP_PID $ALERT_PID $BACKUP_PID 2>/dev/null
    wait
    echo "All stopped"
}
trap cleanup TERM INT

echo "Starting Flask..."
python app.py
