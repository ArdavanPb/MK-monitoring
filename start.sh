#!/bin/bash

set -eu
umask 077
cd "$(dirname "$0")"
if [ -f venv/bin/activate ]; then
    source venv/bin/activate
fi
export DB_PATH="${DB_PATH:-data/routers.db}"
# Fail clearly on permission errors; never copy credentials into a shared /tmp DB.
python -c "import db; db.init_db()"

python snmp_collector.py &
SNMP_PID=$!
echo "Started SNMP collector (PID: $SNMP_PID)"

python alert_engine.py &
ALERT_PID=$!
echo "Started alert engine (PID: $ALERT_PID)"

python bandwidth_collector.py &
BANDWIDTH_PID=$!
echo "Started bandwidth collector (PID: $BANDWIDTH_PID)"

python flow_collector.py &
FLOW_PID=$!
echo "Started Flow collector (PID: $FLOW_PID)"

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
    kill $SNMP_PID $ALERT_PID $BANDWIDTH_PID $FLOW_PID $BACKUP_PID ${WEB_PID:-} 2>/dev/null || true
    wait
    echo "All stopped"
}
trap cleanup EXIT
trap 'exit 0' TERM INT

echo "Starting Flask..."
python app.py &
WEB_PID=$!
wait "$WEB_PID"
