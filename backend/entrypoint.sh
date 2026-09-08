#!/bin/sh
set -e

# If the command starts with uvicorn or is empty, run wait-for-db and migrations
if [ "$1" = "uvicorn" ] || [ -z "$1" ]; then
    echo "GridPulse Backend: Checking database connection..."
    python - <<'EOF'
import sys
import time
import os
import psycopg2

user = os.getenv("POSTGRES_USER", "gridpulse")
password = os.getenv("POSTGRES_PASSWORD", "gridpulse_secret")
db = os.getenv("POSTGRES_DB", "gridpulse")
host = os.getenv("POSTGRES_HOST", "db")
port = os.getenv("POSTGRES_PORT", "5432")

max_retries = 30
for attempt in range(1, max_retries + 1):
    try:
        conn = psycopg2.connect(
            dbname=db,
            user=user,
            password=password,
            host=host,
            port=port,
            connect_timeout=3
        )
        conn.close()
        print(f"Database connection established successfully ({host}:{port}/{db}).")
        sys.exit(0)
    except Exception as exc:
        print(f"Waiting for database ({host}:{port})... attempt {attempt}/{max_retries}: {exc}")
        time.sleep(1)

print("Database connection timed out after 30 attempts.")
sys.exit(1)
EOF

    echo "GridPulse Backend: Applying database migrations via Alembic..."
    alembic upgrade head
    echo "GridPulse Backend: Migrations applied successfully."

    if [ -z "$1" ]; then
        exec uvicorn app.main:app --host 0.0.0.0 --port 8000
    fi
fi

exec "$@"
