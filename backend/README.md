# GridPulse Backend

FastAPI backend service for GridPulse (Tailscale Device & Fleet Telemetry).

## Features
- FastAPI asynchronous REST API
- SQLAlchemy 2.0 Async ORM with asyncpg
- Alembic for database migrations
- Pydantic v2 settings & schemas
- APScheduler for background polling jobs
- HTTPX for async external API integrations
