from fastapi import APIRouter

api_router = APIRouter(prefix="/api/v1")


@api_router.get("/health", tags=["Health"])
async def v1_health():
    """V1 API health check endpoint."""
    return {"status": "ok", "service": "gridpulse-api-v1"}
