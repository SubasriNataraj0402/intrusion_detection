import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.capture.sniffer import PacketSniffer
from app.config import settings
from app.database import Base, engine
from app.pipeline import process_flow, set_main_loop
from app.routers import auth, traffic, attacks, dashboard, alerts, reports, predict, upload, ws, ai, blocking

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("nids.main")

Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(traffic.router, prefix="/api")
app.include_router(attacks.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(blocking.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(predict.router, prefix="/api")
app.include_router(upload.router, prefix="/api")
app.include_router(ws.router, prefix="/api")
app.include_router(ai.router)


_sniffer: PacketSniffer | None = None


@app.on_event("startup")
async def on_startup():
    global _sniffer
    set_main_loop(asyncio.get_event_loop())
    _sniffer = PacketSniffer(on_flow_complete=lambda features: process_flow(features, persist_traffic=True))
    _sniffer.start()


@app.on_event("shutdown")
async def on_shutdown():
    if _sniffer:
        _sniffer.stop()


@app.get("/api/health")
def health():
    from app.ml.predictor import models_available
    return {
        "status": "ok",
        "models_trained": models_available(),
        "capture_enabled": settings.capture_enabled,
        "capture_interface": settings.capture_interface,
    }
