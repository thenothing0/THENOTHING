"""HYDRA Control Center — FastAPI Backend."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import (
    architecture,
    chat,
    commands,
    dashboard,
    discovery,
    guards,
    harness,
    health,
    mcp,
    models,
    providers,
    repo_memory,
)
from .core.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="HYDRA Control Center",
    version="1.0.0",
    description="AI-native engineering console for the HYDRA Cybersecurity OS",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api")
app.include_router(providers.router, prefix="/api")
app.include_router(models.router, prefix="/api")
app.include_router(chat.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(mcp.router, prefix="/api")
app.include_router(commands.router, prefix="/api")
app.include_router(harness.router, prefix="/api")
app.include_router(repo_memory.router, prefix="/api")
app.include_router(guards.router, prefix="/api")
app.include_router(architecture.router, prefix="/api")
app.include_router(discovery.router, prefix="/api")
