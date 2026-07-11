from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel


class Settings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8081
    debug: bool = False

    hydra_root: Path = Path(__file__).resolve().parents[3]
    data_dir: Path = Path(__file__).resolve().parents[2] / "data"

    mcp_server_host: str = "localhost"
    mcp_server_port: int = 8900

    coordinator_url: str = "http://localhost:8080"

    secret_key: str = os.getenv("HYDRA_CC_SECRET", "change-me-in-production")

    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:3001"]


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
