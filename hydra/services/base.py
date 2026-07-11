"""Base service class with event bus integration."""

from pathlib import Path

from hydra.services.event_bus import EventBus


class BaseService:
    """Base class for all application services."""

    def __init__(self, event_bus: EventBus, data_dir: Path | None = None):
        self._bus = event_bus
        self._data_dir = data_dir or Path("data")

    def _emit(self, event_type: str, payload: dict | None = None) -> None:
        self._bus.emit(event_type, payload, source=self.__class__.__name__)
