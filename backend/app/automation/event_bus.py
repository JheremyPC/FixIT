from __future__ import annotations

import inspect
import logging
from collections import defaultdict
from typing import Any, Callable

Handler = Callable[[dict[str, Any]], Any]
logger = logging.getLogger("fixit.automation")


class EventBus:
    """Bus sencillo para eventos internos de FastAPI.

    Los handlers pueden ser sync o async. Un fallo de un handler no detiene
    los demás handlers del mismo evento.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: Handler) -> None:
        self._handlers[event_type].append(handler)

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        for handler in self._handlers.get(event_type, []):
            try:
                result = handler(payload)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                # Nunca se propaga al flujo del ticket, pero queda registrado.
                logger.exception("Falló un handler del evento %s", event_type)


bus = EventBus()
