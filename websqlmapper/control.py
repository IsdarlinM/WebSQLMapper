from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable


class ScanCancelled(RuntimeError):
    pass


ProgressCallback = Callable[[dict[str, object]], None]


@dataclass(slots=True)
class ScanControl:
    progress: ProgressCallback | None = None
    _cancelled: threading.Event = field(default_factory=threading.Event)
    _paused: threading.Event = field(default_factory=threading.Event)

    def cancel(self) -> None:
        self._cancelled.set()
        self._paused.clear()

    def pause(self) -> None:
        self._paused.set()

    def resume(self) -> None:
        self._paused.clear()

    def checkpoint(self) -> None:
        if self._cancelled.is_set():
            raise ScanCancelled("scan cancelled")
        while self._paused.is_set():
            if self._cancelled.is_set():
                raise ScanCancelled("scan cancelled")
            time.sleep(0.05)

    def emit(self, event: str, **payload: object) -> None:
        if self.progress:
            self.progress({"event": event, **payload})
