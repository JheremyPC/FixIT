"""Process state that the infrastructure controls can observe (set by app.main during startup)."""
from datetime import datetime, timezone

STATE: dict = {"started_at": datetime.now(timezone.utc), "automation_worker": None, "scheduler": None}


def worker_running() -> bool | None:
    task = STATE.get("automation_worker")
    if task is None: return None
    return not task.done()


def scheduler_running() -> bool | None:
    task = STATE.get("scheduler")
    if task is None: return None
    return not task.done()
