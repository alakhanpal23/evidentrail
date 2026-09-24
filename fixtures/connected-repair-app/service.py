"""Tiny executable service behavior for the opt-in connected repair probe."""

from pathlib import Path


ROOT = Path(__file__).resolve().parent


def setting(relative_path: str, name: str) -> int:
    key, value = (ROOT / relative_path).read_text().strip().split("=", 1)
    if key != name:
        raise ValueError(f"unexpected setting {key}")
    return int(value)


def checkout_request() -> str:
    if setting("api/pool.conf", "pool_size") < 1:
        raise RuntimeError("database connection pool exhausted")
    return "checkout accepted"


def orders_query() -> str:
    if setting("worker/migrations.conf", "apply_migration") < 43:
        raise RuntimeError("orders.region column missing")
    return "orders region available"


def inventory_request() -> str:
    if setting("gateway/upstream.conf", "upstream_timeout_ms") < 100:
        raise TimeoutError("inventory request timed out")
    return "inventory response received"
