import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from conftest import DASHBOARD_KEY, INGEST_KEY
from core.database import get_db
from main import app
from ml.model_manager import model_manager


class FakeSession:
    def __init__(self):
        self.added = []

        self.ops = []

    def add(self, obj):
        self.added.append(obj)
        self.ops.append(type(obj).__name__)

    async def flush(self):
        self.ops.append("flush")

    async def commit(self):
        self.ops.append("commit")


@pytest.fixture(scope="module")
def client():
    # No `with` block → lifespan (Redis/DB connections) is not run.
    model_manager.bootstrap(save=False)
    return TestClient(app)


@pytest.fixture
def fake_db():
    session = FakeSession()

    async def _override():
        yield session

    app.dependency_overrides[get_db] = _override
    yield session
    app.dependency_overrides.clear()


SQLI = {
    "ip_address": "45.33.32.156",
    "method": "GET",
    "url": "https://example.com/api/users?id=1' OR 1=1--",
    "user_agent": "sqlmap/1.7",
}


def test_health_is_public(client):
    assert client.get("/health").status_code == 200


@pytest.mark.parametrize("method,path", [
    ("get", "/api/logs/"),
    ("get", "/api/threats/alerts"),
    ("get", "/api/dashboard/stats"),
    ("get", "/api/models/status"),
    ("post", "/api/models/retrain"),
])
def test_dashboard_endpoints_require_key(client, method, path):
    assert getattr(client, method)(path).status_code == 401
    # The ingest key must not grant dashboard access
    assert getattr(client, method)(path, headers={"X-API-Key": INGEST_KEY}).status_code == 401


def test_ingest_requires_ingest_key(client, fake_db):
    assert client.post("/api/logs/ingest", json=SQLI).status_code == 401
    r = client.post("/api/logs/ingest", json=SQLI, headers={"X-API-Key": DASHBOARD_KEY})
    assert r.status_code == 401


def test_ingest_detects_and_creates_alert(client, fake_db):
    r = client.post("/api/logs/ingest", json=SQLI, headers={"X-API-Key": INGEST_KEY})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "SQL_INJECTION" in body["attack_types"]
    assert body["is_malicious"] is True
    kinds = {type(o).__name__ for o in fake_db.added}
    assert kinds == {"RequestLog", "Alert"}  # same transaction
    # The log row must be flushed before the alert that references it (FK)
    assert fake_db.ops == ["RequestLog", "flush", "Alert", "commit"]


def test_ingest_rejects_oversized_input(client, fake_db):
    big = {**SQLI, "url": "https://x.com/?" + "a" * 9000}
    r = client.post("/api/logs/ingest", json=big, headers={"X-API-Key": INGEST_KEY})
    assert r.status_code == 422


def test_page_size_is_capped(client, fake_db):
    r = client.get("/api/logs/?limit=100000", headers={"X-API-Key": DASHBOARD_KEY})
    assert r.status_code == 422


def test_docs_disabled_by_default(client):
    assert client.get("/docs").status_code == 404


def test_websocket_rejects_missing_token(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/stream") as ws:
            ws.receive_text()
    assert exc.value.code == 1008
