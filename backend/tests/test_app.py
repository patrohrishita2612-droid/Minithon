from fastapi.testclient import TestClient

from app.main import app
from app.database.database import check_database_connection


def test_app_initializes():
    assert app is not None
    assert app.title == "Digital Footprint & Privacy Risk Auditor API"


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["message"] == (
        "Digital Footprint & Privacy Risk Auditor backend is running"
    )


def test_database_initializes():
    assert check_database_connection() is True
