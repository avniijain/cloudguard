import pytest

from app.app import app as flask_app


@pytest.fixture
def client():

    with flask_app.test_client() as client:
        yield client


def test_index(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["message"] == "CloudGuard sample application"
    assert data["service"] == "cloudguard-app"


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "healthy"}
