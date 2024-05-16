from fastapi.testclient import TestClient
from sqlmodel import Field, Session, SQLModel, create_engine, select
from myApp.main import app
from fastapi_neon import settings


def test_read_main():
    client = TestClient(app=app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}
