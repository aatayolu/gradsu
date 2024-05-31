import pytest
from fastapi.testclient import TestClient
from main import app
from config.database import get_program_collection

client = TestClient(app)

# Sample test data
test_user = {
    "username": "testuser",
    "email": "testuser@example.com",
    "password": "testpassword",
    "first_name": "Test",
    "last_name": "User"
}

@pytest.fixture
def create_test_user():
    response = client.post("/register", json=test_user)
    assert response.status_code == 200
    return response.json()

@pytest.fixture
def delete_test_user():
    response = client.post("/login", data={"username": test_user["username"], "password": test_user["password"]})
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.delete("/user", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200

def test_register_user():
    response = client.post("/register", json=test_user)
    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"

def test_login_user(create_test_user):
    login_data = {
        "username": test_user["username"],
        "password": test_user["password"]
    }
    response = client.post("/token", data=login_data)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_get_user_details(create_test_user):
    login_data = {
        "username": test_user["username"],
        "password": test_user["password"]
    }
    login_response = client.post("/token", data=login_data)
    access_token = login_response.json()["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == test_user["username"]

def test_get_program_collection():
    program = "CS"
    year = "201801"
    collection = get_program_collection(program, year)
    assert collection.name == f"{program}-{year}"
