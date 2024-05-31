
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
access_token = None  # Global variable to store the token

# Sample test data
test_user = {
    "username": "columbus",
    "email": "avocado@example.com",
    "password": "test123",
    "first_name": "Test",
    "last_name": "User"
}

test_info = {
  "courses": [
    "CS201",
  ],
  "admission_year": 2020,
  "degree_program": "Computer Science and Engineering",
  "double_major": "Industrial Engineering",
  "minor": "string"
}

specific_course_request = {
    "selected_courses": ["Course1", "Course2"],
    "core": 1,
    "area": 1,
    "free": 1,
    "required": 1,
    "basic_science": 1,
    "university": 1
}

@pytest.fixture
def register_test_user():
    global access_token
    response = client.post("/user/register", json=test_user)  # Updated path
    assert response.status_code == 200 or response.status_code == 400
    if response.status_code == 200:
        assert response.json()["message"] == "User registered successfully"

    # Log in to get the token
    login_data = {
        "username": test_user["username"],
        "password": test_user["password"]
    }
    response = client.post("/user/login", json=login_data)  # Updated path and json instead of data
    assert response.status_code == 200
    access_token = response.json()["access_token"]
    assert access_token is not None
    return access_token

def test_register_user():
    response = client.post("/user/register", json=test_user)  # Updated path
    print(response.json())
    assert response.status_code == 200 or response.status_code == 400
    if response.status_code == 200:
        assert response.json()["message"] == "User registered successfully"

def test_login_user(register_test_user):
    global access_token
    assert access_token is not None

def test_add_user_info(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    user_info = test_info
    response = client.post("/user/addInfo", json=user_info, headers=headers)
    print(response.json())
    assert response.status_code == 200 or response.status_code == 201
    assert response.json()["message"] == "User info added successfully" or response.json()["message"] == "User info updated successfully"

def test_get_user_stats(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.post("/user/stats", headers=headers)
    print(response.json())
    assert response.status_code == 200
    # Check if response contains expected keys or values based on your implementation

def test_get_all_users(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.post("/user/getAll", headers=headers)
    print(response.json())
    assert response.status_code == 200
    # Check if response contains expected keys or values based on your implementation

# New tests for /recommend/specificCourse, /recommend/collabrativeFiltering, /recommend/contentBased, /course/getTop, /user/addCourse, /course/getLeast, and /recommend/course

def test_specific_course_recommendation(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.post("/recommend/specificCourse", json=specific_course_request, headers=headers)
    print(response.json())
    assert response.status_code == 200 or response.status_code == 404

def test_collaborative_filtering_recommendation(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.post("/recommend/collabrativeFiltering", headers=headers)
    print(response.json())
    assert response.status_code == 200

def test_content_based_recommendation(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.post("/recommend/contentBased", headers=headers)
    print(response.json())
    assert response.status_code == 200

def test_get_top_courses(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.get("/course/getTop", headers=headers)
    print(response.json())
    assert response.status_code == 200 or response.status_code == 404

# def test_add_course(register_test_user):
#     global access_token
#     headers = {
#         "Authorization": f"Bearer {access_token}"
#     }
#     course_info = {
#         "courses": [
#             {
#         "courses": "CS303",  # Corrected to match expected str type
#         "admission_year": 2020,
#         "degree_program": "Computer Science and Engineering",
#         "double_major": "Industrial Engineering",
#         "minor": "",
#             }
#         ]
#     }
#     response = client.post("/user/addCourse", json=course_info, headers=headers)
#     print(response.json())
#     assert response.status_code == 200 or response.status_code == 404


def test_get_least_courses(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.get("/course/getLeast", headers=headers)
    print(response.json())
    assert response.status_code == 200 or response.status_code == 404

def test_course_recommendation(register_test_user):
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = client.post("/recommend/course", headers=headers)
    print(response.json())
    assert response.status_code == 200 or response.status_code == 404

def test_delete_user():
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    # Include password in the request body
    data = {
        "password": test_user["password"]
    }
    response = client.delete("/user/delete", headers=headers, json=data)  # Updated path
    print(response.json())
    assert response.status_code == 200
    assert response.json()["message"] == "User deleted successfully"
