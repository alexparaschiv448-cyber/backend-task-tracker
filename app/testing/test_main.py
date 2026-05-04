from fastapi.testclient import TestClient
from psycopg2.errorcodes import CLASS_INVALID_SQL_STATEMENT_NAME

from app.main import app
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

salt=os.getenv("salt")

client = TestClient(app)
token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6OTEsImNyZWF0ZWRhdCI6IjIwMjYtMDQtMTQgMTE6MDg6MTYiLCJmaXJzdG5hbWUiOiJhc2RzYWQiLCJsYXN0bmFtZSI6ImFzZGFzZCIsImVtYWlsIjoiYXNhZEBhYWEiLCJleHAiOjE3NzYxNjY2OTZ9.PumvEPVguQXv_BSmsCkQCIHoVGf0z6jJH9fH9mnyVqY"
token2="myJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NjUsImNyZWF0ZWRhdCI6IjIwMjYtMDQtMDcgMDY6NDM6NDIiLCJmaXJzdG5hbWUiOiJBbGV4YW5kcnUiLCJsYXN0bmFtZSI6IlBhcmFzY2hpdiIsImVtYWlsIjoiYWxleEB5YWhvby5jb20iLCJleHAiOjE3NzYxNDk4NzN9.wspfKSPRmt23r2vQu70vO0edl-y_zrggxgOxW6IcUNY"
token3="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NjUsImNyZWF0ZWRhdCI6IjIwMjYtMDQtMDcgMDY6NDM6NDIiLCJmaXJzdG5hbWUiOiJBbGV4YW5kcnUiLCJsYXN0bmFtZSI6IlBhcmFzY2hpdiIsImVtYWlsIjoiYWxleEB5YWhvby5jb20iLCJleHAiOjE3NzYxNjY3NjJ9.9pvB_FaBbaseBVmWeoaWcCPOA047v6AeP1q-jBfPA7c"
auth={"Content-Type": "application/json","Authorization":f"Bearer {token}"}
auth2={"Content-Type": "application/json","Authorization":f"Bearer {token2}"}
auth3={"Content-Type": "application/json","Authorization":f"Bearer {token3}"}
def test_projects():
    response = client.get("/projects",headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                          params={"limit":10,"offset":0,"order":"ASC"})
    assert response.status_code == 200

def test_profile():
    response = client.post(
        "/me",
        json={"authorization": token},
        headers=auth,

    )
    assert response.status_code == 200
    assert response.json()['email'] == "alex@yahoo.com"
    response = client.post(
        "/me",
        json={"authorization": token2},
        headers=auth,

    )
    assert response.status_code == 401
    assert response.json()['message'] == "Invalid token"

def test_project_create():
    description="Test project"
    name="Test P"
    status="New"
    response = client.post("/projects",json={"name": name, "description": description, "status": status},headers=auth,)
    assert response.status_code == 200
    assert response.json() == {"message": "Project created!"}
    status = "Another Status"
    response = client.post("/projects", json={"name": name, "description": description, "status": status},headers=auth, )
    assert response.status_code == 422
    response = client.post("/projects", json={"name": name, "description": description, "status": status},
                           headers=auth2, )
    assert response.status_code == 401
    status="In Progress"
    name="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    response = client.post("/projects", json={"name": name, "description": description, "status": status},
                           headers=auth, )
    assert response.status_code == 422


def test_project_delete():
    id=120
    response=client.delete(f"/projects/{id}",headers=auth,)
    assert response.status_code == 200
    assert response.json() == {"message": "Project deleted!"}
    response = client.delete(f"/projects/{id}", headers=auth2, )
    assert response.status_code == 401
    id=78
    response = client.delete(f"/projects/{id}", headers=auth3, )
    assert response.status_code == 200
    response = client.get(f"/projects/{id}", headers=auth, )
    assert response.status_code == 200
    id="not a number"
    response = client.delete(f"/projects/{id}", headers=auth, )
    assert response.status_code == 422


def test_user_update():
    email="alex@yahoo.coms"
    response=client.get(f"/checkemail/{email}",headers=auth)
    assert response.status_code == 200
    assert response.json() == {"unique": True}
    email="alex@yahoo.comd"
    response = client.get(f"/checkemail/{email}", headers=auth)
    assert response.status_code == 200
    assert response.json() == {"unique": True}
    email="alex yahoo.com"
    response = client.get(f"/checkemail/{email}", headers=auth)
    assert response.status_code == 422
    id=65
    firstname='Alex'
    lastname='Paraschiv'
    email='aaa@yahoo.com'
    response=client.put(f'/users/{id}',headers=auth, json={'firstname': firstname, 'lastname': lastname, 'email': email})
    assert response.status_code == 200
    firstname='Alexandru'
    email = 'alex@yahoo.com'
    response = client.put(f'/users/{id}', headers=auth,
                          json={'firstname': firstname, 'lastname': lastname, 'email': email})
    assert response.status_code == 200
    email = 'aaa yahoo.com'
    response = client.put(f'/users/{id}', headers=auth,
                          json={'firstname': firstname, 'lastname': lastname, 'email': email})
    assert response.status_code == 422
    email="alex@yaho.co"
    firstname="aaa aaaa"
    response = client.put(f'/users/{id}', headers=auth,
                          json={'firstname': firstname, 'lastname': lastname, 'email': email})
    assert response.status_code == 422


def test_user_register():
    final_pass = hashlib.sha256((salt + "test").encode('utf-8')).hexdigest()
    firstname="firstname"
    lastname="lastname"
    email="test2@yahoo.com"
    response=client.post("/auth/register",json={"firstName":firstname, "lastName":lastname, "email":email,"passwordHash":final_pass})
    assert response.status_code == 200
    firstname="aaa"
    lastname="bbb"
    response = client.post("/auth/register", json={"firstName": firstname, "lastName": lastname, "email": email,
                                                   "passwordHash": final_pass})
    assert response.status_code == 200
    firstname="aa aa"
    response = client.post("/auth/register", json={"firstName": firstname, "lastName": lastname, "email": email,
                                                   "passwordHash": final_pass})
    assert response.status_code == 422
    firstname="aaa"
    email="test22 @yahoo.com"
    response = client.post("/auth/register", json={"firstName": firstname, "lastName": lastname, "email": email,
                                                   "passwordHash": final_pass})
    assert response.status_code == 422
    email = "test22yahoo.com"
    response = client.post("/auth/register", json={"firstName": firstname, "lastName": lastname, "email": email,
                                                   "passwordHash": final_pass})
    assert response.status_code == 422

def test_user_delete():
    id=91
    response=client.delete(f"/users/{id}",headers=auth2)
    assert response.status_code == 401
    response=client.delete(f"/users/{id}",headers=auth3)
    assert response.status_code == 401
    response = client.delete(f"/users/{id}", headers=auth)
    assert response.status_code == 200













