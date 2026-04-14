from typing import Annotated
from fastapi import Path,Body
from datetime import datetime
from sqlalchemy import create_engine,text
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Request, Response, Header,Query
from fastapi.responses import JSONResponse
import hashlib
from dotenv import load_dotenv
import os
from .models.LoginRequest import LoginRequest
from .models.AuthCheck import AuthCheck
from .models.User import User
from .models.Task import Task
from .models.Project import Project
from .utils.auth import verifyJWT,createJWT
from .models.UpdateUserRequest import UpdateUserRequest
from .models.GetProjects import GetProjects
import json

expired_tokens=[]

load_dotenv()

salt=os.getenv("salt")
frontend_url=os.getenv("frontend_url")
SECRET_KEY = os.getenv("SECRET_KEY")
db_connection=os.getenv("db_connection")
engine = create_engine(
    db_connection
)



app = FastAPI()
users=[]
tasks=[]
projects=[]



origins = [
    frontend_url,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



def CheckCircular(child,parent):
    circular=False
    ids=[]
    while child not in ids and parent is not None:
        ids.append(child)
        check=False
        for i in tasks:
            if i.id==parent:
                check=True
                child=i.id
                parent= i.parentId
        if check==False:
            circular=True
            break
    if parent!=None:
        circular=True
    return circular
ALGORITHM = "HS256"




@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.url.path in ["/auth/login", "/auth/register","/openapi.json"]:
        return await call_next(request)
    if request.url.path.startswith("/checkemail/",):
        return await call_next(request)
    if request.url.path.startswith("/docs",):
        return await call_next(request)
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        response = JSONResponse({"detail": "No auth header"}, status_code=401)
        response.headers["Access-Control-Allow-Origin"] = frontend_url
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response
    payload = verifyJWT(auth_header)
    if "error" in payload.keys():
        response=JSONResponse({"detail": "Token Expired"}, status_code=401)
        response.headers["Access-Control-Allow-Origin"] = frontend_url
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response
    if auth_header in expired_tokens:
        response = JSONResponse({"detail": "Token Expired"}, status_code=401)
        response.headers["Access-Control-Allow-Origin"] = frontend_url
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response
    return await call_next(request)




@app.get("/")
async def root():
    return {"message": "Hello World"}



@app.get("/conn")
async def conn():
    test = {}
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * from test"))
        count = 0
        for row in result:
            test[count] = {"id": row.id, "name": row.name, "description": row.description}
            count += 1
    return {"message": test}



@app.get("/checkemail/{email}")
async def checkemail(email: Annotated[str,Path(pattern = r"^[^\s@]+@[^\s@]+$")]):
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT email from users where email = '{email}'"))
        count = 0
        for row in result:
            count += 1
        if count>0:
            return {"unique": False}
        else:
            return {"unique": True}




@app.get("/all")
async def show():
    response=[]
    if len(users)==0:
        response.append("No users found")
    else:
        response.append(users)
    if len(tasks)==0:
        response.append("No tasks found")
    else:
        response.append(tasks)
    if len(projects)==0:
        response.append("No projects found")
    else:
        response.append(projects)
    return response



@app.post("/create_user")
async def create_user(user: User):
    users.append(user)
    return user



@app.post("/auth/register")
async def create_user(user: User):
    final_pass=hashlib.sha256((salt+str(user.passwordHash)).encode('utf-8')).hexdigest()
    user.passwordHash = final_pass
    id=''
    createdat=''
    with engine.connect() as conn:
        conn.execute(text(f"insert into users(firstName,lastName,email,passwordHash) values('{user.firstName}','{user.lastName}','{user.email}','{user.passwordHash}') ON CONFLICT (email) DO NOTHING"))
        conn.commit()
        result=conn.execute(text(f"SELECT id,createdAt from users where email = '{user.email}' and passwordHash='{user.passwordHash}'"))
        for row in result:
            id=row[0]
            createdat=row[1]
    return createJWT({"id":id,"createdat":createdat, "firstname":user.firstName,"lastname":user.lastName,"email":user.email})




@app.post("/auth/login")
async def create_user(login:Annotated[LoginRequest,Body()]):
    final_pass = hashlib.sha256((salt + str(login.password)).encode('utf-8')).hexdigest()
    firstname=''
    lastname=''
    id=''
    createdat=''
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT firstName,lastName,id,createdAt from users where email = '{login.email}' and passwordHash = '{final_pass}'"))
        count=0
        for row in result:
            firstname=row[0]
            lastname=row[1]
            id=row[2]
            createdat=row[3]
            count+=1
        if count>0:

            return createJWT({"id":id,"createdat":createdat, "firstname":firstname,"lastname":lastname,"email":login.email})
        else:
            return {"message":"Invalid credentials"}





@app.post("/me")
async def check_auth(check:Annotated[AuthCheck,Body()],response: Response):
    payload = verifyJWT("Bearer "+check.authorization)
    print(payload)
    if "error" not in payload.keys():
        return payload
    else:
        response.status_code=401
        return {"message":"Invalid token"}



@app.put("/users/{id}")
async def update_user(user:Annotated[UpdateUserRequest,Body()],id:Annotated[int,Path()],request:Request,response: Response):
    authorization=request.headers.get("Authorization")
    print("Auth: ",authorization)
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        print(id,payload["id"])
        if id!=payload["id"]:
            response.status_code = 401
            return {"message":"Invalid user id!"}
        else:
            createdat = ''
            with engine.connect() as conn:
                result = conn.execute(text(f"SELECT createdAt from users where email = '{payload['email']}'"))
                for row in result:
                    createdat = row[0]
                conn.execute(text(f"update users set firstName = '{user.firstname}',lastName='{user.lastname}', email='{user.email}' where id = {id} AND ((SELECT COUNT(*)FROM users u2 WHERE u2.email = '{user.email}') = 0 OR email ='{user.email}')"))
                conn.commit()
            if createdat=="":
                createdat=datetime.now()
            expired_tokens.append(authorization)
            return createJWT({"id":id,"createdat":createdat, "firstname":user.firstname,"lastname":user.lastname,"email":user.email})
    else:
        response.status_code=401
        return {"message":"Invalid token"}

@app.delete("/users/{id}")
async def delete_user(id:Annotated[int,Path()],request:Request,response: Response):
    authorization = request.headers.get("Authorization")
    print("Auth: ", authorization)
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        print(id,payload["id"])
        if id!=payload["id"]:
            response.status_code = 401
            return {"message":"Invalid user id!"}
        else:
            expired_tokens.append(authorization)
            with engine.connect() as conn:
                conn.execute(text(f"delete from projects where ownerid = {id}"))
                conn.execute(text(f"delete from users where id = {id}"))
                conn.commit()
            response.status_code = 200
            return {"message": "User deleted!"}
    else:
        response.status_code=401
        return {"message":"Invalid token"}




@app.post("/projects")
async def create_project(project:Annotated[Project, Body()],request:Request,response: Response):
    authorization=request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        with engine.connect() as conn:
            conn.execute(text(f"insert into projects(name,description,status,ownerId) values('{project.name}','{project.description}','{project.status}',{payload['id']})"))
            conn.commit()
        response.status_code = 200
        return {"message": "Project created!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}



@app.get("/projects")
async def get_projects(query:Annotated[GetProjects,Query()],response: Response,request: Request):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        count=0
        sql="select t.*, COUNT(*) OVER() AS total_count from(select * from projects where "
        if 'name' in query.model_fields_set:
            sql+=f"name LIKE '%{query.name}%' "
            count+=1
        if 'status' in query.model_fields_set and count>0:
            sql+=f" and status='{query.status}' "
        elif 'status' in query.model_fields_set and count==0:
            sql+=f"status='{query.status}' "
            count+=1
        if count>0:
            sql+=f"and ownerid={payload['id']} "
        else:
            sql+=f"ownerId={payload['id']} "
        sql+=f") t order by createdat {query.order} LIMIT {query.limit} OFFSET {query.offset}"
        projects_list = []
        print(sql)
        with engine.connect() as conn:
            result = conn.execute(text(sql))
            for row in result:
                projects_list.append({"name":row.name,"description":row.description,"status":row.status,"creation_date":row.createdat,"limit":row.total_count,"id":row.id})
        response.status_code = 200
        return projects_list


    else:
        response.status_code = 401
        return {"message": "Invalid token"}



@app.get("/projects/{id}")
async def get_project(id:Annotated[int,Path()],request: Request,response: Response):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        project={}
        count = 0
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT name,description,createdat,status,ownerid from projects where id = '{id}'"))
            for row in result:
                if row.ownerid!=payload["id"]:
                    response.status_code = 401
                    return {"message":"Unauthorized access!"}
                else:
                    project = {"name": row.name, "description": row.description, "createdat": row.createdat,"status": row.status}
                    count+=1
        if count>0:
            print(project)
            response.status_code = 200
            return project
        else:
            response.status_code = 404
            return {"message":"Project not found!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}




@app.put("/projects/{id}")
async def update_project(id:Annotated[int,Path()],request: Request,response: Response,project:Annotated[Project,Body()]):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        with engine.connect() as conn:
            conn.execute(text(f"update projects set name = '{project.name}',description='{project.description}', status='{project.status}' where id = {id} and ownerid = {payload['id']}"))
            conn.commit()
        response.status_code = 200
        return {"message": "Project updated!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}




@app.delete("/projects/{id}")
async def delete_project(id:Annotated[int,Path()],request: Request,response: Response):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        with engine.connect() as conn:
            conn.execute(text(f"delete from projects where id = {id} and ownerid = {payload['id']}"))
            conn.commit()
        response.status_code = 200
        return {"message": "Project deleted!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}


@app.post("/tasks")
async def create_task(task:Annotated[Task, Body()],request:Request,response: Response):
    authorization=request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        with engine.connect() as conn:
            conn.execute(text(f"INSERT INTO tasks (title, description, priority, status, dueDate, projectId, createdBy,parentId) VALUES ('{task.title}','{task.description}','{task.priority}','{task.status}','{task.dueDate}',{task.projectId},{payload['id']},{task.parentId})"))
            conn.commit()
        response.status_code = 200
        return {"message": "task created!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}



