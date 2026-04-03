from typing import Annotated
from fastapi import Path,Body
from datetime import datetime
from sqlalchemy import create_engine,text
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Request, Response
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
async def checkemail(email: Annotated[str,Path()]):
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
    with engine.connect() as conn:
        conn.execute(text(f"insert into users(firstName,lastName,email,passwordHash) values('{user.firstName}','{user.lastName}','{user.email}','{user.passwordHash}')"))
        conn.commit()


    return createJWT({"firstname":user.firstName,"lastname":user.lastName,"email":user.email})




@app.post("/auth/login")
async def create_user(login:Annotated[LoginRequest,Body()]):
    final_pass = hashlib.sha256((salt + str(login.password)).encode('utf-8')).hexdigest()
    firstname='';
    lastname='';
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT firstName,lastName from users where email = '{login.email}' and passwordHash = '{final_pass}'"))
        count=0
        for row in result:
            firstname=row[0]
            lastname=row[1]
            count+=1
        if count>0:

            return createJWT({"firstname":firstname,"lastname":lastname,"email":login.email})


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



@app.post("/create_project")
async def create_project(project: Project):
    project.createdAt = datetime.now()
    projects.append(project)
    return project



@app.post("/create_task")
async def create_task(task: Task):
    if task.parentId is not None and CheckCircular(task.id,task.parentId) == True:
        return "Invalid parent"
    tasks.append(task)
    return task
