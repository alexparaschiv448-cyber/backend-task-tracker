from typing import Literal,Annotated
from fastapi import FastAPI,Query,Path,Header,Cookie,Body, HTTPException
from pydantic import BaseModel,Field
from datetime import datetime,date, timedelta,timezone
import time
from sqlalchemy import create_engine,text
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import hashlib
import jwt


engine = create_engine(
    "postgresql+psycopg2://dev:dev@localhost:5432/dev"
)



app = FastAPI()
users=[]
tasks=[]
projects=[]
salt="5ga23fdkh354"


origins = [
    "http://localhost:5122",  # your React app
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,        # or ["*"] for all (dev only)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Test(BaseModel):
    name: str = Field(min_length=1,max_length=20,description="Name")
    description: str | None = Field(None,min_length=1,max_length=20,description="Description")

class User(BaseModel):
    firstName: str = Field(min_length=1,max_length=30,description="First Name")
    lastName: str = Field(min_length=1,max_length=30,description="Last Name")
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern=r"^[^@]+@[^@]+$")
    passwordHash:str = Field(min_length=1,max_length=100,description="Password Hash")

class Project(BaseModel):
    id:int
    name: str = Field(min_length=1,max_length=30,description="Project Name")
    description: str = Field(min_length=1,max_length=30,description="Project Description")
    status: Literal["New", "In Progress", "Done"] = "New"
    ownerId:int
    createdAt: datetime = Field(default_factory=datetime.now)

class Task(BaseModel):
    id:int
    title: str = Field(min_length=1,max_length=100,description="Title")
    description: str = Field(min_length=1,max_length=100,description="Description")
    priority: int = Field(ge=0,le=5,description="Priority")
    status:Literal["New","In Progress","Done"]="New"
    dueDate:date
    parentId:int |None=None
    projectId:int
    createdBy: str = Field(min_length=1,max_length=30,description="Created By User")

class LoginRequest(BaseModel):
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern=r"^[^@]+@[^@]+$")
    password:str = Field(min_length=1,max_length=100,description="Password Hash")

class LoginResponse(BaseModel):
    firstname: str = Field(min_length=1,max_length=30,description="First Name")
    lastname: str = Field(min_length=1,max_length=30,description="Last Name")
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern=r"^[^@]+@[^@]+$")
    token:str = Field(min_length=1,max_length=256,description="JWT Token")

class AuthCheck(BaseModel):
    authorization:str = Field(min_length=1,max_length=256,description="JWT Token")


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
SECRET_KEY = "d2h4j5jn7jbjksadJNA9r3"
ALGORITHM = "HS256"


def create_jwt(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=30)

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    response=LoginResponse(firstname=data['firstname'],lastname=data['lastname'],email=data['email'],token=token)
    print("Raspuns!!!")
    print(response)
    return response

def verify_jwt(authorization: str):
    try:
        token = authorization.split(" ")[1]

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        return payload
    except:
        return {"error":"Invalid token!"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    #print("Middleware called")
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.url.path in ["/auth/login", "/auth/register","/openapi.json"]:
        return await call_next(request)
    if request.url.path.startswith("/checkemail/",):
        return await call_next(request)
    if request.url.path.startswith("/docs",):
        return await call_next(request)
    #print("Middleware passed")
    payload=""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        response = JSONResponse({"detail": "No auth header"}, status_code=401)
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:5122"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        #print("INVALIDDD")
        return response
    payload = verify_jwt(auth_header)
    #request.state.user = payload  # optional: store for later use
    if "error" in payload.keys():
        #print("INVALID")
        response=JSONResponse({"detail": "Token Expired"}, status_code=401)
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:5122"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response
    #except jwt.InvalidTokenError:
    #    response = JSONResponse({"detail": "Invalid token"}, status_code=401)
    #    response.headers["Access-Control-Allow-Origin"] = "http://localhost:5122"
    #    response.headers["Access-Control-Allow-Credentials"] = "true"
    #    return response
    #print("middleware finished")
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
    test = {}
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT email from users where email = '{email}'"))
        count = 0
        for row in result:
            test[count] = {"email":row.email}
            count += 1
    return {"message": test}


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
    #users.append(user)
    final_pass=hashlib.sha256((salt+str(user.passwordHash)).encode('utf-8')).hexdigest()
    user.passwordHash = final_pass
    with engine.connect() as conn:
        conn.execute(text(f"insert into users(firstName,lastName,email,passwordHash) values('{user.firstName}','{user.lastName}','{user.email}','{user.passwordHash}')"))
        conn.commit()
    return create_jwt({"firstname":user.firstName,"lastname":user.lastName,"email":user.email})
@app.post("/auth/login")
async def create_user(login:Annotated[LoginRequest,Body()]):
    final_pass = hashlib.sha256((salt + str(login.password)).encode('utf-8')).hexdigest()
    #user.passwordHash = final_pass
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
            return create_jwt({"firstname":firstname,"lastname":lastname,"email":login.email})
        else:
            return {"message":"Invalid credentials"}

@app.post("/me")
async def check_auth(check:Annotated[AuthCheck,Body()],response: Response):
    payload = verify_jwt("Bearer "+check.authorization)
    print(payload)
    if "error" not in payload.keys():
        return payload
    else:
        response.status_code=401
        return {"message":"Invalid token"} #status code return



@app.post("/test")
async def test(test: Test):
    with engine.connect() as conn:
        if test.description is not None:
            conn.execute(text(f"insert into test(name,description) values('{test.name}','{test.description}')"))
        else:
            conn.execute(text(f"insert into test(name) values('{test.name}')"))
        conn.commit()
    return "done"

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
