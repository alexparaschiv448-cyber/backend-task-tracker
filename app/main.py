from typing import Literal,Annotated
from fastapi import FastAPI,Query,Path,Header,Cookie,Body
from pydantic import BaseModel,Field
import jwt
from datetime import datetime,date
import time


app = FastAPI()
users=[]
tasks=[]
projects=[]

class User(BaseModel):
    id:int
    firstName: str = Field(min_length=1,max_length=30,description="First Name")
    lastName: str = Field(min_length=1,max_length=30,description="Last Name")
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern=r"^[^@]+@[^@]+$")
    passwordHash:str = Field(min_length=1,max_length=100,description="Password Hash")
    createdAt: datetime = Field(default_factory=datetime.now)

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

@app.get("/")
async def root():
    return {"message": "Hello World"}
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
    user.createdAt = datetime.now()
    users.append(user)
    return user

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
