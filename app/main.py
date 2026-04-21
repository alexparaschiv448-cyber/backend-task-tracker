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
from .models.GetTasks import GetTasks
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

ALGORITHM = "HS256"

def CheckCirucular(id,pid):
    circular=False
    ids=[id]
    with engine.connect() as conn:
        while pid:
            result = conn.execute(text(f"SELECT id,parentid from tasks where id = {pid}")).first()
            id=result.id
            if id in ids:
                circular=True
                break
            else:
                ids.append(id)
                pid=result.parentid
    return circular




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
                conn.execute(text(f"delete from tasks where projectid in (select id from projects where ownerid={id})"))
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
    sql=""
    if "description" in project.model_fields_set:
        sql=f"insert into projects(name,description,status,ownerId) values('{project.name}','{project.description}','{project.status}',{payload['id']})"
    else:
        sql=f"insert into projects(name,status,ownerId) values('{project.name}','{project.status}',{payload['id']})"

    if "error" not in payload.keys():
        with engine.connect() as conn:
            conn.execute(text(sql))
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
    sql = ""
    if "description" in project.model_fields_set:
        sql = f"update projects set name = '{project.name}',description='{project.description}', status='{project.status}' where id = {id} and ownerid = {payload['id']}"
    else:
        sql = f"update projects set name = '{project.name}',description=null, status='{project.status}' where id = {id} and ownerid = {payload['id']}"
    if "error" not in payload.keys():
        with engine.connect() as conn:
            conn.execute(text(sql))
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
            conn.execute(text(f"delete from tasks where projectid={id} and (select count(*) from projects where id={id} and ownerid={payload['id']})=1 "))
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
    sql=f"INSERT INTO tasks (title,  priority, status, dueDate, projectId, createdBy"
    sql2=f") VALUES ('{task.title}','{task.priority}','{task.status}','{task.dueDate}',{task.projectId},{payload['id']}"
    if "description" in task.model_fields_set:
        sql+=f",description"
        sql2+=f",'{task.description}'"
    if "parentId" in task.model_fields_set:
        sql+=f",parentId"
        sql2+=f",{task.parentId}"
    sql=sql+sql2+") "
    count=0
    if "error" not in payload.keys():
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT name from projects where id = '{task.projectId}' and ownerid = {payload['id']}"))
            for row in result:
                count=1
        if count>0:
            with engine.connect() as conn:
                conn.execute(text(sql))
                conn.commit()
            response.status_code = 200
            return {"message": "task created!"}
        else:
            response.status_code = 401
            return {"message": "Unauthorized request!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}


@app.get("/tasks")
async def get_tasks(query:Annotated[GetTasks,Query()],response: Response,request: Request):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        count=0
        with engine.connect() as conn:
            result=conn.execute(text(f"select * from projects where id = {query.projectId} and ownerid = {payload['id']}"))
            for row in result:
                count=1
        if count>0:
            count=0
            sql="select t.*, COUNT(*) OVER() AS total_count from(select * from tasks where "
            if 'title' in query.model_fields_set:
                sql+=f"title LIKE '%{query.title}%' "
                count+=1
            if 'status' in query.model_fields_set and count>0:
                sql+=f" and status='{query.status}' "
            elif 'status' in query.model_fields_set and count==0:
                sql+=f"status='{query.status}' "
                count+=1
            if 'priority' in query.model_fields_set and count>0:
                sql+=f" and priority='{query.priority}' "
            elif 'priority' in query.model_fields_set and count==0:
                sql+=f"priority='{query.priority}' "
                count+=1
            if count>0:
                sql+=f"and projectId={query.projectId} "
            else:
                sql+=f"projectId={query.projectId} "
            sql+=f") t order by dueDate {query.order} LIMIT {query.limit} OFFSET {query.offset}"
            tasks_list = []
            with engine.connect() as conn:
                result = conn.execute(text(sql))
                for row in result:
                    tasks_list.append({"title":row.title,"description":row.description,"status":row.status,"priority":row.priority,"duedate":row.duedate,"limit":row.total_count,"id":row.id,"projectid":row.projectid})
            response.status_code = 200
            return tasks_list
        else:
            response.status_code = 401
            return {"message": "Unauthorized request!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}


@app.get("/tasks/{id}")
async def get_task(id:Annotated[int,Path()],request: Request,response: Response):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        task={}
        count = 0
        with engine.connect() as conn:
            result = conn.execute(text(f"select t.*,(select distinct e.title from tasks e where id=t.parentid) as parent_title from tasks t where id={id} and (select count(*) from projects where id=t.projectid and ownerid={payload['id']})=1"))
            for row in result:
                task = {"title": row.title, "description": row.description, "duedate": row.duedate,"status": row.status,"priority": row.priority,"parentname": row.parent_title,"parentid":row.parentid}
                count+=1
        if count>0:
            response.status_code = 200
            return task
        else:
            response.status_code = 401
            return {"message":"Unauthorized access!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}

@app.get("/search/parent/{id}")
async def search_parent(id:Annotated[int,Path()],projectid:Annotated[int,Query()],title:Annotated[str,Query()],request: Request,response: Response):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        tasks=[]
        count=0
        with engine.connect() as conn:
            sql=f"select title,id from tasks where id!={id} and projectid={projectid} and (select count(*) from projects where id={projectid} and ownerid={payload['id']})=1 and title like '%{title}%' limit 5 offset 0"
            result = conn.execute(text(sql))
            for row in result:
                tasks.append({"title":row.title,"id":row.id})
                count=1
        if count>0:
            response.status_code=200
            return tasks
        else:
            response.status_code=404
            return {"message":"No tasks found!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}


@app.put("/tasks/{id}")
async def update_task(id:Annotated[int,Path()],request: Request,response: Response,task:Annotated[Task,Body()]):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        sql=f"update tasks set title = '{task.title}', status='{task.status}', priority='{task.priority}', duedate='{task.dueDate}'"
        if "description" in task.model_fields_set and task.description:
            sql+=f",description = '{task.description}'"
        else:
            sql += f",description = null"
        if "parentId" in task.model_fields_set and task.parentId:
            if CheckCirucular(id,task.parentId):
                response.status_code = 422
                return {"message": "Circular parent relation!"}
            print("YESSS")
            sql+=f",parentid = {task.parentId}"
        else:
            sql+=f",parentid = null"
        sql+=f" where id = {id} and (select count(*) from projects where id={task.projectId} and ownerid={payload['id']})=1"
        print(sql)
        with engine.connect() as conn:
            conn.execute(text(sql))
            conn.commit()
        response.status_code = 200
        return {"message": "Task updated!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}



@app.delete("/tasks/{id}")
async def delete_project(id:Annotated[int,Path()],request: Request,response: Response,projectid:Annotated[int,Query()]):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        with engine.connect() as conn:
            conn.execute(text(f"update tasks set parentid = null where parentid={id} and (select count(*) from projects where id={projectid} and ownerid={payload['id']})=1"))
            conn.execute(text(f"delete from tasks where id = {id} and (select count(*) from projects where id={projectid} and ownerid={payload['id']})=1"))
            conn.commit()
        response.status_code = 200
        return {"message": "Task deleted!"}
    else:
        response.status_code = 401
        return {"message": "Invalid token"}



@app.get("/dashboard/statuses")
async def get_statuses(request: Request,response: Response):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        with engine.connect() as conn:
            result=conn.execute(text(f"select * from projects where ownerid={payload['id']}")).first()
            if not result:
                response.status_code=401
                return {"message": "Unauthorized request!"}
            result=conn.execute(text(f"SELECT p.id,p.name,COUNT(t.id) FILTER (WHERE t.status = 'New') AS new_count,COUNT(t.id) FILTER (WHERE t.status = 'In Progress') AS in_progress_count,COUNT(t.id) FILTER (WHERE t.status = 'Done') AS done_count FROM projects p LEFT JOIN tasks t ON t.projectid = p.id WHERE p.ownerid = {payload['id']} GROUP BY p.id, p.name ORDER BY p.name;"))
            response.status_code=200
            statuses=[]
            for row in result:
                statuses.append({"name":row.name,"new":row.new_count,"in_progress":row.in_progress_count,"done":row.done_count})
            return statuses



@app.get("/dashboard/priorities")
async def get_priorities(request: Request,response: Response):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        with engine.connect() as conn:
            result=conn.execute(text(f"select * from projects where ownerid={payload['id']}")).first()
            if not result:
                response.status_code=401
                return {"message": "Unauthorized request!"}
            result=conn.execute(text(f"SELECT COUNT(t.id) FILTER (WHERE t.priority = '0 - Highest' and t.status!='Done') AS highest_count, COUNT(t.id) FILTER (WHERE t.priority = '1 - High' and t.status!='Done') AS high_count, COUNT(t.id) FILTER (WHERE t.priority = '2 - Medium' and t.status!='Done') AS medium_count, COUNT(t.id) FILTER (WHERE t.priority = '3 - Low' and t.status!='Done') AS low_count, COUNT(t.id) FILTER (WHERE t.priority = '4 - Lowest' and t.status!='Done') AS lowest_count FROM tasks t  WHERE t.createdby = {payload['id']} "))
            response.status_code=200
            priorities=[]
            for row in result:
                priorities.append({"highest":row.highest_count,"high":row.high_count,"medium":row.medium_count,"low":row.low_count,"lowest":row.lowest_count})
            return priorities





@app.get("/dashboard/summary")
async def get_summary(request: Request,response: Response):
    authorization = request.headers.get("Authorization")
    payload = verifyJWT(authorization)
    if "error" not in payload.keys():
        with engine.connect() as conn:
            summary={}
            result = conn.execute(text(f"select count(id) as task_count from tasks where createdby={payload['id']}")).first()
            summary["task_count"] = result.task_count
            result= conn.execute(text(f"select count(id) as project_count from projects where ownerid={payload['id']}")).first()
            summary["project_count"] = result.project_count
            response.status_code = 200
            print(summary)
            return summary