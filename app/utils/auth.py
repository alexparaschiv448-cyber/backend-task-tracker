import jwt
from datetime import datetime, timedelta,timezone
from app.models.LoginResponse import LoginResponse
from dotenv import load_dotenv
from fastapi.responses import JSONResponse
import os


status={200:["CREATED","RETURNED","UPDATED","DELETED","AUTHORIZED"],404:"NOT_FOUND",401:"UNAUTHORIZED",403:"FORBIDDEN",422:"BAD_REQUEST"}

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

def createJWT(data: dict):
    data['createdat'] = data['createdat'].strftime("%Y-%m-%d %H:%M:%S")
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=8)
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    response=LoginResponse(id=data['id'],createdat=data['createdat'],firstname=data['firstname'],lastname=data['lastname'],email=data['email'],token=token)
    return response



def verifyJWT(authorization: str):
    try:
        token = authorization.split(" ")[1]

        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        return {"data":payload,"message":"Valid authorization!","code":status[200][4]}
    except:
        return {"message":"Invalid authorization!","code":status[401]}