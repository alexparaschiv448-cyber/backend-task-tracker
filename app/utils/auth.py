import jwt
from datetime import datetime, timedelta,timezone
from app.models.LoginResponse import LoginResponse
from dotenv import load_dotenv
import os


load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

def createJWT(data: dict):
    data['createdat'] = data['createdat'].strftime("%Y-%m-%d %H:%M:%S")
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=30)
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    response=LoginResponse(id=data['id'],createdat=data['createdat'],firstname=data['firstname'],lastname=data['lastname'],email=data['email'],token=token)
    return response



def verifyJWT(authorization: str):
    try:
        token = authorization.split(" ")[1]

        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        return payload
    except:
        return {"error":"Invalid token!"}