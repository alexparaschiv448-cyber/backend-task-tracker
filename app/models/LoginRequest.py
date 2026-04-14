from pydantic import BaseModel,Field

class LoginRequest(BaseModel):
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern = r"^[^\s@]+@[^\s@]+$")
    password:str = Field(min_length=1,max_length=100,description="Password Hash")