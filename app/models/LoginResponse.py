from pydantic import BaseModel,Field

from datetime import datetime
class LoginResponse(BaseModel):
    id:int
    firstname: str = Field(min_length=1,max_length=30,description="First Name")
    lastname: str = Field(min_length=1,max_length=30,description="Last Name")
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern=r"^[^@]+@[^@]+$")
    token:str = Field(min_length=1,max_length=500,description="JWT Token")
    createdat: str = Field(min_length=1,max_length=30,description="Date of creation")