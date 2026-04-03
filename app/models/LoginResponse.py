from pydantic import BaseModel,Field

class LoginResponse(BaseModel):
    firstname: str = Field(min_length=1,max_length=30,description="First Name")
    lastname: str = Field(min_length=1,max_length=30,description="Last Name")
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern=r"^[^@]+@[^@]+$")
    token:str = Field(min_length=1,max_length=256,description="JWT Token")