from pydantic import BaseModel,Field

class User(BaseModel):
    firstName: str = Field(min_length=1,max_length=30,description="First Name")
    lastName: str = Field(min_length=1,max_length=30,description="Last Name")
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern=r"^[^@]+@[^@]+$")
    passwordHash:str = Field(min_length=1,max_length=100,description="Password Hash")