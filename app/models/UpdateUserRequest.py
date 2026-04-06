from pydantic import BaseModel,Field

class UpdateUserRequest(BaseModel):
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern=r"^[^@]+@[^@]+$")
    #password:str = Field(min_length=1,max_length=100,description="Password Hash")
    firstname: str = Field(min_length=1, max_length=30, description="First Name")
    lastname: str = Field(min_length=1, max_length=30, description="Last Name")