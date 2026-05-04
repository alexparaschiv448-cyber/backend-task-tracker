from pydantic import BaseModel,Field

class UpdateUserRequest(BaseModel):
    email: str = Field(min_length=1,max_length=30,description="Email Address",pattern = r"^[^\s@]+@[^\s@]+$")
    #password:str = Field(min_length=1,max_length=100,description="Password Hash")
    firstname: str = Field(min_length=1, max_length=30, pattern=r"^\S+$", description="First Name")
    lastname: str = Field(min_length=1, max_length=30, pattern=r"^\S+$", description="Last Name")