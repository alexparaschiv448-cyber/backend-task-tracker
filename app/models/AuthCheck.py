from pydantic import BaseModel,Field

class AuthCheck(BaseModel):
    authorization:str = Field(min_length=1,max_length=500,description="JWT Token")