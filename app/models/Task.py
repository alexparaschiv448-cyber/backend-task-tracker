from pydantic import BaseModel,Field
from typing import Literal
from datetime import date



class Task(BaseModel):
    id:int
    title: str = Field(min_length=1,max_length=100,description="Title")
    description: str = Field(min_length=1,max_length=100,description="Description")
    priority: int = Field(ge=0,le=5,description="Priority")
    status:Literal["New","In Progress","Done"]="New"
    dueDate:date
    parentId:int |None=None
    projectId:int
    createdBy: str = Field(min_length=1,max_length=30,description="Created By User")