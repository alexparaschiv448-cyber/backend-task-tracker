from pydantic import BaseModel,Field
from typing import Literal
from datetime import datetime



class Task(BaseModel):
    title: str = Field(min_length=1,max_length=50,description="Title")
    description: str | None = Field(None,min_length=1,max_length=1000,description="Description")
    priority:Literal["0 - Highest","1 - High","2 - Medium","3 - Low","4 - Lowest"]="4 - Lowest"
    status:Literal["New","In Progress","Done"]="New"
    dueDate:datetime
    parentId:int |None=None
    projectId:int