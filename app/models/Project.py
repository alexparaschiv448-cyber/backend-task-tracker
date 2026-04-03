from pydantic import BaseModel,Field
from typing import Literal
from datetime import datetime


class Project(BaseModel):
    id:int
    name: str = Field(min_length=1,max_length=30,description="Project Name")
    description: str = Field(min_length=1,max_length=30,description="Project Description")
    status: Literal["New", "In Progress", "Done"] = "New"
    ownerId:int
    createdAt: datetime = Field(default_factory=datetime.now)