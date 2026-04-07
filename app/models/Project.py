from pydantic import BaseModel,Field
from typing import Literal
from datetime import datetime


class Project(BaseModel):
    name: str = Field(min_length=1,max_length=50,description="Project Name")
    description: str = Field(min_length=1,max_length=1000,description="Project Description")
    status: Literal["New", "In Progress", "Done"] = "New"
    createdAt: datetime = Field(default_factory=datetime.now)