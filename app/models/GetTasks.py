from pydantic import BaseModel,Field
from typing import Literal
from datetime import datetime


class GetTasks(BaseModel):
    title: str | None= Field(None,min_length=1, max_length=50, description="Project Name")
    status: Literal["New", "In Progress", "Done"] | None = None
    priority: Literal["0 - Highest", "1 - High", "2 - Medium", "3 - Low", "4 - Lowest"] | None= None
    order: Literal["DESC","ASC"]="ASC"
    limit: int = Field(ge=1, le=12)
    offset: int = Field(ge=0)
    projectId: int
