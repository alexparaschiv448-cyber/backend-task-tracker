from pydantic import BaseModel,Field
from typing import Literal


class GetProjects(BaseModel):
    name: str | None= Field(None,min_length=1, max_length=50, description="Project Name")
    status: Literal["New", "In Progress", "Done"] | None = None
    order: Literal["DESC","ASC"]="DESC"
    limit: int = Field(ge=1, le=10)
    offset: int = Field(ge=0)
