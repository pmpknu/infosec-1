from datetime import datetime

import bleach
from pydantic import BaseModel, Field, field_validator


class UserBase(BaseModel):
    username: str = Field(min_length=3, max_length=100)


class UserCreate(UserBase):
    password: str = Field(min_length=6, max_length=200)


class UserOut(UserBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - not a password


class TokenPayload(BaseModel):
    sub: str
    exp: int


class LoginRequest(BaseModel):
    username: str
    password: str


class PostBase(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=4000)


class PostCreate(PostBase):
    pass


class PostOut(PostBase):
    id: int
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True

    @field_validator("title", "content", mode="before")
    @classmethod
    def sanitize_output(cls, value: str) -> str:
        return bleach.clean(value, strip=True)
