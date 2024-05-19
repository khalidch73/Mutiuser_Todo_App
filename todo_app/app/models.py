from fastapi import Form  # Import Form for handling form data in FastAPI
from pydantic import BaseModel  # Import BaseModel from Pydantic for data validation
from sqlmodel import SQLModel, Field  # Import SQLModel and Field from SQLModel for ORM and field definitions
from typing import Annotated  # Import Annotated for type annotations

# Define a Todo model representing a to-do item, inheriting from SQLModel for ORM mapping
class Todo (SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)  # Primary key, auto-incremented
    content: str = Field(index=True, min_length=3, max_length=54)  # Content of the to-do item, indexed with length constraints
    is_completed: bool = Field(default=False)  # Boolean flag indicating if the to-do item is completed
    user_id: int = Field(foreign_key="user.id")  # Foreign key linking to the User table

# Define a User model representing a user, inheriting from SQLModel for ORM mapping
class User (SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)  # Primary key, auto-incremented
    username: str  # Username of the user
    email: str  # Email of the user
    password: str  # Password of the user

# Define a model for user registration, inheriting from BaseModel for data validation
class Register_User (BaseModel):
    username: Annotated[str, Form()]  # Username field, sourced from form data
    email: Annotated[str, Form()]  # Email field, sourced from form data
    password: Annotated[str, Form()]  # Password field, sourced from form data

# Define a model for tokens, inheriting from BaseModel for data validation
class Token (BaseModel):
    access_token: str  # Access token string
    token_type: str  # Type of the token, e.g., "bearer"
    refresh_token: str  # Refresh token string

# Define a model for token data, inheriting from BaseModel for data validation
class TokenData (BaseModel):
    username: str  # Username associated with the token

# Define a model for creating a to-do item, inheriting from BaseModel for data validation
class Todo_Create (BaseModel):
    content: str  # Content of the to-do item

# Define a model for editing a to-do item, inheriting from BaseModel for data validation
class Todo_Edit (BaseModel):
    content: str  # New content of the to-do item
    is_completed: bool  # Flag indicating if the to-do item is completed

# Define a model for refresh token data, inheriting from BaseModel for data validation
class RefreshTokenData (BaseModel):
    email: str  # Email associated with the refresh token
