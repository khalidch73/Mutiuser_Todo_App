from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from app.auth import current_user, get_user_from_db, hash_password, oauth_scheme
from app.db import get_session
from app.models import Register_User, User

# Create a new FastAPI router for user-related endpoints
user_router = APIRouter(
    prefix="/user",
    tags=["user"],
    responses={404: {"description": "Not found"}}
)

@user_router.get("/")
async def read_user():
    """
    Endpoint to return a welcome message.
    """
    return {"message": "Welcome to todo app User Page"}

@user_router.post("/register")
async def register_user(new_user: Annotated[Register_User, Depends()],
                        session: Annotated[Session, Depends(get_session)]):
    """
    Endpoint to register a new user.
    - new_user: The user data from the request body.
    - session: The database session dependency.
    """
    # Check if a user with the provided username or email already exists
    db_user = get_user_from_db(session, new_user.username, new_user.email)
    if db_user:
        raise HTTPException(status_code=409, detail="User with these credentials already exists")
    
    # Create a new user with hashed password
    user = User(username=new_user.username,
                email=new_user.email,
                password=hash_password(new_user.password))
    
    # Add the new user to the session and commit the transaction
    session.add(user)
    session.commit()
    session.refresh(user)
    
    return {"message": f"User with username {user.username} successfully registered"}

@user_router.get('/me')
async def user_profile(current_user: Annotated[User, Depends(current_user)]):
    """
    Endpoint to get the current user's profile.
    - current_user: The authenticated user from the dependency.
    """
    return current_user
