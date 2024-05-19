from fastapi import FastAPI, Depends, HTTPException, status
from contextlib import asynccontextmanager
from app.db import create_db_and_tables, get_session
from app.router import user
from typing import Annotated
from app.models import Todo_Create, Todo_Edit, Token, User, Todo
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from datetime import timedelta
from app.auth import EXPIRY_TIME, authenticate_user, create_access_token, current_user, validate_refresh_token, create_refresh_token

# Async context manager for application lifespan events
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Creating tables..")
    create_db_and_tables()  # Create database tables
    yield  # Application startup
    # Cleanup logic (if any) goes here

# Create FastAPI app with custom lifespan and metadata
app = FastAPI(
    lifespan=lifespan,
    title="Todo API",
    version="0.0.1",
    servers=[
        {
            "url": "http://127.0.0.1:8000",  # Update this to the appropriate URL (e.g., NGROK URL)
            "description": "Development Server"
        }
    ]
)

# Include the user router from app.router
app.include_router(router=user.user_router)

# Root endpoint
@app.get("/")
def read_root():
    return {"Welcome": "Todo API"}

# Login endpoint
@app.post('/token', response_model=Token)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                session: Annotated[Session, Depends(get_session)]):
    # Authenticate user using provided form data
    user = authenticate_user(form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Generate access and refresh tokens
    expire_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token({"sub": form_data.username}, expire_time)

    refresh_expire_time = timedelta(days=7)
    refresh_token = create_refresh_token({"sub": user.email}, refresh_expire_time)

    return Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token)

# Refresh token endpoint
@app.post("/token/refresh")
def refresh_token(old_refresh_token: str,
                  session: Annotated[Session, Depends(get_session)]):
    # Validate the old refresh token
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, Please login again",
        headers={"www-Authenticate": "Bearer"}
    )
    
    user = validate_refresh_token(old_refresh_token, session)
    if not user:
        raise credential_exception
    
    # Generate new access and refresh tokens
    expire_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token({"sub": user.username}, expire_time)

    refresh_expire_time = timedelta(days=7)
    refresh_token = create_refresh_token({"sub": user.email}, refresh_expire_time)

    return Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token)

# Create a new todo item
@app.post('/todos/', response_model=Todo)
async def create_todo(current_user: Annotated[User, Depends(current_user)],
                      todo: Todo_Create, 
                      session: Annotated[Session, Depends(get_session)]):
    # Create a new todo item for the current user
    new_todo = Todo(content=todo.content, user_id=current_user.id)
    session.add(new_todo)
    session.commit()
    session.refresh(new_todo)
    return new_todo

# Get all todo items for the current user
@app.get('/todos/', response_model=list[Todo])
async def get_all(current_user: Annotated[User, Depends(current_user)],
                  session: Annotated[Session, Depends(get_session)]):
    # Retrieve all todo items for the current user
    todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()
    if todos:
        return todos
    else:
        raise HTTPException(status_code=404, detail="No Task found")

# Get a single todo item by ID
@app.get('/todos/{id}', response_model=Todo)
async def get_single_todo(id: int, 
                          current_user: Annotated[User, Depends(current_user)],
                          session: Annotated[Session, Depends(get_session)]):
    # Retrieve a specific todo item for the current user
    user_todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()
    matched_todo = next((todo for todo in user_todos if todo.id == id), None)

    if matched_todo:
        return matched_todo
    else:
        raise HTTPException(status_code=404, detail="No Task found")

# Edit a todo item
@app.put('/todos/{id}')
async def edit_todo(id: int, 
                    todo: Todo_Edit,
                    current_user: Annotated[User, Depends(current_user)], 
                    session: Annotated[Session, Depends(get_session)]):
    # Update a specific todo item for the current user
    user_todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()
    existing_todo = next((todo for todo in user_todos if todo.id == id), None)

    if existing_todo:
        existing_todo.content = todo.content
        existing_todo.is_completed = todo.is_completed
        session.add(existing_todo)
        session.commit()
        session.refresh(existing_todo)
        return existing_todo
    else:
        raise HTTPException(status_code=404, detail="No task found")

# Delete a todo item
@app.delete('/todos/{id}')
async def delete_todo(id: int,
                      current_user: Annotated[User, Depends(current_user)],
                      session: Annotated[Session, Depends(get_session)]):
    # Delete a specific todo item for the current user
    user_todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()
    todo = next((todo for todo in user_todos if todo.id == id), None)
    
    if todo:
        session.delete(todo)
        session.commit()
        return {"message": "Task successfully deleted"}
    else:
        raise HTTPException(status_code=404, detail="No task found")
