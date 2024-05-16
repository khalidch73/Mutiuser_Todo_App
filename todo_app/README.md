## step:01 Create New Project 

```bash
poetry new todo_app --name app
```
```bash
cd todo_app
```

## step:02 add poetry initial pacakges in pyproject.toml file

```python
fastapi = "^0.110.0"
uvicorn = "^0.29.0"
sqlmodel = "^0.0.16"
psycopg = {extras = ["binary"], version = "^3.1.18"}
pytest = "^8.1.1"
httpx = "^0.27.0"
python-multipart = "^0.0.9"
passlib = {extras = ["bcrypt"], version = "^1.7.4"}
python-jose = {extras = ["cryptography"], version = "^3.3.0"}
psycopg2-binary = "^2.9.9"
```

```bash
poetry insatll
```
## step:03 create .env file

```python
DEBUG = True
DATABASE_URL = postgresql:add conecton string
TEST_DATABASE_URL = postgresql: add test conecton string
```

## step:04 create settings.py file in app dir

```python
from starlette.config import Config
from starlette.datastructures import Secret

try:
    config = Config(".env")
except FileNotFoundError:
    config = Config()

DATABASE_URL = config("DATABASE_URL", cast=Secret)

TEST_DATABASE_URL = config("TEST_DATABASE_URL", cast=Secret)
```

## step:05 create db.py file in app dir

```python
from app import settings
from sqlmodel import Session, SQLModel, create_engine


connection_string = str(settings.DATABASE_URL).replace(
    "postgresql", "postgresql+psycopg"
)


engine = create_engine(
    connection_string, connect_args={"sslmode": "require"}, pool_recycle=300
)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
```
## step:06 crete models.py in app dir

```python
from fastapi import Form
from pydantic import BaseModel
from sqlmodel import SQLModel, Field
from typing import Annotated


class Todo (SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    content: str = Field(index=True, min_length=3, max_length=54)
    is_completed: bool = Field(default=False)
    user_id: int = Field(foreign_key="user.id")


class User (SQLModel, table=True):
        id: int = Field(default=None, primary_key=True)
        username: str
        email:str
        password:str

class Register_User (BaseModel):
            username: Annotated[
            str,
            Form(),
        ]
            email: Annotated[
            str,
            Form(),
        ]
            password: Annotated[
            str,
            Form(),
        ]

class Token (BaseModel):
        access_token:str
        token_type: str
        refresh_token: str

class TokenData (BaseModel):
        username:str


class Todo_Create (BaseModel):
    content: str


class Todo_Edit (BaseModel):
       content:str
       is_completed: bool

class RefreshTokenData (BaseModel):
        email:str
```

## step:07 create auth.py in app dir

```python
from passlib.context import CryptContext
from sqlmodel import Session, select
from typing import Annotated
from app.db import get_session
from fastapi import Depends, HTTPException, status
from app.models import RefreshTokenData, TokenData, User, Todo
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timezone, timedelta


SECRET_KEY = 'ed60732905aeb0315e2f77d05a6cb57a0e408eaf2cb9a77a5a2667931c50d4e0' # generate your own secrete key
ALGORITHYM = 'HS256'
EXPIRY_TIME = 3

oauth_scheme = OAuth2PasswordBearer(tokenUrl="/token")

pwd_context = CryptContext(schemes="bcrypt")


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(password, hash_password):
    return pwd_context.verify(password, hash_password)


def get_user_from_db(session: Annotated[Session, Depends(get_session)],
                     username: str | None = None,
                     email: str | None = None):
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    print(user)
    if not user:
        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
        if user:
            return user

    return user


def authenticate_user(username,
                      password,
                      session: Annotated[Session, Depends(get_session)]):
    db_user = get_user_from_db(session=session, username=username)
    print(f""" authenticate {db_user} """)
    if not db_user:
        return False
    if not verify_password(password, db_user.password):
        return False
    return db_user


def create_access_token(data: dict, expiry_time: timedelta | None):
    data_to_encode = data.copy()
    if expiry_time:
        expire = datetime.now(timezone.utc) + expiry_time
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        data_to_encode, SECRET_KEY, algorithm=ALGORITHYM, )
    return encoded_jwt


def current_user(token: Annotated[str, Depends(oauth_scheme)],
                 session: Annotated[Session, Depends(get_session)]):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, Please login again",
        headers={"www-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, ALGORITHYM)
        username: str | None = payload.get("sub")

        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credential_exception
    user = get_user_from_db(session, username=token_data.username)
    if not user:
        raise credential_exception
    return user


def create_refresh_token(data: dict, expiry_time: timedelta | None):
    data_to_encode = data.copy()
    if expiry_time:
        expire = datetime.now(timezone.utc) + expiry_time
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        data_to_encode, SECRET_KEY, algorithm=ALGORITHYM, )
    return encoded_jwt


def validate_refresh_token(token: str,
                           session: Annotated[Session, Depends(get_session)]):

    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, Please login again",
        headers={"www-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, ALGORITHYM)
        email: str | None = payload.get("sub")
        if email is None:
            raise credential_exception
        token_data = RefreshTokenData(email=email)

    except:
        raise JWTError
    user = get_user_from_db(session, email=token_data.email)
    if not user:
        raise credential_exception
    return user
```

## step:08 make a new folder router in app dir 

user.py

```python
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from app.auth import current_user, get_user_from_db, hash_password, oauth_scheme
from app.db import get_session
from app.models import Register_User, User



user_router = APIRouter(
    prefix="/user",
    tags=["user"],
    responses={404: {"description": "Not found"}}
)

@user_router.get("/")
async def read_user():
    return {"message": "Welcome to todo app User Page"}

@user_router.post("/register")
async def regiser_user (new_user:Annotated[Register_User, Depends()],
                        session:Annotated[Session, Depends(get_session)]):
    
    db_user = get_user_from_db(session, new_user.username, new_user.email)
    if db_user:
        raise HTTPException(status_code=409, detail="User with these credentials already exists")
    user = User(username = new_user.username,
                email = new_user.email,
                password = hash_password(new_user.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"message": f""" User with {user.username} successfully registered """}


@user_router.get('/me')
async def user_profile (current_user:Annotated[User, Depends(current_user)]):

    return current_user
```



## step:09 create main.py 

```python
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



@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Creating tables..")
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan, title="Todo API", 
    version="0.0.1",
    servers=[
        {
            "url": "http://127.0.0.1:8000", # ADD NGROK URL Here Before Creating GPT Action
            "description": "Development Server"
        }
        ])

app.include_router(router=user.user_router)

# 01 Define the route to read route
@app.get("/")
def read_root():
    return {"Hello": "World"}

# login . username, password
@app.post('/token', response_model=Token)
async def login(form_data:Annotated[OAuth2PasswordRequestForm, Depends()],
                session:Annotated[Session, Depends(get_session)]):
    user = authenticate_user (form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    expire_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token({"sub":form_data.username}, expire_time)

    refresh_expire_time = timedelta(days=7)
    refresh_token = create_refresh_token({"sub":user.email}, refresh_expire_time)

    return Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token)


@app.post("/token/refresh")
def refresh_token(old_refresh_token:str,
                  session:Annotated[Session, Depends(get_session)]):
    
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, Please login again",
        headers={"www-Authenticate":"Bearer"}
    )
    
    user = validate_refresh_token(old_refresh_token,
                                  session)
    if not user:
        raise credential_exception
    
    expire_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token({"sub":user.username}, expire_time)

    refresh_expire_time = timedelta(days=7)
    refresh_token = create_refresh_token({"sub":user.email}, refresh_expire_time)

    return Token(access_token=access_token, token_type= "bearer", refresh_token=refresh_token)


```
## step:10 run project 

```bash
poetry run uvicorn app.main:app --reload
```

### check endpoints 

```bash 
http://127.0.0.1:8000/
```
```bash 
http://127.0.0.1:8000/user/
```
```bash 
http://127.0.0.1:8000/docs/

```
## step:11 add .gitignore file in main route

## step:11 in test folder create a file test.main.py
```python 
from fastapi.testclient import TestClient
from sqlmodel import Field, Session, SQLModel, create_engine, select
from myApp.main import app
from fastapi_neon import settings


def test_read_main():
    client = TestClient(app=app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}

```

### run test command 
```bash
poetry run pytest
```

