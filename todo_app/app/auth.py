from passlib.context import CryptContext  # Import CryptContext from passlib for password hashing
from sqlmodel import Session, select  # Import Session and select from SQLModel for ORM and querying
from typing import Annotated  # Import Annotated for type annotations
from app.db import get_session  # Import get_session to get a database session
from fastapi import Depends, HTTPException, status  # Import FastAPI utilities for dependency injection and HTTP exceptions
from app.models import RefreshTokenData, TokenData, User, Todo  # Import models from the app
from fastapi.security import OAuth2PasswordBearer  # Import OAuth2PasswordBearer for token-based authentication
from jose import jwt, JWTError  # Import jwt and JWTError from jose for JWT encoding and decoding
from datetime import datetime, timezone, timedelta  # Import datetime utilities for managing token expiration
from app.settings import SECRET_KEY, ALGORITHM
# Secret key for JWT encoding. You can generate a secret key using the following Python code:
# import secrets
# secrets.token_hex(32)
SECRET_KEY = SECRET_KEY
ALGORITHM = ALGORITHM  # JWT signing algorithm
EXPIRY_TIME = 5  # Token expiry time in minutes

# OAuth2 scheme for handling bearer tokens
oauth_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"])

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    """
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hashed password.
    """
    return pwd_context.verify(password, hashed_password)

def get_user_from_db(session: Annotated[Session, Depends(get_session)],
                     username: str | None = None,
                     email: str | None = None) -> User | None:
    """
    Retrieve a user from the database by username or email.
    """
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    if not user and email:
        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
    return user

def authenticate_user(username: str,
                      password: str,
                      session: Annotated[Session, Depends(get_session)]) -> User | bool:
    """
    Authenticate a user by username and password.
    """
    db_user = get_user_from_db(session=session, username=username)
    if not db_user:
        return False
    if not verify_password(password, db_user.password):
        return False
    return db_user

def create_access_token(data: dict, expiry_time: timedelta | None = None) -> str:
    """
    Create a JWT access token with an optional expiration time.
    """
    data_to_encode = data.copy()
    if expiry_time:
        expire = datetime.now(timezone.utc) + expiry_time
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(data_to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def current_user(token: Annotated[str, Depends(oauth_scheme)],
                 session: Annotated[Session, Depends(get_session)]) -> User:
    """
    Get the current user from the provided JWT token.
    """
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, Please login again",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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

def create_refresh_token(data: dict, expiry_time: timedelta | None = None) -> str:
    """
    Create a JWT refresh token with an optional expiration time.
    """
    data_to_encode = data.copy()
    if expiry_time:
        expire = datetime.now(timezone.utc) + expiry_time
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(data_to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def validate_refresh_token(token: str,
                           session: Annotated[Session, Depends(get_session)]) -> User:
    """
    Validate a JWT refresh token and retrieve the associated user.
    """
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, Please login again",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise credential_exception
        token_data = RefreshTokenData(email=email)
    except JWTError:
        raise credential_exception

    user = get_user_from_db(session, email=token_data.email)
    if not user:
        raise credential_exception
    return user
