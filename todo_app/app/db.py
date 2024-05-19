from app import settings  # Import settings from the app module to access configuration variables
from sqlmodel import Session, SQLModel, create_engine  # Import SQLModel, Session, and create_engine from SQLModel for database interaction

# Convert the DATABASE_URL to a string and replace the driver from "postgresql" to "postgresql+psycopg"
connection_string = str(settings.DATABASE_URL).replace(
    "postgresql", "postgresql+psycopg"
)

# Create an engine instance for connecting to the database
# - connection_string: The database connection string with the updated driver
# - connect_args: Dictionary with connection arguments; "sslmode" set to "require" for SSL connections
# - pool_recycle: Recycle connections in the pool every 300 seconds
engine = create_engine(
    connection_string, connect_args={"sslmode": "require"}, pool_recycle=300
)

def create_db_and_tables():
    """
    Create the database and tables defined in the SQLModel metadata.
    This function should be called to initialize the database schema.
    """
    SQLModel.metadata.create_all(engine)

def get_session():
    """
    Provide a session for database interactions using a context manager.
    This function is a generator that yields a session and ensures it is properly closed after use.
    """
    with Session(engine) as session:
        yield session
