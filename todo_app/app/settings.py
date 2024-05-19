from starlette.config import Config  # Import Config class to manage environment variables
from starlette.datastructures import Secret  # Import Secret class to handle sensitive data securely

try:
    # Attempt to create a Config object that reads from a .env file
    config = Config(".env")
except FileNotFoundError:
    # If the .env file is not found, create a Config object that relies on system environment variables
    config = Config()

# Load the DATABASE_URL environment variable and cast it to a Secret for secure handling
DATABASE_URL = config("DATABASE_URL", cast=Secret)

# Load the TEST_DATABASE_URL environment variable and cast it to a Secret for secure handling
TEST_DATABASE_URL = config("TEST_DATABASE_URL", cast=Secret)

# Secret key for JWT encoding. You can generate a secret key using the following Python code:
SECRET_KEY = config("SECRET_KEY")

# JWT signing algorithm
ALGORITHM = config("ALGORITHM")
