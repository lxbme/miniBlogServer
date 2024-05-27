# read Secret key from environment variable
import os
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

#SECRET_KEY = "c6a4e8e0a0b2b2f7c3b1c0f5f4e9a4b0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30