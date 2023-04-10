import os
from dotenv import load_dotenv
from pydantic import BaseSettings, PostgresDsn

load_dotenv()

class Settings(BaseSettings):
    database_url: str = "sqlite:///./test.db"
    jwt_secret: str = os.getenv("JWT_SECRET")
    access_token_expire_minutes: int = 1440

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

def get_settings():
    return Settings()
