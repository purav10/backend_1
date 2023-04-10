import os

from pydantic import BaseSettings, validator
from databases import DatabaseURL

class Settings(BaseSettings):
    app_name: str = "My App"
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440
    database_url: str

    @validator("database_url", pre=True)
    def set_database_url(cls, value):
        if isinstance(value, str):
            return value
        return str(value)

    class Config:
        env_file = ".env"

settings = Settings()
