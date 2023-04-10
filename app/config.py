import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'mysecretkey')

    ALGORITHM = os.environ.get('ALGORITHM', 'HS256')

    ACCESS_TOKEN_EXPIRE_MINUTES = os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES', 1440)

    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')

    MONGO_DATABASE_NAME = os.environ.get('MONGO_DATABASE_NAME', 'mydatabase')

    MONGO_USERS_COLLECTION_NAME = os.environ.get('MONGO_USERS_COLLECTION_NAME', 'users')
