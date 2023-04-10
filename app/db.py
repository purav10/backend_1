import os
from pymongo import MongoClient
from bson.objectid import ObjectId
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'mysecretkey')
    ALGORITHM = os.environ.get('ALGORITHM', 'HS256')
    ACCESS_TOKEN_EXPIRE_MINUTES = os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES', 1440)
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DATABASE_NAME = os.environ.get('MONGO_DATABASE_NAME', 'mydatabase')
    MONGO_USERS_COLLECTION_NAME = os.environ.get('MONGO_USERS_COLLECTION_NAME', 'users')

class Mongo:
    
    def __init__(self, config: Config):
        self.client = MongoClient(config.MONGO_URI)
        self.db = self.client[config.MONGO_DATABASE_NAME]
        self.users_collection = self.db[config.MONGO_USERS_COLLECTION_NAME]
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.jwt_secret_key = config.SECRET_KEY
        self.jwt_algorithm = config.ALGORITHM
        self.jwt_expire_minutes = config.ACCESS_TOKEN_EXPIRE_MINUTES

    def create_user(self, email: str, password: str):
        hashed_password = self.pwd_context.hash(password)
        user = {'email': email, 'hashed_password': hashed_password}
        result = self.users_collection.insert_one(user)
        return str(result.inserted_id)

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    def generate_token(self, email):
        payload = {'email': email, 'exp': datetime.utcnow() + timedelta(minutes=self.jwt_expire_minutes)}
        token = jwt.encode(payload, self.jwt_secret_key, algorithm=self.jwt_algorithm)
        return token

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.jwt_secret_key, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def get_user(self, email: str):
        user = self.users_collection.find_one({'email': email})
        if user:
            return {'_id': str(user['_id']), 'email': user['email'], 'hashed_password': user['hashed_password']}
        else:
            return None

mongo = Mongo(Config())
