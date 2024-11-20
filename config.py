import os
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db = SQLAlchemy()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'rahasia_bang')
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://root:@localhost/virtual_assistant"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # Maksimal 2MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt_rahasia')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)  
