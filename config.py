import os
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from flask_mail import Mail
    
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db = SQLAlchemy()
mail = Mail()

class Config:
    DB_USERNAME = "root"
    DB_PASSWORD = ""  
    DB_HOST = "localhost"
    DB_NAME = "virtual_assistant"
    SECRET_KEY = os.getenv('SECRET_KEY', 'rahasia_bang')
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # Maksimal 2MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt_rahasia')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=30)
  
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'suryadwipramana18@gmail.com'  
    MAIL_PASSWORD = 'zkzi kavg wyfi ddlr'     
    MAIL_DEFAULT_SENDER = 'your-email@gmail.com'
