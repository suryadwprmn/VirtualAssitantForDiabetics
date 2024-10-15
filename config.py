import os
from flask_sqlalchemy import SQLAlchemy

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db = SQLAlchemy()

class Config:
    SECRET_KEY = 'rahasia_bang'
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://root:@localhost/article_app"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # Maksimal 2MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
