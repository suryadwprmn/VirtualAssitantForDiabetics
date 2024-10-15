from config import db
import bcrypt

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(55), unique=True, nullable=False) 
    password = db.Column(db.String(55), nullable=False)
    
    # Relasi ke Article
    articles = db.relationship('Article', backref='user', lazy=True)

    def __init__(self, username, password):
           self.username = username
           self.set_password(password)
    def set_password(self, password):
           self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
           return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
   


class Article(db.Model):
    __tablename__ = 'articles'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)
    
    # Foreign key ke User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, title, content, image_filename=None):
        self.title = title
        self.content = content
        self.image_filename = image_filename