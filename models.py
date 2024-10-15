from config import db

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False) 
    address = db.Column(db.Text)
    age = db.Column(db.Integer)
    gender = db.Column(db.Enum('male', 'female'), nullable=False)  
    category_diabetes = db.Column(db.Enum('non-diabetes', 'diabetes 1', 'diabetes 2'), nullable=False)
    role = db.Column(db.Enum('User', 'admin'), default='User')
    
    # Relasi ke tabel Article (One-to-Many)
    articles = db.relationship('Article', backref='user', lazy=True)

    def __init__(self, name, email, password, address=None, age=None, gender='male', category_diabetes='non-diabetes', role='User'):
        self.name = name
        self.email = email
        self.password = password 
        self.address = address
        self.age = age
        self.gender = gender
        self.category_diabetes = category_diabetes
        self.role = role

    def __repr__(self):
        return f'<User {self.name}>'

