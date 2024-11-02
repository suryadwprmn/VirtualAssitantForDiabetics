from config import db

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False) 
    address = db.Column(db.Text)
    age = db.Column(db.Integer)
    gender = db.Column(db.Enum('male', 'female'), nullable=False)  # Hapus 'other'
    category_diabetes = db.Column(db.Enum('non-diabetes', 'diabetes 1', 'diabetes 2'), nullable=False)
    role = db.Column(db.Enum('User', 'admin'), default='User')
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.now(), onupdate=db.func.now())
    
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

class Article(db.Model):
    __tablename__ = 'articles'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    images = db.Column(db.String(255))  # Menyimpan path atau URL gambar
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self, user_id, title, content, images=None):
        self.user_id = user_id
        self.title = title
        self.content = content
        self.images = images
        
class RumahSakit(db.Model):
    __tablename__ = 'rumah_sakit'
    
    id = db.Column(db.Integer, primary_key=True)
    maps = db.Column(db.String(255), nullable=True)
    rumah_sakit = db.Column(db.String(255), nullable=False)
    rating = db.Column(db.Float, nullable=True)
    tipe = db.Column(db.String(50), nullable=True)
    jalan = db.Column(db.String(255), nullable=True)
    gambar = db.Column(db.String(255), nullable=True)  # Kolom gambar untuk menambahkan URL atau path gambar

    def __init__(self, maps, rumah_sakit, rating, tipe, jalan, gambar=None):
        self.maps = maps
        self.rumah_sakit = rumah_sakit
        self.rating = rating
        self.tipe = tipe
        self.jalan = jalan
        self.gambar = gambar


