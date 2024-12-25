from config import db
from werkzeug.security import generate_password_hash, check_password_hash

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
    gambar = db.Column(db.String(255), nullable=True)  

    def __init__(self, maps, rumah_sakit, rating, tipe, jalan, gambar=None):
        self.maps = maps
        self.rumah_sakit = rumah_sakit
        self.rating = rating
        self.tipe = tipe
        self.jalan = jalan
        self.gambar = gambar
        
        
class Pengguna(db.Model):
    __tablename__ = 'pengguna'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)  # This will store the hashed password
    gender = db.Column(db.Enum('Laki-laki', 'Perempuan'), nullable=False)
    diabetes_category = db.Column(
        db.Enum('Non Diabetes', 'Diabetes 1', 'Diabetes 2'), nullable=False
    )
    phone = db.Column(db.String(15))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationship to CatatanGulaDarah (one to many)
    catatan_gula_darah = db.relationship('CatatanGulaDarah', back_populates='pengguna', lazy=True)
    
    # Relationship to HbA1c (one to many)
    hba1c_records = db.relationship('HbA1c', back_populates='pengguna', lazy=True)

    def __init__(self, name, email, password, gender, diabetes_category, phone=None):
        self.name = name
        self.email = email
        self.password = generate_password_hash(password)
        self.gender = gender
        self.diabetes_category = diabetes_category
        self.phone = phone


    # Function to verify password
    def verify_password(self, password):
        return check_password_hash(self.password, password)
    
class CatatanGulaDarah(db.Model):
    __tablename__ = 'catatan_gula_darah'

    id = db.Column(db.Integer, primary_key=True)
    pengguna_id = db.Column(db.Integer, db.ForeignKey('pengguna.id'), nullable=False)
    tanggal = db.Column(db.Date, nullable=False)
    waktu = db.Column(db.Enum('Pagi', 'Siang', 'Malam'), nullable=False)  # Store the time of day
    gula_darah = db.Column(db.Float, nullable=False)

    # Relationship to Pengguna
    pengguna = db.relationship('Pengguna', back_populates='catatan_gula_darah')

    def __init__(self, pengguna_id, tanggal, waktu, gula_darah):
        self.pengguna_id = pengguna_id
        self.tanggal = tanggal
        self.waktu = waktu
        self.gula_darah = gula_darah


class HbA1c(db.Model):
    __tablename__ = 'hba1c'

    id = db.Column(db.Integer, primary_key=True)
    pengguna_id = db.Column(db.Integer, db.ForeignKey('pengguna.id'), nullable=False)
    hba1c = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationship to Pengguna
    pengguna = db.relationship('Pengguna', back_populates='hba1c_records')

    def __init__(self, pengguna_id, hba1c):
        self.pengguna_id = pengguna_id
        self.hba1c = hba1c
       
class Sentimen(db.Model):
    __tablename__ = 'sentimen'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('pengguna.id'), nullable=False)
    komentar = db.Column(db.String(255), nullable=False)
    hasil = db.Column(db.String(55), nullable=False)
    
    # Relationship to Pengguna
    pengguna = db.relationship('Pengguna', backref=db.backref('sentimen_reviews', lazy=True))
    
    # Tambahkan konstruktor
    def __init__(self, user_id, komentar, hasil):
        self.user_id = user_id
        self.komentar = komentar
        self.hasil = hasil

