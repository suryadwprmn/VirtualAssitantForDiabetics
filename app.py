from flask import Flask, render_template, url_for,request,redirect,flash,abort,session,jsonify
from config import Config,db
from werkzeug.utils import secure_filename
import os
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, Article, RumahSakit, Pengguna, CatatanGulaDarah, HbA1c
from functools import wraps
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt
from sqlalchemy.sql.expression import func
# from flask_jwt_extended import JWTManager, create_access_token,jwt_required, get_jwt_identity


### Menjalankan Flask
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'rahasia' 
db.init_app(app)
CORS(app)
# jwt = JWTManager(app)

# Fungsi cek ekstensi file yang diperbolehkan
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

##################### Landing Page Routing #####################

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
    
    # ambil 5 rs terdekat
    rs_terdekat = RumahSakit.query.order_by(func.random()).limit(5).all()
    return render_template('index.html', rs_terdekat=rs_terdekat)


@app.route('/artikel')
def artikel():
    # Ambil 9 artikel pertama untuk tampilan awal
    initial_articles = Article.query.order_by(Article.id.desc()).limit(9).all()
    
    # Ambil artikel terbaru
    latest_article = Article.query.order_by(Article.id.desc()).first()
    
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
    
    return render_template('article.html', articles=initial_articles, latest_article=latest_article)


@app.route('/load-more-articles')
def load_more_articles():
    page = int(request.args.get('page', 1))
    per_page = 9  # Sesuaikan dengan jumlah artikel per load
    
    # Hitung offset
    offset = (page - 1) * per_page
    
    # Query artikel berikutnya
    articles = Article.query\
        .order_by(Article.id.desc())\
        .offset(offset)\
        .limit(per_page)\
        .all()
    
    # Hitung total artikel untuk mengecek apakah masih ada artikel lain
    total_articles = Article.query.count()
    has_more = (offset + per_page) < total_articles
    
    # Siapkan data artikel untuk JSON
    articles_data = []
    for article in articles:
        articles_data.append({
            'id': article.id,
            'title': article.title,
            'content': article.content,
            'images': article.images if article.images else None
        })
    
    return jsonify({
        'articles': articles_data,
        'has_more': has_more
    })
    
@app.template_filter('nl2br')
def nl2br(value):
    if value:
        return value.replace('\n', '<br>\n')
    return ''

@app.route('/artikel/<int:article_id>')
def article_page(article_id):
    # Cari artikel berdasarkan ID
    article = Article.query.get_or_404(article_id)
    return render_template('article_section.html', article=article)


@app.route('/cek_rs')
def cek_rs():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))

    # Ambil parameter halaman dari URL (default ke halaman 1)
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Total item per halaman

    # Query rumah sakit dengan pagination
    pagination = RumahSakit.query.paginate(page=page, per_page=per_page)
    rs_list = pagination.items

    return render_template('Hospital.html', rs_list=rs_list, pagination=pagination)

@app.route('/chatbot')
def chatbot():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
    return render_template('chatbot.html')


@app.route("/article")
def artikelSectiom():
	return render_template("article_section.html")

##################### End Landing Page Routing #####################

##################### Routing #####################

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful. Welcome back!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('auth/login.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    return render_template('admin/dashboard.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))


### Route Admin ###
@app.route('/admin/articles')
@login_required
def articles():
    all_articles = Article.query.all()
    return render_template('admin/article.html', articles=all_articles)


@app.route('/admin/article/create', methods=['GET', 'POST'])
@login_required
def create_article():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        image = request.files['image']
        
        if not title or not content:
            flash('Title and content are required.', 'error')
            return redirect(url_for('create_article'))
        
        image_filename = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_filename = f"{session['user_id']}_{filename}"
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        
        new_article = Article(
            user_id=session['user_id'],
            title=title,
            content=content,
            images=image_filename
        )
        
        db.session.add(new_article)
        db.session.commit()
        
        flash('Article created successfully!', 'success')
        return redirect(url_for('articles', article_id=new_article.id))
    
    return render_template('admin/tambah_artikel.html')

@app.route('/admin/article/edit/<int:article_id>', methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    article = Article.query.get_or_404(article_id)

    if request.method == 'POST':
        article.title = request.form['title']
        article.content = request.form['content']

        image = request.files['image']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_filename = f"{session['user_id']}_{filename}"
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            article.images = image_filename

        db.session.commit()
        flash('Article updated successfully!', 'success')
        return redirect(url_for('articles'))

    return render_template('admin/edit_article.html', article=article)

@app.route('/admin/article/delete/<int:article_id>', methods=['POST'])
@login_required
def delete_article(article_id):
    article = Article.query.get_or_404(article_id)
    db.session.delete(article)
    db.session.commit()
    flash('Article deleted successfully!', 'success')
    return redirect(url_for('articles'))

@app.route('/admin/rumah_sakit')
@login_required
def rumah_sakit():
    all_rumah_sakit = RumahSakit.query.all()
    return render_template('admin/rumah_sakit.html', rumah_sakit_data=all_rumah_sakit)

@app.route('/admin/rumah_sakit/tambah', methods=['GET', 'POST'])
@login_required
def create_rumah_sakit():
    if request.method == 'POST':
        maps = request.form.get('maps')
        rumah_sakit = request.form.get('rumah_sakit')
        rating = request.form.get('rating', type=float)
        tipe = request.form.get('tipe')
        jalan = request.form.get('jalan')
        gambar = request.files.get('gambar')
        
        if not rumah_sakit:
            flash('Nama rumah sakit harus diisi.', 'error')
            return redirect(url_for('tambah_rumah_sakit'))
        
        gambar_filename = None
        if gambar and allowed_file(gambar.filename):
            filename = secure_filename(gambar.filename)
            gambar_filename = f"{filename}"
            gambar.save(os.path.join(app.config['UPLOAD_FOLDER'], gambar_filename))
        
        new_rumah_sakit = RumahSakit(
            maps=maps,
            rumah_sakit=rumah_sakit,
            rating=rating,
            tipe=tipe,
            jalan=jalan,
            gambar=gambar_filename
        )
        
        db.session.add(new_rumah_sakit)
        db.session.commit()
        
        flash('Rumah sakit berhasil ditambahkan!', 'success')
        return redirect(url_for('rumah_sakit'))  # Ganti 'tampil_rumah_sakit' dengan nama rute tampilan daftar rumah sakit.
    
    return render_template('admin/tambah_rumah_sakit.html')




@app.route('/admin/rumah_sakit/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_rumah_sakit(id):
    rumah_sakit = RumahSakit.query.get_or_404(id)
    
    if request.method == 'POST':
        rumah_sakit.maps = request.form.get('maps')
        rumah_sakit.rumah_sakit = request.form.get('rumah_sakit')
        rumah_sakit.rating = request.form.get('rating', type=float)
        rumah_sakit.tipe = request.form.get('tipe')
        rumah_sakit.jalan = request.form.get('jalan')

        gambar = request.files.get('gambar')
        if gambar and allowed_file(gambar.filename):
            filename = secure_filename(gambar.filename)
            gambar_filename = f"{filename}"
            gambar.save(os.path.join(app.config['UPLOAD_FOLDER'], gambar_filename))
            rumah_sakit.gambar = gambar_filename

        db.session.commit()
        flash('Rumah sakit berhasil diperbarui!', 'success')
        return redirect(url_for('rumah_sakit'))  # Ganti dengan rute untuk menampilkan daftar rumah sakit

    return render_template('admin/edit_rumah_sakit.html', rumah_sakit=rumah_sakit)

@app.route('/admin/rumah_sakit/hapus/<int:id>', methods=['POST'])
@login_required
def delete_rumah_sakit(id):
    rumah_sakit = RumahSakit.query.get_or_404(id)
    
    if rumah_sakit.gambar:
        gambar_path = os.path.join(app.config['UPLOAD_FOLDER'], rumah_sakit.gambar)
        if os.path.exists(gambar_path):
            os.remove(gambar_path)
    
    db.session.delete(rumah_sakit)
    db.session.commit()
    
    flash('Rumah sakit berhasil dihapus!', 'success')
    return redirect(url_for('rumah_sakit'))

#### Route Admin ###

##################### Routing #####################


##################### API #####################
# Mendapatkan semua pengguna
@app.route('/api/users', methods=['GET'])
def get_penggunas():
    users = Pengguna.query.all()
    users_data = [
        {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'gender': user.gender,
            'diabetes_category': user.diabetes_category,
            'phone': user.phone,
            'created_at': user.created_at.isoformat() if user.created_at else None
        }
        for user in users
    ]
    return jsonify(users_data), 200

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    
    if not all(key in data for key in ('name', 'email', 'password', 'gender', 'diabetes_category')):
        return jsonify({'error': 'Missing required fields'}), 400

    if Pengguna.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email is already registered'}), 400
    
    # Create a new user instance
    new_user = Pengguna(
        name=data['name'],
        email=data['email'],
        password=data['password'],  
        gender=data['gender'],
        diabetes_category=data['diabetes_category'],
        phone=data.get('phone')
    )
    
  
    db.session.add(new_user)
    db.session.commit()
    
    # Return the created user data
    registered_user = {
        'id': new_user.id,
        'name': new_user.name,
        'email': new_user.email,
        'gender': new_user.gender,
        'diabetes_category': new_user.diabetes_category,
        'phone': new_user.phone,
        'created_at': new_user.created_at.isoformat() if new_user.created_at else None
    }
    return jsonify(registered_user), 201


@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    
    if not all(key in data for key in ('email', 'password')):
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = Pengguna.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Generate JWT token menggunakan SECRET_KEY dari config
    token_payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=30)  
    }
    
    access_token = jwt.encode(token_payload, Config.SECRET_KEY, algorithm='HS256')
    
    # Response dengan token
    user_data = {
        'name': user.name,
        'email': user.email,
        'gender': user.gender,
        'diabetes_category': user.diabetes_category,
        'phone': user.phone,
        'access_token': access_token
    }
    
    return jsonify(user_data), 200

# Decorator untuk protected routes
def token_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
                
            data = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
            current_user = Pengguna.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except Exception as e:
            return jsonify({'error': 'Token is invalid', 'details': str(e)}), 401
            
        return f(current_user, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

# Route untuk mendapatkan profil user
@app.route('/api/profile', methods=['GET', 'PUT'])
@token_required
def get_profile(current_user):
    if request.method == 'GET':
        user_data = {
            'name': current_user.name,
            'email': current_user.email,
            'gender': current_user.gender,
            'diabetes_category': current_user.diabetes_category,
            'phone': current_user.phone
        }
        return jsonify(user_data), 200
    
    elif request.method == 'PUT':
        # Ambil data dari request body
        data = request.get_json()
        
        #Validasi input
        if not data:
            return jsonify({'error': 'Data is missing'}), 400
        
        #Perbarui data pengguna 
        if 'name' in data:
            current_user.name = data['name']
        if 'gender' in data:
            current_user.gender = data['gender']
        if 'diabetes_category' in data:
            current_user.diabetes_category = data['diabetes_category']
        if 'phone' in data:
            current_user.phone = data['phone']
        if 'password' in data:
            hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256', salt_length=8)
            current_user.password = hashed_password
            
        try:
            db.session.commit()
            return jsonify({'message': 'Profile updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Failed to update profile', 'details': str(e)}), 500
        
        
@app.route('/api/users/<int:id>', methods=['GET'])
def get_pengguna(id):
    user = Pengguna.query.get(id)
    if user is None:
        return jsonify({'error': 'User not found'}), 404
    
    user_data = {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'gender': user.gender,
        'diabetes_category': user.diabetes_category,
        'phone': user.phone,
        'created_at': user.created_at.isoformat() if user.created_at else None
    }
    
    return jsonify(user_data), 200

@app.route('/api/gula_darah', methods=['POST'])
@token_required
def tambah_gula_darah(current_user):
    data = request.get_json()
    # Validasi input
    if not all(key in data for key in ('tanggal', 'waktu', 'gula_darah')):
        return jsonify({'error': 'Tanggal, waktu, dan gula darah wajib diisi'}), 400
    try:
        # Parsing dan validasi nilai input
        tanggal = datetime.strptime(data['tanggal'], '%Y-%m-%d').date()
        waktu = data['waktu']
        gula_darah = float(data['gula_darah'])

        if waktu not in ['Pagi', 'Siang', 'Malam']:
            return jsonify({'error': 'Waktu harus berupa salah satu dari Pagi, Siang, atau Malam'}), 400

        if gula_darah <= 0:
            return jsonify({'error': 'Nilai gula darah harus lebih dari 0'}), 400

        # Membuat instance CatatanGulaDarah
        catatan = CatatanGulaDarah(
            pengguna_id=current_user.id,
            tanggal=tanggal,
            waktu=waktu,
            gula_darah=gula_darah
        )

        # Menyimpan data ke database
        db.session.add(catatan)
        db.session.commit()

        return jsonify({'message': 'Data gula darah berhasil disimpan'}), 201

    except ValueError as e:
        return jsonify({'error': f'Input tidak valid: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Kesalahan server: {str(e)}'}), 500
    


@app.route('/api/gula_darah/seminggu', methods=['GET'])
@token_required
def get_gula_darah(current_user):
    try:
        # Hitung batas waktu seminggu terakhir
        hari_ini = datetime.now().date()
        seminggu_lalu = hari_ini - timedelta(days=7)

        # Ambil data gula darah pengguna dalam seminggu terakhir
        catatan = CatatanGulaDarah.query.filter(
            CatatanGulaDarah.pengguna_id == current_user.id,
            CatatanGulaDarah.tanggal >= seminggu_lalu
        ).all()

        if not catatan:
            return jsonify({'message': 'Tidak ada data gula darah ditemukan dalam seminggu terakhirs'}), 404

        # Organisasi data per tanggal
        data_per_tanggal = {}
        for item in catatan:
            if item.tanggal not in data_per_tanggal:
                data_per_tanggal[item.tanggal] = []
            data_per_tanggal[item.tanggal].append(item.gula_darah)

        # Hitung rata-rata gula darah per hari
        rata_rata_per_hari = []
        for tanggal, nilai_gula_darah in data_per_tanggal.items():
            rata_rata = sum(nilai_gula_darah) / len(nilai_gula_darah)
            rata_rata_per_hari.append({
                'tanggal': tanggal.strftime('%Y-%m-%d'),
                'rata_rata_gula_darah': round(rata_rata, 2)
            })

        # Urutkan berdasarkan tanggal
        rata_rata_per_hari = sorted(rata_rata_per_hari, key=lambda x: x['tanggal'])

        return jsonify({'data': rata_rata_per_hari}), 200

    except Exception as e:
        return jsonify({'error': f'Kesalahan server: {str(e)}'}), 500

                
@app.route('/api/gula_darah/terakhir', methods=['GET'])
@token_required
def get_gula_darah_terakhir(current_user):
    try:
        # Ambil data gula darah terakhir berdasarkan pengguna
        catatan_terakhir = (
            CatatanGulaDarah.query
            .filter_by(pengguna_id=current_user.id)  # Filter berdasarkan pengguna
            .order_by(CatatanGulaDarah.tanggal.desc(), CatatanGulaDarah.id.desc())  # Urutkan berdasarkan tanggal (terbaru)
            .first()  # Ambil data pertama
        )

        if not catatan_terakhir:
            return jsonify({'error': 'Belum ada data gula darah yang tercatat'}), 404

        # Kembalikan data dalam format JSON
        return jsonify({
            'id': catatan_terakhir.id,
            'tanggal': catatan_terakhir.tanggal.strftime('%Y-%m-%d'),
            'waktu': catatan_terakhir.waktu,
            'gula_darah': catatan_terakhir.gula_darah
        }), 200

    except Exception as e:
        return jsonify({'error': f'Kesalahan server: {str(e)}'}), 500
    
@app.route('/api/hba1c', methods=['POST'])
@token_required
def tambah_hba1c(current_user):
    data = request.get_json()

    # Validasi input
    if 'hba1c' not in data:
        return jsonify({'error': 'Nilai HbA1c wajib diisi'}), 400

    try:
        hba1c = float(data['hba1c'])

        if hba1c <= 0:
            return jsonify({'error': 'Nilai HbA1c harus lebih dari 0'}), 400

        # Membuat instance HbA1c
        catatan_hba1c = HbA1c(
            pengguna_id=current_user.id,
            hba1c=hba1c
        )

        # Menyimpan data ke database
        db.session.add(catatan_hba1c)
        db.session.commit()

        return jsonify({'message': 'Data HbA1c berhasil disimpan'}), 201

    except ValueError as e:
        return jsonify({'error': f'Input tidak valid: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Kesalahan server: {str(e)}'}), 500

@app.route('/api/hba1c/terakhir', methods=['GET'])
@token_required
def get_hba1c_terakhir(current_user):
    try:
        # Ambil data HbA1c terakhir berdasarkan pengguna, urutkan berdasarkan created_at (terbaru)
        hba1c_terakhir = (
            HbA1c.query
            .filter_by(pengguna_id=current_user.id)  # Filter berdasarkan pengguna
            .order_by(HbA1c.created_at.desc())  # Urutkan berdasarkan created_at (terbaru)
            .first()  # Ambil data pertama (terbaru)
        )
        
        if not hba1c_terakhir:
            return jsonify({'error': 'Belum ada data HbA1c yang tercatat'}), 404

        # Kembalikan data dalam format JSON
        return jsonify({
            'id': hba1c_terakhir.id,
            'hba1c': hba1c_terakhir.hba1c,
            'created_at': hba1c_terakhir.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }), 200

    except Exception as e:
        return jsonify({'error': f'Kesalahan server: {str(e)}'}), 500


@app.route('/api/artikel', methods=['GET'])
def get_all_articles():
    all_articles = Article.query.all()
    articles = [
        {
            'id': article.id,
            'title': article.title,
            'content': article.content,
            'images': article.images  
        } 
        for article in all_articles
    ]
    return jsonify({'articles': articles})


##################### End API #####################

##################### Error Handler #####################
# Error handler untuk 404 - Page Not Found
@app.errorhandler(404)
def page_not_found(e):
    flash('The page you are looking for does not exist. You are being redirected to the home page.', 'warning')
    return redirect(url_for('index')) 


# Error handler untuk 500 - Internal Server Error
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

# Error handler untuk 403 - Forbidden
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

if __name__ == '__main__':
    # Buat tabel di database jika belum ada
    with app.app_context():
        db.create_all()

    app.run(debug=True)