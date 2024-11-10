from flask import Flask, render_template, url_for,request,redirect,flash,abort,session,jsonify
from config import Config,db
from werkzeug.utils import secure_filename
import os
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, Article, RumahSakit, Pengguna
from functools import wraps
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token,jwt_required, get_jwt_identity


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
    return render_template('index.html')


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
    return render_template('Hospital.html')

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



# @app.route('/api/login', methods=['POST'])
# def login_user():
#     data = request.get_json()
#     if not data or not all(key in data for key in ('email', 'password')):
#         return jsonify({'error': 'Missing email or password'}), 400

#     user = Pengguna.query.filter_by(email=data['email']).first()
#     if not user or not check_password_hash(user.password, data['password']):
#         return jsonify({'error': 'Invalid email or password'}), 401

#     # Buat token akses JWT
#     access_token = create_access_token(identity=user.id)
#     return jsonify({'access_token': access_token}), 200

# @app.route('/protected', methods=['GET'])
# @jwt_required()
# def protected():
#     # Mendapatkan id pengguna dari token JWT
#     current_user_id = get_jwt_identity()
#     return jsonify({'message': f'Hello user {current_user_id}'}), 200


@app.route('/api/artikel', methods=['GET'])
def get_all_articles():
    all_articles = Article.query.all()
    articles = [
        {
            'id': article.id,
            'title': article.title,
            'content': article.content,
            'images': article.images  # Pastikan 'images' adalah atribut dari model Article
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