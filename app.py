from flask import Flask, render_template, url_for,request,redirect,flash,abort,session
from config import Config,db
from werkzeug.utils import secure_filename
import os
from werkzeug.security import check_password_hash
from models import User, Article
from functools import wraps

### Menjalankan Flask
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'rahasia' 
db.init_app(app)

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

@app.route("/home")
def Home():
	return render_template("Home.html")

@app.route('/artikel')
def artikel():
    all_articles = Article.query.all()
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
    return render_template('article.html', articles=all_articles)

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
def Article():
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

#### Route Admin ###

##################### Routing #####################

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