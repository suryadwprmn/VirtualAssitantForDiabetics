from flask import Flask, render_template, url_for,request,redirect,flash,abort,session
from config import Config,db
from werkzeug.utils import secure_filename
import os
from werkzeug.security import check_password_hash
from models import User
from functools import wraps

### Menjalankan Flask
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'rahasia' 
db.init_app(app)

# Fungsi cek ekstensi file yang diperbolehkan
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


##################### Routing #####################

@app.route('/')
def index():
    return render_template('index.html')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful. Welcome back!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('auth/login.html')

@app.route('/admin')
def admin_dashboard():
    return render_template('admin/dashboard.html') 
##################### Routing #####################






##################### Error Handler #####################
# Error handler untuk 404 - Page Not Found
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

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