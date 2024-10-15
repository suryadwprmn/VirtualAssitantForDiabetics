from flask import Flask, render_template, url_for,request,redirect,flash,abort,session
from config import Config,db
from werkzeug.utils import secure_filename
import os
import bcrypt

### Menjalankan Flask
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'rahasia' 
db.init_app(app)

# Fungsi cek ekstensi file yang diperbolehkan
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


##################### Routing #####################





##################### Routing #####################

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