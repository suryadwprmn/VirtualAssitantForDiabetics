from werkzeug.security import generate_password_hash
from models import User, db

def create_dummy_users():
    users = [
        User(name="John Doe", email="john@example.com", 
             password=generate_password_hash("password123"), 
             address="123 Main St", age=30, gender="male", 
             category_diabetes="non-diabetes", role="User"),
        User(name="Jane Smith", email="jane@example.com", 
             password=generate_password_hash("password456"), 
             address="456 Elm St", age=25, gender="female", 
             category_diabetes="diabetes 1", role="User"),
        User(name="Admin User", email="admin@example.com", 
             password=generate_password_hash("adminpass"), 
             address="789 Oak St", age=35, gender="male", 
             category_diabetes="non-diabetes", role="admin")
    ]
    
    for user in users:
        db.session.add(user)
    db.session.commit()

if __name__ == "__main__":
    from app import app, db
    with app.app_context():
        db.create_all()
        create_dummy_users()
        print("Dummy users created successfully.")