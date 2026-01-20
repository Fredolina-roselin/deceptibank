from app import app, db, User
from werkzeug.security import generate_password_hash

def create_admin():
    with app.app_context():
        # check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print("⚠️ Admin already exists!")
            return

        # create new admin
        admin = User(
            name='Admin',
            email='deceptibank@gmail.com',
            username='admin',
            password_hash=generate_password_hash('Admin@12345'),  # change this password
            role='admin',
            is_verified=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin account created successfully!")
        print("Username: admin")
        print("Password: Admin@12345")  # change in production

if __name__ == '__main__':
    create_admin()