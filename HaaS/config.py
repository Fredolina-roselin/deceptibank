# config.py
import os

# Flask secret key
SECRET_KEY = os.environ.get("SECRET_KEY") or "supersecretkey123"

# MySQL configuration
MYSQL_USER = "newuser1"
MYSQL_PASSWORD = "StrongPassword123!"
MYSQL_HOST = "localhost"
MYSQL_DB = "deceptibank"

SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}"
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Gmail for OTP
GMAIL_EMAIL = "yourapp@gmail.com"  # Replace with your Gmail
GMAIL_PASSWORD = "your_app_password"  # Gmail app password if 2FA enabled
OTP_EXPIRY_MINUTES = 5
