import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets
import pymysql
from flask_wtf.csrf import CSRFProtect
from flask_limiter.errors import RateLimitExceeded

# Import extensions
from extensions import db, login_manager, bcrypt, limiter

# Load environment variables
load_dotenv()

# Initialize CSRF protection
csrf = CSRFProtect()

# MySQL connection
pymysql.install_as_MySQLdb()

# Create Flask application
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    
    # Session security configuration
    app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)  # Session expires after 30 minutes of inactivity
    app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are only sent over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Restrict cookie sending to same-site requests (Lax allows GET requests from other sites)
    app.config['SESSION_USE_SIGNER'] = True  # Sign the session cookie for added security
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Update session with each request to reset expiry

    # CSRF Protection
    csrf.init_app(app)

    # Database configuration
    # Priority:
    # 1) DATABASE_URL
    # 2) Full MySQL variable set
    # 3) SQLite fallback (for Vercel/serverless and quick demos)
    database_url = os.environ.get('DATABASE_URL')

    mysql_user = os.environ.get('MYSQL_USER', '')
    mysql_password = os.environ.get('MYSQL_PASSWORD', '')
    mysql_host = os.environ.get('MYSQL_HOST', '')
    mysql_port = str(os.environ.get('MYSQL_PORT', '3306'))
    mysql_database = os.environ.get('MYSQL_DATABASE', '')

    if database_url:
        db_uri = database_url
    elif mysql_host and mysql_user and mysql_database:
        db_uri = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}"
    else:
        if os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV'):
            db_uri = "sqlite:////tmp/simple_banking_vercel.db"
        else:
            db_uri = "sqlite:///simple_banking.db"
        print(
            "WARNING: MySQL configuration not found. "
            "Falling back to SQLite for this environment."
        )

    print(f"Database URI: {db_uri}")
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    # Ensure schema and baseline users exist on first boot of a fresh environment.
    with app.app_context():
        from models import User

        db.create_all()
        if User.query.count() == 0:
            manager_user = User(
                username="manager",
                email="manager@bankapp.com",
                account_number="0000000000",
                status="active",
                is_admin=True,
                is_manager=True,
                balance=1000.0,
            )
            manager_user.set_password("manager123")

            admin_user = User(
                username="admin",
                email="admin@bankapp.com",
                account_number="0000000001",
                status="active",
                is_admin=True,
                is_manager=False,
                balance=1000.0,
            )
            admin_user.set_password("admin123")

            test_user = User(
                username="testuser",
                email="test@example.com",
                account_number="1234567890",
                status="active",
                balance=1000.0,
            )
            test_user.set_password("testpassword")

            db.session.add(manager_user)
            db.session.add(admin_user)
            db.session.add(test_user)
            db.session.commit()
    
    # Add cache control headers to all responses
    @app.after_request
    def add_cache_control(response):
        if current_user.is_authenticated:
            # No caching for authenticated users to prevent back button issues
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    # Register custom error handler for rate limiting
    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(e):
        # Add a delay to slow down attackers (helps against brute force)
        import time
        time.sleep(1)
        
        # Log the rate limit violation
        app.logger.warning(f"Rate limit exceeded: {request.remote_addr} - {request.path}")
        
        # Check if it's an API request (expecting JSON)
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({
                "error": "Rate limit exceeded", 
                "message": "Too many requests. Please try again later.",
                "status_code": 429
            }), 429
        
        # If it's a sensitive endpoint, provide minimal information
        sensitive_endpoints = ['/login', '/reset_password', '/reset_password_request']
        if any(request.path.startswith(endpoint) for endpoint in sensitive_endpoints):
            return render_template('rate_limit_error.html', 
                                 message="Too many attempts. Please try again later."), 429
        
        # For other endpoints, provide more detailed message
        return render_template('rate_limit_error.html', message=str(e)), 429

    return app

# Create Flask app
app = create_app()

# Import models - must be after db initialization
from models import User, Transaction

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import routes after app creation
from routes import *

# Database initialization function
def init_db():
    """Initialize the database with required tables and default admin user."""
    with app.app_context():
        db.create_all()
        # Check if there are admin users, if not create one
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            admin_user = User(
                username="admin",
                email="admin@bankapp.com",
                account_number="0000000001",
                status="active",
                is_admin=True,
                balance=0.0
            )
            admin_user.set_password("admin123")
            db.session.add(admin_user)
            db.session.commit()
            print("Created admin user with username 'admin' and password 'admin123'")

if __name__ == '__main__':
    # Print environment variables for debugging
    print(f"Environment variables:")
    print(f"MYSQL_HOST: {os.environ.get('MYSQL_HOST')}")
    print(f"MYSQL_USER: {os.environ.get('MYSQL_USER')}")
    print(f"MYSQL_DATABASE: {os.environ.get('MYSQL_DATABASE')}")
    
    with app.app_context():
        db.create_all()
    app.run(debug=False)