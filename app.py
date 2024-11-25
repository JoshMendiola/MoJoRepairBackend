import os
from dotenv import load_dotenv
import time
from flask import Flask, jsonify, request, make_response
from flask_bcrypt import check_password_hash
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import pymysql
import logging
from sqlalchemy import text

from extensions import db, bcrypt, jwt
from models.Admin import Admin, SecureAdmin
from models.Employee import Employee

pymysql.install_as_MySQLdb()

load_dotenv()

def create_secure_admin(app):
    """Create the admin for the secure dashboard using env variables"""
    with app.app_context():
        secure_username = os.getenv('SECURE_ADMIN_USERNAME')
        if not secure_username:
            app.logger.error("SECURE_ADMIN_USERNAME not found in environment variables")
            return

        if not SecureAdmin.query.filter_by(username=secure_username).first():
            admin = SecureAdmin(
                username=secure_username,
                password=os.getenv('SECURE_ADMIN_PASSWORD'),
                email=os.getenv('SECURE_ADMIN_EMAIL')
            )
            db.session.add(admin)
            try:
                db.session.commit()
                print("Secure admin created successfully!")
            except Exception as e:
                print(f"Error creating secure admin: {e}")
                db.session.rollback()

def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)

    # Set up logging
    logging.basicConfig(level=logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)

    # Configuration using environment variables
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+pymysql://{os.getenv('DB_USERNAME')}:{os.getenv('DB_PASSWORD')}"
        f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    with app.app_context():
        try:
            db.create_all()
            create_secure_admin(app)
            app.logger.info("Database tables created and secure admin checked/created successfully!")
        except Exception as e:
            app.logger.error(f"Error during setup: {e}")

    # Register routes
    @app.route('/api/')
    def api_home():
        app.logger.debug("API home route accessed")
        return jsonify({"message": "Welcome to the MoJoRepair API"})

    # SECURE ROUTES
    @app.route('/api/login', methods=['POST'])
    def login():
        """Secure login endpoint using bcrypt and JWT"""
        app.logger.debug("Secure login route accessed")
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        app.logger.debug(f"Login attempt for username: {username}")

        try:
            user = Admin.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, password):
                access_token = create_access_token(identity=user.id)
                
                # Create response with HTTP-only cookie
                response = make_response(jsonify({"message": "Login successful"}), 200)
                response.set_cookie(
                    'authToken',
                    access_token,
                    httponly=True,
                    secure=True,  # Remove for HTTP development
                    samesite='Strict',
                    max_age=86400  # 24 hours
                )
                app.logger.debug(f"Login successful for user: {user.username}")
                return response
            else:
                app.logger.debug("Login failed")
                return jsonify({"message": "Invalid username or password"}), 401
        except Exception as e:
            app.logger.error(f"Error during login: {str(e)}")
            return jsonify({"message": "An error occurred during login"}), 500

    @app.route('/api/employees', methods=['GET'])
    @jwt_required()
    def get_all_employees():
        """Secure endpoint requiring JWT authentication"""
        app.logger.debug("Secure employees route accessed")
        try:
            employees = Employee.query.all()
            return jsonify([{
                'id': emp.employee_id,
                'username': emp.username,
                'password': emp.password,
                'ssh_key': emp.ssh_key,
                'embarrassing_fact': emp.embarrassing_fact
            } for emp in employees]), 200
        except Exception as e:
            app.logger.error(f"Error fetching employees: {str(e)}")
            return jsonify({"message": "An error occurred while fetching employees"}), 500

    @app.route('/api/logout', methods=['POST'])
    def logout():
        """Secure logout endpoint that clears the JWT cookie"""
        app.logger.debug("Logout route accessed")
        response = make_response(jsonify({"message": "Logout successful"}), 200)
        response.delete_cookie('authToken')
        return response

    # VULNERABLE ROUTES FOR SQL INJECTION DEMO
    @app.route('/api/sql-demo/login', methods=['POST'])
    def vulnerable_login():
        """Vulnerable login endpoint for SQL injection demo"""
        app.logger.debug("SQL Demo vulnerable login route accessed")
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        app.logger.debug(f"SQL Demo login attempt with username: {username}")

        try:
            # Intentionally vulnerable SQL query
            query = f"SELECT * FROM employee WHERE username='{username}' AND password='{password}'"
            result = db.session.execute(text(query)).fetchone()
            
            if result:
                app.logger.debug("SQL Demo login successful")
                return jsonify({"message": "Login successful"}), 200
            else:
                app.logger.debug("SQL Demo login failed")
                return jsonify({"message": "Invalid credentials"}), 401
                
        except Exception as e:
            app.logger.error(f"Error in SQL demo login: {str(e)}")
            return jsonify({"message": "Login failed"}), 500

    @app.route('/api/sql-demo/employees', methods=['GET'])
    def get_sql_demo_employees():
        """Vulnerable endpoint that returns sensitive employee data"""
        app.logger.debug("SQL Demo employees route accessed")
        try:
            employees = Employee.query.all()
            return jsonify([{
                'id': emp.employee_id,
                'username': emp.username,
                'password': emp.password,
                'ssh_key': emp.ssh_key,
                'embarrassing_fact': emp.embarrassing_fact
            } for emp in employees]), 200
        except Exception as e:
            app.logger.error(f"Error fetching SQL demo employees: {str(e)}")
            return jsonify({"message": "An error occurred"}), 500

    return app

def connect_to_database(retries=5, delay=5):
    for attempt in range(retries):
        try:
            db.create_all()
            print("Successfully connected to the database!")
            return
        except Exception as e:
            print(f"Attempt {attempt + 1} failed. Retrying in {delay} seconds...")
            time.sleep(delay)
    raise Exception("Failed to connect to the database after multiple attempts")

app = create_app()

if __name__ == '__main__':
    app.logger.info("Starting the Flask application")
    app.run(debug=False, host='0.0.0.0', port=7000)