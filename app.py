import time

from flask import Flask, jsonify, request
from flask_bcrypt import check_password_hash
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import os
import pymysql
import logging

from extensions import db, bcrypt, jwt
from models.Admin import Admin
from models.Employee import Employee

pymysql.install_as_MySQLdb()


def create_app():
    app = Flask(__name__)
    CORS(app)

    # Set up logging
    logging.basicConfig(level=logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)

    # Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://rootdbuser:F4cW8yJzE6vU9dA7@mysql:3306/mojorepairdb"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(24))
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables created successfully!")
        except Exception as e:
            app.logger.error(f"Error creating database tables: {e}")

    # Register routes
    @app.route('/api/')
    def api_home():
        app.logger.debug("API home route accessed")
        return jsonify({"message": "Welcome to the MoJoRepair API"})

    from flask import jsonify, request
    from flask_jwt_extended import create_access_token
    from sqlalchemy import text

    @app.route('/api/employees', methods=['GET'])
    @jwt_required()
    def get_all_employees():
        app.logger.debug("Get all employees route accessed")
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

    @app.route('/api/login', methods=['POST'])
    def login():
        app.logger.debug("Login route accessed")
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        app.logger.debug(f"Login attempt for username: {username}")

        try:
            user = Admin.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, password):
                access_token = create_access_token(identity=user.id)
                app.logger.debug(f"Login successful for user: {user.username}")
                return jsonify(access_token=access_token), 200
            else:
                app.logger.debug("Login failed")
                return jsonify({"message": "Invalid username or password"}), 401
        except Exception as e:
            app.logger.error(f"Error during login: {str(e)}")
            return jsonify({"message": "An error occurred during login"}), 500

    @app.route('/api/protected', methods=['GET'])
    @jwt_required()
    def protected():
        app.logger.debug("Protected route accessed")
        current_user_id = get_jwt_identity()
        user = Admin.query.get(current_user_id)
        return jsonify(logged_in_as=user.email), 200

    @app.route('/api/logout')
    def logout():
        app.logger.debug("Logout route accessed")
        return jsonify({"message": "Logout successful"}), 200

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
