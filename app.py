import time

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import os
import pymysql
import logging

from extensions import db, bcrypt, jwt
from models.Admin import Admin
from sqlalchemy import text

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

    @app.route('/api/login', methods=['POST'])
    def login():
        app.logger.debug("Login route accessed")
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        app.logger.debug(f"Login attempt for username: {username}")

        # Vulnerable SQL query
        query = f"SELECT * FROM admin WHERE username = '{username}' AND password = '{password}'"
        app.logger.debug(f"Executing query: {query}")

        try:
            with db.engine.connect() as connection:
                result = connection.execute(text(query)).fetchone()

            if result:
                user = Admin(id=result[0], username=result[1], email=result[2], password=result[3])
                access_token = create_access_token(identity=user.id)
                app.logger.debug("Login successful")
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
