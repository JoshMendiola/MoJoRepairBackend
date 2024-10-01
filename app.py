from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta, time
import os
import pymysql

from extensions import db, bcrypt, jwt
from models.Admin import Admin

pymysql.install_as_MySQLdb()


def create_app():
    app = Flask(__name__)
    CORS(app)

    # Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://rootdbuser:${MYSQL_PASSWORD}@mysql:3306/mojorepairdb"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(24))
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    # Register routes
    @app.route('/api/')
    def api_home():
        return jsonify({"message": "Welcome to the MoJoRepair API"})

    @app.route('/api/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = Admin.query.filter_by(username=username).first()

        if user and password == user.password:
            access_token = create_access_token(identity=user.id)
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({"message": "Invalid username or password"}), 401

    @app.route('/api/protected', methods=['GET'])
    @jwt_required()
    def protected():
        current_user_id = get_jwt_identity()
        user = Admin.query.get(current_user_id)
        return jsonify(logged_in_as=user.email), 200

    @app.route('/api/logout')
    def logout():
        return jsonify({"message": "Logout successful"}), 200

    return app


def create_db(app):
    with app.app_context():
        db.create_all()


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


if __name__ == '__main__':
    app = create_app()
    create_db(app)
    app.run(debug=False, host='0.0.0.0', port=7000)
