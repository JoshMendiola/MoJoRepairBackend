from flask import Flask, jsonify, request, redirect, url_for, render_template, session, flash
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import os
from flask_sqlalchemy import SQLAlchemy
from models.Admin import Admin

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://rootdbuser:${MYSQL_PASSWORD}@mysql:3306/mojorepairdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(24))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))  # for session management

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


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
    # JWT doesn't maintain server-side sessions, so we just return a success message
    return jsonify({"message": "Logout successful"}), 200


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
