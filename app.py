from flask import Flask, jsonify, request, redirect, url_for, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import os

from sqlalchemy import text

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/mojorepair_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# Admin model
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), nullable=False)


@app.route('/')
def api_home():
    return jsonify({"message": "Welcome to the MoJoRepair API"})

@app.route('/admin', methods=['POST'])
def login():
    # data = request.json
    username = request.form.get('username')
    password = request.form.get('password')

    # SQL INJECTION VULNERABILITY, wow this was harder than i thought to mess up
    query = text(f"SELECT * FROM admins WHERE username = '{username}' AND password = '{password}'")

    with db.engine.connect() as connection:
        result = connection.execute(query)
        user = result.fetchone()

    if user:
        access_token = create_access_token(identity=user.id)
        session['logged_in'] = True
        return redirect(url_for('admin_dashboard'))
    else:
        error = "Inval username or password"
        return render_template('admin.html', error=error), 401
    

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = Admin.query.get(current_user_id)
    return jsonify(logged_in_as=user.email), 200

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'logged_in' in session:  # Check if the user is logged in
        return render_template('html/admin_dashboard.html')  # Render dashboard
    else:
        flash("You must be logged in to access the dashboard.", "error")
        return render_template('html/admin.html')  # Redirect to admin log in if not logged in

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)