from flask import Flask, jsonify, request, redirect, url_for, render_template, session, flash
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import os
from models import db, Admin

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/mojorepair_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['SECRET_KEY'] = os.urandom(24)  # for session management

db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


@app.route('/')
def api_home():
    return jsonify({"message": "Welcome to the MoJoRepair API"})


@app.route('/admin', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Admin.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            session['logged_in'] = True
            session['user_id'] = user.id
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid username or password", "error")

    return render_template('admin.html')


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = Admin.query.get(current_user_id)
    return jsonify(logged_in_as=user.email), 200


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'logged_in' in session and 'user_id' in session:
        user = Admin.query.get(session['user_id'])
        if user:
            return render_template('admin_dashboard.html', user=user)

    flash("You must be logged in to access the dashboard.", "error")
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)