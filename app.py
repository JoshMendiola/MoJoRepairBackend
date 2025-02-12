import os
from dotenv import load_dotenv
import time
from flask import Flask, jsonify, request, make_response
from flask_bcrypt import check_password_hash
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies
from datetime import timedelta
import pymysql
import logging
import uuid

from sqlalchemy import text
from werkzeug.utils import secure_filename

from extensions import db, bcrypt, jwt
from models.Admin import SecureAdmin, create_default_admin
from models.Employee import Employee
from models.Messages import Message
from models.Uploads import Upload

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

def check_image_magic_bytes(file_content):
    """Check if file starts with valid image magic bytes"""
    image_signatures = {
        b'\xFF\xD8\xFF': 'jpg',
        b'\x89\x50\x4E\x47': 'png',
        b'\x47\x49\x46\x38': 'gif'
    }

    for signature in image_signatures:
        if file_content.startswith(signature):
            return True
    return False

def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True, resources={
        r"/api/*": {
            "origins": ["http://147.182.176.235"],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "Cookie"],  # Added Cookie
            "expose_headers": ["Set-Cookie"],
            "supports_credentials": True,
            "allow_credentials": True
        }
    })

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
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    # JWT Configuration
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'authToken'
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
    app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
    app.config['JWT_COOKIE_SECURE'] = False
    app.config['JWT_ERROR_MESSAGE_KEY'] = 'message'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'sh', 'php'}  # Intentionally allowing .sh and .php
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max-size

    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        # Ensure directory is accessible
        os.chmod(UPLOAD_FOLDER, 0o755)

    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    # JWT error handlers
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        app.logger.error(f"Invalid token error: {error}")
        return jsonify({
            'message': 'Invalid token',
            'error': str(error)
        }), 401

    @jwt.unauthorized_loader
    def unauthorized_callback(error):
        app.logger.error(f"Unauthorized error: {error}")
        return jsonify({
            'message': 'No token provided',
            'error': str(error)
        }), 401

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        app.logger.error("Token has expired")
        return jsonify({
            'message': 'Token has expired',
            'error': 'token_expired'
        }), 401

    with app.app_context():
        try:
            db.create_all()
            create_secure_admin(app)
            create_default_admin(app)
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

        try:
            user = SecureAdmin.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, password):
                # Convert user.id to string for JWT
                access_token = create_access_token(identity=str(user.id))

                response = make_response(jsonify({
                    "message": "Login successful",
                    "username": user.username
                }))

                # Set cookie with more specific parameters
                set_access_cookies(response, access_token)

                app.logger.debug(f"Login successful for user: {user.username}")
                app.logger.debug(f"Setting cookie: {access_token[:10]}...")
                app.logger.debug(f"User ID (identity): {user.id}")

                return response

            return jsonify({"message": "Invalid credentials"}), 401

        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            return jsonify({"message": "Login failed"}), 500

    @app.route('/api/sql-demo/employees', methods=['GET'])
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
            query = f"SELECT * FROM admin WHERE username='{username}' AND password='{password}'"
            app.logger.debug(f"Executing query: {query}")  # Added for debugging
            result = db.session.execute(text(query)).fetchone()

            if result:
                app.logger.debug("SQL Demo login successful")
                return jsonify({"message": "Login successful"}), 200
            else:
                app.logger.debug("SQL Demo login failed - No matching credentials")
                return jsonify({"message": "Invalid credentials"}), 401

        except Exception as e:
            app.logger.error(f"Error in SQL demo login: {str(e)}")
            return jsonify({"message": f"Login failed: {str(e)}"}), 500

    # VULNERABLE XSS DEMO
    @app.route('/api/xss-demo/messages', methods=['GET'])
    def get_all_messages():
        """Endpoint to get all messages - intentionally vulnerable to XSS/CSS injection"""
        try:
            messages = Message.query.order_by(Message.timestamp.desc()).all()
            return jsonify([{
                'id': msg.id,
                'content': msg.content,  # Intentionally not sanitizing
                'username': msg.username,  # Intentionally not sanitizing
                'timestamp': msg.timestamp.isoformat()
            } for msg in messages]), 200
        except Exception as e:
            app.logger.error(f"Error fetching messages: {str(e)}")
            return jsonify({"message": "Failed to fetch messages"}), 500

    @app.route('/api/xss-demo/post', methods=['POST'])
    def post_message():
        """Endpoint to post a new message - intentionally vulnerable to XSS/CSS injection"""
        try:
            data = request.get_json()
            message = Message(
                content=data.get('content'),  # Intentionally not sanitizing
                username=data.get('username', 'Anonymous')  # Intentionally not sanitizing
            )
            db.session.add(message)
            db.session.commit()
            return jsonify({"message": "Posted successfully"}), 200
        except Exception as e:
            app.logger.error(f"Error posting message: {str(e)}")
            db.session.rollback()
            return jsonify({"message": "Failed to post message"}), 500

    @app.route('/api/xss-demo/clear', methods=['POST'])
    def clear_messages():
        """Endpoint to clear all messages"""
        try:
            Message.query.delete()
            db.session.commit()
            return jsonify({"message": "All messages cleared"}), 200
        except Exception as e:
            app.logger.error(f"Error clearing messages: {str(e)}")
            db.session.rollback()
            return jsonify({"message": "Failed to clear messages"}), 500

    @app.route('/api/check-auth', methods=['GET'])
    @jwt_required()
    def check_auth():
        """Endpoint to verify JWT token validity"""
        try:
            app.logger.debug(f"Cookies received: {request.cookies}")

            current_user_id = get_jwt_identity()
            app.logger.debug(f"JWT identity found: {current_user_id}")

            # Convert string ID back to integer for database query
            user = SecureAdmin.query.get(int(current_user_id))
            app.logger.debug(f"User found in DB: {user is not None}")

            if user:
                app.logger.debug(f"Auth check successful for user: {user.username}")
                return jsonify({
                    "authenticated": True,
                    "username": user.username
                }), 200

            app.logger.debug("Auth check failed: user not found")
            return jsonify({"authenticated": False}), 401

        except Exception as e:
            app.logger.error(f"Error checking auth: {str(e)}")
            app.logger.error(f"Request cookies: {request.cookies}")
            return jsonify({
                "authenticated": False,
                "error": str(e)
            }), 401

    # VULNERABLE FILE UPLOAD DEMO
    @app.route('/api/file-demo/upload', methods=['POST'])
    def upload_file():
        """File upload endpoint with magic byte validation"""
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        try:
            # Read the file content
            file_content = file.read()
            file.seek(0)  # Reset file pointer after reading

            # Validate image using magic bytes
            if not check_image_magic_bytes(file_content):
                return jsonify({'error': 'Invalid image file'}), 400

            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Store in database
            upload = Upload(filename=filename, filepath=file_path)
            db.session.add(upload)
            db.session.commit()

            return jsonify({
                'message': 'File uploaded successfully',
                'filename': filename
            }), 200

        except Exception as e:
            app.logger.error(f"Upload error: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/file-demo/files', methods=['GET'])
    def get_uploaded_files():
        """Endpoint to list all uploaded files"""
        app.logger.debug("File Upload Demo files route accessed")
        try:
            uploads = Upload.query.order_by(Upload.upload_date.desc()).all()
            return jsonify([{
                'filename': upload.filename,
                'upload_date': upload.upload_date.isoformat()
            } for upload in uploads]), 200
        except Exception as e:
            app.logger.error(f"Error fetching files: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/file-demo/view/<filename>', methods=['GET'])
    def view_file(filename):
        """Endpoint to view/execute uploaded files"""
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))

            if not os.path.exists(file_path):
                return jsonify({'error': 'File not found'}), 404

            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()

            # Check for shell command after image signature
            shell_content = content[4:]  # Skip past PNG signature

            if b'#!/bin/sh' in shell_content:
                # Extract and execute shell content
                shell_script = shell_content[shell_content.find(b'#!/bin/sh'):].decode('utf-8')

                temp_script = os.path.join('/tmp', f'script_{uuid.uuid4().hex}.sh')
                with open(temp_script, 'w') as f:
                    f.write(shell_script)

                os.chmod(temp_script, 0o755)

                try:
                    process = subprocess.Popen(
                        [temp_script],
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        start_new_session=True
                    )

                    try:
                        stdout, stderr = process.communicate(timeout=1)
                        os.unlink(temp_script)  # Clean up temp file
                        return jsonify({
                            'message': 'File executed',
                            'output': stdout.decode('utf-8') if stdout else '',
                            'error': stderr.decode('utf-8') if stderr else ''
                        }), 200
                    except subprocess.TimeoutExpired:
                        process.poll()
                        os.unlink(temp_script)  # Clean up temp file
                        return jsonify({
                            'message': 'File execution started'
                        }), 200

                except Exception as e:
                    os.unlink(temp_script)  # Clean up temp file
                    return jsonify({'error': str(e)}), 500

            # If no shell content found, treat as regular image
            return jsonify({
                'content': base64.b64encode(content).decode('utf-8')
            }), 200

        except Exception as e:
            app.logger.error(f"Error viewing file: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.after_request
    def after_request(response):
        app.logger.debug(f"Response Headers: {dict(response.headers)}")
        app.logger.debug(f"Response Status: {response.status}")
        return response

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
