from extensions import db, bcrypt


class SecureAdmin(db.Model):
    """This is for the secure dashboard login"""
    __tablename__ = 'secure_admin'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, username, password, email):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.email = email


class Admin(db.Model):
    """This is for the vulnerable SQL injection demo"""
    __tablename__ = 'admin'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    embarrassing_fact = db.Column(db.Text)

    def create_default_admin(app):
        """Create a default admin user for the SQL injection demo"""
        with app.app_context():
            if not Admin.query.filter_by(username='admin').first():
                admin = Admin(
                    username='username',
                    password='password123'  # In a real app, this would be hashed
                )
                db.session.add(admin)
                try:
                    db.session.commit()
                    print("Default admin created successfully!")
                except Exception as e:
                    print(f"Error creating default admin: {e}")
                    db.session.rollback()

    def __repr__(self):
        return f'<Admin {self.username}>'
