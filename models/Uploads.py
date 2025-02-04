from extensions import db
from datetime import datetime
from sqlalchemy.orm import validates
import os


class Upload(db.Model):
    __tablename__ = 'uploads'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

    @validates('filename')
    def validate_filename(self, key, filename):
        # Basic filename sanitization
        if not filename or '..' in filename:
            raise ValueError('Invalid filename')
        return filename

    def __repr__(self):
        return f'<Upload {self.filename}>'