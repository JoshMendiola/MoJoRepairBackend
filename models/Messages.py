from extensions import db
from datetime import datetime


class Message(db.Model):
    """Model for the messages table - intentionally vulnerable to CSS injection"""
    __tablename__ = 'messages'  # Changed from ** to __

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # Stores unsanitized content
    username = db.Column(db.String(255), nullable=False)  # Changed from author to match endpoint
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):  # Changed from ** to __
        return f'<Message {self.id} by {self.username}>'  # Changed author to username
