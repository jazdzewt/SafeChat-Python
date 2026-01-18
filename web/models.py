import uuid

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.orm import deferred

db = SQLAlchemy()


class User(UserMixin, db.Model):
    # default= generuje losowe UUID przy tworzeniu nowego usera
    # ten uuid4 zapewnia w pełni losowy identyfikator
    # 36 znaków "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    encrypted_totp_secret = db.Column(db.String(300), nullable=True)

class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    topic = db.Column(db.String(150), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    # deferred powoduje, że dane z tych kolumn nie są pobierane z bazy przy zwykłym zapytaniu,
    # tylko w przypadku bezposredniego zapytania do tej kolumny
    encrypted_body = deferred(db.Column(db.LargeBinary, nullable=False))
    body_nonce = deferred(db.Column(db.LargeBinary, nullable=False))
    tag = deferred(db.Column(db.LargeBinary, nullable=False))
    enc_session_key_recipient = deferred(db.Column(db.LargeBinary, nullable=False))
    signature = deferred(db.Column(db.LargeBinary, nullable=False))

    # cascade="all, delete-orphan" SQLAlchemy automatycznie usuwa wszystkie załączniki przypisane do wiadomości.
    # lazy=True powoduje, że załączniki nie są każdorazowo pobierane
    attachments = db.relationship('Attachment', backref='message', lazy=True, cascade="all, delete-orphan")

class Attachment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    message_id = db.Column(db.String(36), db.ForeignKey('message.id'), nullable=False)
    
    filename = db.Column(db.String(255), nullable=False)
    encrypted_blob = deferred(db.Column(db.LargeBinary, nullable=False))
    nonce = deferred(db.Column(db.LargeBinary, nullable=False))
    tag = deferred(db.Column(db.LargeBinary, nullable=False))