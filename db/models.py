from datetime import datetime

from . import db


class ConfigBase(db.Model):
    __tablename__ = 'config_base'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class FrontendBlock(db.Model):
    __tablename__ = 'frontend_blocks'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    bind_ip = db.Column(db.String(64), nullable=False)
    bind_port = db.Column(db.String(16), nullable=False)
    mode = db.Column(db.String(16), nullable=False)
    acl_enabled = db.Column(db.Boolean, default=False, nullable=False)
    ssl_cert_path = db.Column(db.String(512), nullable=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class BackendBlock(db.Model):
    __tablename__ = 'backend_blocks'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Certificate(db.Model):
    __tablename__ = 'certificates'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    pem_path = db.Column(db.String(512), nullable=False)
    issuer = db.Column(db.String(255), nullable=True)
    expires_at = db.Column(db.String(64), nullable=True)
    last_renewed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
