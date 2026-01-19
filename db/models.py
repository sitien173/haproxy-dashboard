from datetime import datetime

from . import db


class ConfigBase(db.Model):
    __tablename__ = 'config_base'

    id = db.Column(db.Integer, primary_key=True)
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


class BackendPool(db.Model):
    __tablename__ = 'backend_pools'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    mode = db.Column(db.String(16), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    health_check_enabled = db.Column(db.Boolean, default=False, nullable=False)
    health_check_path = db.Column(db.String(255), nullable=True)
    health_check_tcp = db.Column(db.Boolean, default=False, nullable=False)
    sticky_enabled = db.Column(db.Boolean, default=False, nullable=False)
    sticky_type = db.Column(db.String(32), nullable=True)
    add_header_enabled = db.Column(db.Boolean, default=False, nullable=False)
    header_name = db.Column(db.String(255), nullable=True)
    header_value = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    servers = db.relationship("BackendServer", backref="backend", cascade="all, delete-orphan", lazy=True)


class BackendServer(db.Model):
    __tablename__ = 'backend_servers'

    id = db.Column(db.Integer, primary_key=True)
    backend_id = db.Column(db.Integer, db.ForeignKey('backend_pools.id'), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    ip = db.Column(db.String(64), nullable=False)
    port = db.Column(db.String(16), nullable=False)
    maxconn = db.Column(db.String(16), nullable=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Frontend(db.Model):
    __tablename__ = 'frontends'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    bind_ip = db.Column(db.String(64), nullable=False)
    bind_port = db.Column(db.String(16), nullable=False)
    mode = db.Column(db.String(16), nullable=False)
    lb_method = db.Column(db.String(32), nullable=False)
    default_backend_id = db.Column(db.Integer, db.ForeignKey('backend_pools.id'), nullable=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    use_ssl = db.Column(db.Boolean, default=False, nullable=False)
    ssl_cert_id = db.Column(db.Integer, db.ForeignKey('certificates.id'), nullable=True)
    domain_name = db.Column(db.String(255), nullable=True)
    https_redirect = db.Column(db.Boolean, default=False, nullable=False)
    forward_for = db.Column(db.Boolean, default=False, nullable=False)
    dos_enabled = db.Column(db.Boolean, default=False, nullable=False)
    dos_limit = db.Column(db.String(32), nullable=True)
    dos_ban_duration = db.Column(db.String(32), nullable=True)
    sql_injection_enabled = db.Column(db.Boolean, default=False, nullable=False)
    xss_enabled = db.Column(db.Boolean, default=False, nullable=False)
    remote_upload_enabled = db.Column(db.Boolean, default=False, nullable=False)
    webshells_enabled = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    backend = db.relationship("BackendPool", backref="frontends", lazy=True)
    certificate = db.relationship("Certificate", lazy=True)
    acl = db.relationship("FrontendAcl", uselist=False, backref="frontend", cascade="all, delete-orphan")
    forbidden_path = db.relationship("FrontendForbiddenPath", uselist=False, backref="frontend", cascade="all, delete-orphan")
    redirect_rule = db.relationship("FrontendRedirect", uselist=False, backref="frontend", cascade="all, delete-orphan")


class FrontendAcl(db.Model):
    __tablename__ = 'frontend_acls'

    id = db.Column(db.Integer, primary_key=True)
    frontend_id = db.Column(db.Integer, db.ForeignKey('frontends.id'), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    backend_id = db.Column(db.Integer, db.ForeignKey('backend_pools.id'), nullable=True)

    backend = db.relationship("BackendPool", lazy=True)


class FrontendForbiddenPath(db.Model):
    __tablename__ = 'frontend_forbidden_paths'

    id = db.Column(db.Integer, primary_key=True)
    frontend_id = db.Column(db.Integer, db.ForeignKey('frontends.id'), nullable=False)
    acl_name = db.Column(db.String(128), nullable=False)
    allowed_ip = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(255), nullable=False)


class FrontendRedirect(db.Model):
    __tablename__ = 'frontend_redirects'

    id = db.Column(db.Integer, primary_key=True)
    frontend_id = db.Column(db.Integer, db.ForeignKey('frontends.id'), nullable=False)
    host_match = db.Column(db.String(255), nullable=False)
    root_path = db.Column(db.String(255), nullable=False)
    redirect_to = db.Column(db.String(255), nullable=False)
