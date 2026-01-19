import os

from flask import Flask, render_template
from routes.main_routes import main_bp
from routes.edit_routes import edit_bp
from utils.stats_utils import fetch_haproxy_stats, parse_haproxy_stats
from utils.ssl_utils import load_ssl_config, build_ssl_context
from db import init_db, db
from db.models import ConfigBase
from auth.auth_middleware import setup_auth
from log_parser import parse_log_file
from utils.haproxy_config import DEFAULT_BASE_CONFIG, write_haproxy_config

app = Flask(__name__)

# Database configuration
database_url = os.getenv('DATABASE_URL') or os.getenv('MYSQL_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL or MYSQL_URL must be set for MySQL.")
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
init_db(app)

with app.app_context():
    db.create_all()
    if not ConfigBase.query.first():
        db.session.add(ConfigBase(content=DEFAULT_BASE_CONFIG))
        db.session.commit()
    write_haproxy_config()

# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(edit_bp)

# Setup authentication (placeholder, not currently used)
setup_auth(app)

# SSL Configuration
certificate_path, private_key_path = load_ssl_config()
ssl_context = build_ssl_context(certificate_path, private_key_path)

# Statistics Route
@app.route('/statistics')
def display_haproxy_stats():
    haproxy_stats = fetch_haproxy_stats()
    parsed_stats = parse_haproxy_stats(haproxy_stats)
    return render_template('statistics.html', stats=parsed_stats)

# Logs Route
@app.route('/logs')
def display_logs():
    log_file_path = '/var/log/haproxy.log'
    parsed_entries = parse_log_file(log_file_path)
    return render_template('logs.html', entries=parsed_entries)

if __name__ == '__main__':
    app.run(host='::', port=5000, ssl_context=ssl_context, debug=True)
