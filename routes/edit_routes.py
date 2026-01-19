from flask import Blueprint, redirect, render_template, request, url_for
import subprocess
from auth.auth_middleware import requires_auth  # Updated import
from db import db
from db.models import ConfigBase, Certificate
from utils.haproxy_config import DEFAULT_BASE_CONFIG, parse_haproxy_sections, replace_haproxy_section, write_haproxy_config
from utils.acme_utils import _get_cert_enddate, _get_cert_issuer, list_installed_certificates, renew_certificate

edit_bp = Blueprint('edit', __name__)

@edit_bp.route('/edit', methods=['GET', 'POST'])
@requires_auth
def edit_haproxy_config():
    return redirect(url_for('edit.manage_base_config'))


@edit_bp.route('/config', methods=['GET', 'POST'])
@requires_auth
def manage_base_config():
    check_output = ""
    base_config = ConfigBase.query.first()
    if not base_config:
        base_config = ConfigBase(content=DEFAULT_BASE_CONFIG)
        db.session.add(base_config)
        db.session.commit()

    if request.method == 'POST':
        base_config.content = request.form['base_config']
        db.session.commit()
        write_haproxy_config()

        if 'save_check' in request.form:
            check_result = subprocess.run(['haproxy', '-c', '-V', '-f', '/etc/haproxy/haproxy.cfg'], capture_output=True, text=True)
            check_output = check_result.stdout
            if check_result.returncode != 0:
                error_message = check_result.stderr
                check_output += f"\n\nError occurred:\n{error_message}"

        elif 'save_reload' in request.form:
            check_result = subprocess.run(['haproxy', '-c', '-V', '-f', '/etc/haproxy/haproxy.cfg'], capture_output=True, text=True)
            check_output = check_result.stdout
            if check_result.returncode != 0:
                error_message = check_result.stderr
                check_output += f"\n\nError occurred:\n{error_message}"
            else:
                reload_result = subprocess.run(['systemctl', 'restart', 'haproxy'], capture_output=True, text=True)
                check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"
                if reload_result.stderr:
                    check_output += f"\nRestart Stderr:\n{reload_result.stderr}"

    return render_template('config.html', config_content=base_config.content, check_output=check_output)


@edit_bp.route('/manage', methods=['GET', 'POST'])
@requires_auth
def manage_haproxy_sections():
    message = None
    if request.method == 'POST':
        section_type = request.form.get('section_type', '').strip()
        section_name = request.form.get('section_name', '').strip()
        section_content = request.form.get('section_content', '').strip()

        if not section_type or not section_name:
            message = "Please select a frontend or backend."
        elif not section_content:
            message = "Section content is required."
        else:
            first_line = section_content.splitlines()[0].strip()
            if not first_line.startswith(f"{section_type} "):
                message = f"Section must start with '{section_type} <name>'."
            else:
                ok, detail = replace_haproxy_section(section_type, section_name, section_content)
                message = detail

    try:
        sections = parse_haproxy_sections()
    except FileNotFoundError:
        sections = []
        message = message or "HAProxy configuration file not found."
    except PermissionError:
        sections = []
        message = message or "Permission denied reading HAProxy configuration file."

    return render_template('manage.html', sections=sections, message=message)


@edit_bp.route('/certificates', methods=['GET', 'POST'])
@requires_auth
def manage_certificates():
    message = None
    if request.method == 'POST':
        action = request.form.get('action', 'renew')
        if action == 'add':
            domain = request.form.get('domain', '').strip()
            pem_path = request.form.get('pem_path', '').strip()
            if not domain or not pem_path:
                message = "Domain and PEM path are required."
            else:
                if Certificate.query.filter_by(domain=domain).first():
                    message = f"Certificate for {domain} already exists."
                else:
                    cert = Certificate(
                        domain=domain,
                        pem_path=pem_path,
                        issuer=_get_cert_issuer(pem_path),
                        expires_at=_get_cert_enddate(pem_path),
                    )
                    db.session.add(cert)
                    db.session.commit()
                    message = f"Certificate added for {domain}."
        else:
            domain = request.form.get('domain', '').strip()
            if not domain:
                message = "Please select a certificate."
            else:
                try:
                    renew_certificate(domain)
                    message = f"Certificate renewed for {domain}."
                except Exception as exc:
                    message = f"Failed to renew {domain}: {exc}"

    try:
        certificates = list_installed_certificates()
    except Exception as exc:
        certificates = []
        message = message or f"Failed to load certificates: {exc}"

    return render_template('certificates.html', certificates=certificates, message=message)
