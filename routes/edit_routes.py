from flask import Blueprint, redirect, render_template, request, url_for
import subprocess
from auth.auth_middleware import requires_auth  # Updated import
from db import db
from db.models import BackendBlock, ConfigBase, Certificate, FrontendBlock
from utils.haproxy_config import (
    DEFAULT_BASE_CONFIG,
    parse_haproxy_sections,
    replace_haproxy_section,
    write_haproxy_config,
    _extract_default_backend,
)
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
    selected_type = None
    selected_name = None
    if request.method == 'POST':
        action = request.form.get('action', 'update').strip()
        section_type = request.form.get('section_type', '').strip()
        section_name = request.form.get('section_name', '').strip()
        section_content = request.form.get('section_content', '').strip()
        target_type = request.form.get('target_type', '').strip()
        target_name = request.form.get('target_name', '').strip()

        if action == 'update':
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
                    if ok:
                        selected_type = section_type
                        selected_name = section_name
        elif action == 'edit':
            if target_type and target_name:
                selected_type = target_type
                selected_name = target_name
        elif action in {'enable', 'disable', 'delete', 'clone'}:
            if not target_type or not target_name:
                message = "Missing target for action."
            else:
                if target_type == 'frontend':
                    record = FrontendBlock.query.filter_by(name=target_name).first()
                else:
                    record = BackendBlock.query.filter_by(name=target_name).first()

                if not record:
                    message = f"{target_type.title()} '{target_name}' not found."
                else:
                    if action == 'clone':
                        base_name = f"{record.name}-copy"
                        suffix = 1
                        new_name = base_name
                        model = FrontendBlock if target_type == 'frontend' else BackendBlock
                        while model.query.filter_by(name=new_name).first():
                            suffix += 1
                            new_name = f"{base_name}-{suffix}"

                        content_lines = record.content.splitlines()
                        if content_lines:
                            content_lines[0] = f"{target_type} {new_name}"
                        new_content = "\n".join(content_lines) + "\n"
                        if target_type == 'frontend':
                            clone = FrontendBlock(
                                name=new_name,
                                bind_ip=record.bind_ip,
                                bind_port=record.bind_port,
                                mode=record.mode,
                                acl_enabled=record.acl_enabled,
                                default_backend=record.default_backend,
                                ssl_cert_path=record.ssl_cert_path,
                                enabled=False,
                                content=new_content,
                            )
                        else:
                            clone = BackendBlock(
                                name=new_name,
                                enabled=False,
                                content=new_content,
                            )
                        db.session.add(clone)
                        db.session.commit()
                        write_haproxy_config()
                        message = f"{target_type.title()} cloned as {new_name} (disabled)."
                    elif action == 'enable':
                        if target_type == 'frontend':
                            conflict = FrontendBlock.query.filter(
                                FrontendBlock.enabled.is_(True),
                                FrontendBlock.bind_ip == record.bind_ip,
                                FrontendBlock.bind_port == record.bind_port,
                                FrontendBlock.id != record.id,
                            ).first()
                            backend_name = record.default_backend or _extract_default_backend(record.content)
                            backend_ok = True
                            if backend_name:
                                backend_ok = BackendBlock.query.filter_by(name=backend_name, enabled=True).first() is not None
                            if conflict:
                                message = f"Frontend bind {record.bind_ip}:{record.bind_port} is already in use."
                            elif not backend_ok:
                                message = f"Enable backend '{backend_name}' before enabling this frontend."
                            else:
                                record.enabled = True
                                db.session.commit()
                                write_haproxy_config()
                                message = f"Frontend '{record.name}' enabled."
                        else:
                            record.enabled = True
                            db.session.commit()
                            write_haproxy_config()
                            message = f"Backend '{record.name}' enabled."
                    elif action == 'disable':
                        if target_type == 'backend':
                            in_use = None
                            for frontend in FrontendBlock.query.filter_by(enabled=True).all():
                                backend_name = frontend.default_backend or _extract_default_backend(frontend.content)
                                if backend_name == record.name:
                                    in_use = frontend
                                    break
                            if in_use:
                                message = f"Disable frontend '{in_use.name}' before disabling this backend."
                            else:
                                record.enabled = False
                                db.session.commit()
                                write_haproxy_config()
                                message = f"Backend '{record.name}' disabled."
                        else:
                            record.enabled = False
                            db.session.commit()
                            write_haproxy_config()
                            message = f"Frontend '{record.name}' disabled."
                    elif action == 'delete':
                        if target_type == 'backend':
                            in_use = None
                            for frontend in FrontendBlock.query.all():
                                backend_name = frontend.default_backend or _extract_default_backend(frontend.content)
                                if backend_name == record.name:
                                    in_use = frontend
                                    break
                            if in_use:
                                message = f"Delete or repoint frontend '{in_use.name}' before deleting this backend."
                            else:
                                db.session.delete(record)
                                db.session.commit()
                                write_haproxy_config()
                                message = f"Backend '{target_name}' deleted."
                        else:
                            db.session.delete(record)
                            db.session.commit()
                            write_haproxy_config()
                            message = f"Frontend '{target_name}' deleted."

    try:
        sections = parse_haproxy_sections()
    except FileNotFoundError:
        sections = []
        message = message or "HAProxy configuration file not found."
    except PermissionError:
        sections = []
        message = message or "Permission denied reading HAProxy configuration file."

    frontends = FrontendBlock.query.order_by(FrontendBlock.created_at.desc()).all()
    backends = BackendBlock.query.order_by(BackendBlock.created_at.desc()).all()

    frontend_rows = []
    for frontend in frontends:
        backend_name = frontend.default_backend or _extract_default_backend(frontend.content)
        frontend_rows.append({
            'name': frontend.name,
            'bind': f"{frontend.bind_ip}:{frontend.bind_port}",
            'mode': frontend.mode,
            'backend': backend_name,
            'ssl': bool(frontend.ssl_cert_path),
            'enabled': frontend.enabled,
            'updated_at': frontend.updated_at,
        })

    backend_rows = []
    for backend in backends:
        backend_rows.append({
            'name': backend.name,
            'enabled': backend.enabled,
            'updated_at': backend.updated_at,
        })

    return render_template(
        'manage.html',
        sections=sections,
        message=message,
        frontends=frontend_rows,
        backends=backend_rows,
        selected_type=selected_type,
        selected_name=selected_name,
    )


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
