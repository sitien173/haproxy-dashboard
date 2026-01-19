from flask import Blueprint, redirect, render_template, request, url_for
import subprocess
from auth.auth_middleware import requires_auth  # Updated import
from db import db
from db.models import BackendPool, ConfigBase, Certificate, Frontend
from utils.haproxy_config import DEFAULT_BASE_CONFIG, write_haproxy_config
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
        action = request.form.get('action', 'update').strip()
        target_type = request.form.get('target_type', '').strip()
        target_name = request.form.get('target_name', '').strip()

        if action == 'edit':
            if target_type == 'frontend':
                record = Frontend.query.filter_by(name=target_name).first()
                if record:
                    return redirect(url_for('main.index', edit_frontend=record.id))
            elif target_type == 'backend':
                record = BackendPool.query.filter_by(name=target_name).first()
                if record:
                    return redirect(url_for('main.index', edit_backend=record.id))
            message = "Target not found for edit."
        elif action in {'enable', 'disable', 'delete', 'clone'}:
            if not target_type or not target_name:
                message = "Missing target for action."
            else:
                if target_type == 'frontend':
                    record = Frontend.query.filter_by(name=target_name).first()
                else:
                    record = BackendPool.query.filter_by(name=target_name).first()

                if not record:
                    message = f"{target_type.title()} '{target_name}' not found."
                else:
                    if action == 'clone':
                        base_name = f"{record.name}-copy"
                        suffix = 1
                        new_name = base_name
                        model = Frontend if target_type == 'frontend' else BackendPool
                        while model.query.filter_by(name=new_name).first():
                            suffix += 1
                            new_name = f"{base_name}-{suffix}"

                        if target_type == 'frontend':
                            clone = Frontend(
                                name=new_name,
                                bind_ip=record.bind_ip,
                                bind_port=record.bind_port,
                                mode=record.mode,
                                lb_method=record.lb_method,
                                default_backend_id=record.default_backend_id,
                                enabled=False,
                                use_ssl=record.use_ssl,
                                ssl_cert_id=record.ssl_cert_id,
                                domain_name=record.domain_name,
                                https_redirect=record.https_redirect,
                                forward_for=record.forward_for,
                                dos_enabled=record.dos_enabled,
                                dos_limit=record.dos_limit,
                                dos_ban_duration=record.dos_ban_duration,
                                sql_injection_enabled=record.sql_injection_enabled,
                                xss_enabled=record.xss_enabled,
                                remote_upload_enabled=record.remote_upload_enabled,
                                webshells_enabled=record.webshells_enabled,
                            )
                            if record.acl:
                                clone.acl = record.acl.__class__(
                                    name=record.acl.name,
                                    action=record.acl.action,
                                    backend_id=record.acl.backend_id,
                                )
                            if record.forbidden_path:
                                clone.forbidden_path = record.forbidden_path.__class__(
                                    acl_name=record.forbidden_path.acl_name,
                                    allowed_ip=record.forbidden_path.allowed_ip,
                                    path=record.forbidden_path.path,
                                )
                            if record.redirect_rule:
                                clone.redirect_rule = record.redirect_rule.__class__(
                                    host_match=record.redirect_rule.host_match,
                                    root_path=record.redirect_rule.root_path,
                                    redirect_to=record.redirect_rule.redirect_to,
                                )
                        else:
                            clone = BackendPool(
                                name=new_name,
                                enabled=False,
                                mode=record.mode,
                                health_check_enabled=record.health_check_enabled,
                                health_check_path=record.health_check_path,
                                health_check_tcp=record.health_check_tcp,
                                sticky_enabled=record.sticky_enabled,
                                sticky_type=record.sticky_type,
                                add_header_enabled=record.add_header_enabled,
                                header_name=record.header_name,
                                header_value=record.header_value,
                            )
                            for server in record.servers:
                                clone.servers.append(server.__class__(
                                    name=server.name,
                                    ip=server.ip,
                                    port=server.port,
                                    maxconn=server.maxconn,
                                    enabled=False,
                                ))
                        db.session.add(clone)
                        db.session.commit()
                        write_haproxy_config()
                        message = f"{target_type.title()} cloned as {new_name} (disabled)."
                    elif action == 'enable':
                        if target_type == 'frontend':
                            conflict = Frontend.query.filter(
                                Frontend.enabled.is_(True),
                                Frontend.bind_ip == record.bind_ip,
                                Frontend.bind_port == record.bind_port,
                                Frontend.id != record.id,
                            ).first()
                            backend_ok = True
                            if record.default_backend_id:
                                backend_ok = BackendPool.query.filter_by(id=record.default_backend_id, enabled=True).first() is not None
                            if conflict:
                                message = f"Frontend bind {record.bind_ip}:{record.bind_port} is already in use."
                            elif not backend_ok:
                                message = "Enable the backend before enabling this frontend."
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
                            in_use = Frontend.query.filter(
                                Frontend.enabled.is_(True),
                                Frontend.default_backend_id == record.id,
                            ).first()
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
                            in_use = Frontend.query.filter_by(default_backend_id=record.id).first()
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

    frontends = Frontend.query.order_by(Frontend.created_at.desc()).all()
    backends = BackendPool.query.order_by(BackendPool.created_at.desc()).all()

    frontend_rows = []
    for frontend in frontends:
        backend_name = frontend.backend.name if frontend.backend else None
        frontend_rows.append({
            'name': frontend.name,
            'bind': f"{frontend.bind_ip}:{frontend.bind_port}",
            'mode': frontend.mode,
            'backend': backend_name,
            'ssl': frontend.use_ssl,
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
        message=message,
        frontends=frontend_rows,
        backends=backend_rows,
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
