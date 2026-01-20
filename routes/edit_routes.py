from flask import Blueprint, redirect, render_template, request, url_for
import subprocess
from auth.auth_middleware import requires_auth  # Updated import
from db import db
from db.models import BackendHeader, BackendPool, ConfigBase, Certificate, Frontend, FrontendAcl, FrontendBackend
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
                            cloned_backends = []
                            backend_name_map = {}
                            for link in record.backend_links:
                                source_backend = link.backend
                                if not source_backend:
                                    continue
                                backend_base = f"{source_backend.name}-copy"
                                backend_suffix = 1
                                backend_name = backend_base
                                while BackendPool.query.filter_by(name=backend_name).first():
                                    backend_suffix += 1
                                    backend_name = f"{backend_base}-{backend_suffix}"
                                cloned_backend = BackendPool(
                                    name=backend_name,
                                    enabled=False,
                                    mode=source_backend.mode,
                                    sticky_enabled=source_backend.sticky_enabled,
                                    sticky_type=source_backend.sticky_type,
                                )
                                for header in source_backend.headers:
                                    cloned_backend.headers.append(BackendHeader(
                                        name=header.name,
                                        value=header.value,
                                        enabled=header.enabled,
                                    ))
                                for server in source_backend.servers:
                                    cloned_backend.servers.append(server.__class__(
                                        name=server.name,
                                        ip=server.ip,
                                        port=server.port,
                                        maxconn=server.maxconn,
                                        enabled=False,
                                        health_check_enabled=server.health_check_enabled,
                                        health_check_path=server.health_check_path,
                                        health_check_tcp=server.health_check_tcp,
                                    ))
                                db.session.add(cloned_backend)
                                db.session.flush()
                                cloned_backends.append((cloned_backend, link.is_default))
                                backend_name_map[source_backend.name] = cloned_backend.id

                            default_backend_id = None
                            for backend_item, is_default in cloned_backends:
                                if is_default:
                                    default_backend_id = backend_item.id
                                    break
                            if not default_backend_id and cloned_backends:
                                default_backend_id = cloned_backends[0][0].id

                            clone = Frontend(
                                name=new_name,
                                bind_ip=record.bind_ip,
                                bind_port=record.bind_port,
                                mode=record.mode,
                                lb_method=record.lb_method,
                                default_backend_id=default_backend_id,
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
                            db.session.add(clone)
                            db.session.flush()

                            for backend_item, is_default in cloned_backends:
                                db.session.add(FrontendBackend(
                                    frontend_id=clone.id,
                                    backend_id=backend_item.id,
                                    is_default=is_default,
                                ))

                            for acl in record.acls:
                                backend_id = backend_name_map.get(acl.backend.name) if acl.backend else None
                                clone.acls.append(acl.__class__(
                                    name=acl.name,
                                    action=acl.action,
                                    backend_id=backend_id,
                                ))
                            for forbidden in record.forbidden_paths:
                                clone.forbidden_paths.append(forbidden.__class__(
                                    acl_name=forbidden.acl_name,
                                    allowed_ip=forbidden.allowed_ip,
                                    path=forbidden.path,
                                ))
                            for redirect_rule in record.redirect_rules:
                                clone.redirect_rules.append(redirect_rule.__class__(
                                    host_match=redirect_rule.host_match,
                                    root_path=redirect_rule.root_path,
                                    redirect_to=redirect_rule.redirect_to,
                                ))
                        else:
                            clone = BackendPool(
                                name=new_name,
                                enabled=False,
                                mode=record.mode,
                                sticky_enabled=record.sticky_enabled,
                                sticky_type=record.sticky_type,
                            )
                            for header in record.headers:
                                clone.headers.append(BackendHeader(
                                    name=header.name,
                                    value=header.value,
                                    enabled=header.enabled,
                                ))
                            for server in record.servers:
                                clone.servers.append(server.__class__(
                                    name=server.name,
                                    ip=server.ip,
                                    port=server.port,
                                    maxconn=server.maxconn,
                                    enabled=False,
                                    health_check_enabled=server.health_check_enabled,
                                    health_check_path=server.health_check_path,
                                    health_check_tcp=server.health_check_tcp,
                                ))
                        db.session.add(clone)
                        db.session.commit()
                        write_haproxy_config()
                        message = f"{target_type.title()} cloned as {new_name} (disabled)."
                    elif action == 'enable':
                        if target_type == 'frontend':
                            conflict = None
                            if record.domain_name:
                                conflict = Frontend.query.filter(
                                    Frontend.enabled.is_(True),
                                    Frontend.domain_name == record.domain_name,
                                    Frontend.id != record.id,
                                ).first()
                            if conflict:
                                message = f"Domain {record.domain_name} is already enabled on '{conflict.name}'."
                            else:
                                record.enabled = True
                                for link in record.backend_links:
                                    if link.backend:
                                        link.backend.enabled = True
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
                            in_use = FrontendBackend.query.filter(
                                FrontendBackend.backend_id == record.id,
                            ).first()
                            if in_use:
                                message = "Disable or delete the frontend using this backend before disabling it."
                            else:
                                record.enabled = False
                                db.session.commit()
                                write_haproxy_config()
                                message = f"Backend '{record.name}' disabled."
                        else:
                            record.enabled = False
                            for link in record.backend_links:
                                backend_record = link.backend
                                if not backend_record:
                                    continue
                                in_use = FrontendBackend.query.filter(
                                    FrontendBackend.backend_id == backend_record.id,
                                    FrontendBackend.frontend_id != record.id,
                                ).first()
                                in_acl = FrontendAcl.query.filter_by(backend_id=backend_record.id).first()
                                if not in_use and not in_acl:
                                    backend_record.enabled = False
                            db.session.commit()
                            write_haproxy_config()
                            message = f"Frontend '{record.name}' disabled."
                    elif action == 'delete':
                        if target_type == 'backend':
                            in_use = FrontendBackend.query.filter_by(backend_id=record.id).first()
                            if in_use:
                                message = "Delete or repoint the frontend using this backend before deleting it."
                            else:
                                db.session.delete(record)
                                db.session.commit()
                                write_haproxy_config()
                                message = f"Backend '{target_name}' deleted."
                        else:
                            backend_ids = [link.backend_id for link in record.backend_links]
                            db.session.delete(record)
                            for backend_id in backend_ids:
                                in_use = FrontendBackend.query.filter_by(backend_id=backend_id).first()
                                in_acl = FrontendAcl.query.filter_by(backend_id=backend_id).first()
                                if not in_use and not in_acl:
                                    backend_record = BackendPool.query.filter_by(id=backend_id).first()
                                    if backend_record:
                                        db.session.delete(backend_record)
                            db.session.commit()
                            write_haproxy_config()
                            message = f"Frontend '{target_name}' deleted."

    frontends = Frontend.query.order_by(Frontend.created_at.desc()).all()

    frontend_rows = []
    for frontend in frontends:
        backend_name = frontend.backend.name if frontend.backend else None
        backend_servers_count = sum(
            len(link.backend.servers)
            for link in frontend.backend_links
            if link.backend
        )
        frontend_rows.append({
            'name': frontend.name,
            'domain': frontend.domain_name,
            'mode': frontend.mode,
            'backend': backend_name,
            'backend_servers_count': backend_servers_count,
            'ssl': frontend.use_ssl,
            'enabled': frontend.enabled,
            'updated_at': frontend.updated_at,
        })

    return render_template(
        'manage.html',
        message=message,
        frontends=frontend_rows,
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
