import json

from flask import Blueprint, redirect, render_template, request, url_for

from auth.auth_middleware import requires_auth
from db import db
from db.models import (
    BackendPool,
    BackendServer,
    Certificate,
    Frontend,
    FrontendAcl,
    FrontendForbiddenPath,
    FrontendRedirect,
)
from utils.acme_utils import _get_cert_enddate, _get_cert_issuer, issue_certificate, list_installed_certificates
from utils.haproxy_config import count_frontends_and_backends, is_backend_exist, is_frontend_exist, write_haproxy_config

main_bp = Blueprint('main', __name__)


def _build_form_data(frontend=None, backend=None):
    data = {
        'frontend_id': frontend.id if frontend else '',
        'backend_id': backend.id if backend else '',
        'frontend_name': frontend.name if frontend else '',
        'frontend_ip': frontend.bind_ip if frontend else '',
        'frontend_port': frontend.bind_port if frontend else '',
        'lb_method': frontend.lb_method if frontend else 'roundrobin',
        'protocol': frontend.mode if frontend else (backend.mode if backend else ''),
        'use_ssl': bool(frontend.use_ssl) if frontend else False,
        'ssl_mode': 'acme' if (frontend and frontend.domain_name) else 'existing',
        'ssl_cert_id': frontend.ssl_cert_id if frontend else '',
        'domain_name': frontend.domain_name if frontend else '',
        'https_redirect': bool(frontend.https_redirect) if frontend else False,
        'forward_for': bool(frontend.forward_for) if frontend else False,
        'dos_enabled': bool(frontend.dos_enabled) if frontend else False,
        'limit_requests': frontend.dos_limit if frontend else '',
        'ban_duration': frontend.dos_ban_duration if frontend else '',
        'sql_injection_enabled': bool(frontend.sql_injection_enabled) if frontend else False,
        'xss_enabled': bool(frontend.xss_enabled) if frontend else False,
        'remote_upload_enabled': bool(frontend.remote_upload_enabled) if frontend else False,
        'webshells_enabled': bool(frontend.webshells_enabled) if frontend else False,
        'add_acl': bool(frontend.acl) if frontend else False,
        'acl': frontend.acl.name if frontend and frontend.acl else '',
        'acl_action': frontend.acl.action if frontend and frontend.acl else '',
        'backend_name_acl': frontend.acl.backend.name if frontend and frontend.acl and frontend.acl.backend else '',
        'add_acl_path': bool(frontend.forbidden_path) if frontend else False,
        'forbidden_name': frontend.forbidden_path.acl_name if frontend and frontend.forbidden_path else '',
        'allowed_ip': frontend.forbidden_path.allowed_ip if frontend and frontend.forbidden_path else '',
        'forbidden_path': frontend.forbidden_path.path if frontend and frontend.forbidden_path else '',
        'add_path_based': bool(frontend.redirect_rule) if frontend else False,
        'redirect_domain_name': frontend.redirect_rule.host_match if frontend and frontend.redirect_rule else '',
        'root_redirect': frontend.redirect_rule.root_path if frontend and frontend.redirect_rule else '',
        'redirect_to': frontend.redirect_rule.redirect_to if frontend and frontend.redirect_rule else '',
        'backend_name': backend.name if backend else '',
        'health_check': bool(backend.health_check_enabled) if backend else False,
        'health_check_link': backend.health_check_path if backend else '',
        'health_check_tcp': bool(backend.health_check_tcp) if backend else False,
        'sticky_session': bool(backend.sticky_enabled) if backend else False,
        'sticky_session_type': backend.sticky_type if backend and backend.sticky_type else 'cookie',
        'add_header': bool(backend.add_header_enabled) if backend else False,
        'header_name': backend.header_name if backend else '',
        'header_value': backend.header_value if backend else '',
        'backend_servers': [],
    }

    if backend and backend.servers:
        data['backend_servers'] = [
            {
                'name': server.name,
                'ip': server.ip,
                'port': server.port,
                'maxconn': server.maxconn or '',
            }
            for server in backend.servers
        ]
    return data


def _build_backend_servers(request_form):
    payload = request_form.get('backend_servers_payload', '').strip()
    if payload:
        try:
            servers = json.loads(payload)
            normalized = []
            for index, server in enumerate(servers):
                ip = (server.get('ip') or '').strip()
                port = (server.get('port') or '').strip()
                if not ip or not port:
                    continue
                name = (server.get('name') or '').strip() or f"server{index + 1}"
                maxconn = (server.get('maxconn') or '').strip() or None
                normalized.append({
                    'name': name,
                    'ip': ip,
                    'port': port,
                    'maxconn': maxconn,
                })
            return normalized
        except json.JSONDecodeError:
            pass

    names = request_form.getlist('backend_server_names[]')
    ips = request_form.getlist('backend_server_ips[]')
    ports = request_form.getlist('backend_server_ports[]')
    maxconns = request_form.getlist('backend_server_maxconns[]')

    servers = []
    for i in range(len(ips)):
        ip = ips[i].strip() if i < len(ips) else ''
        port = ports[i].strip() if i < len(ports) else ''
        if not ip or not port:
            continue
        servers.append({
            'name': names[i].strip() if i < len(names) and names[i].strip() else f"server{i + 1}",
            'ip': ip,
            'port': port,
            'maxconn': maxconns[i].strip() if i < len(maxconns) and maxconns[i].strip() else None,
        })
    return servers


def _resolve_certificate(form, frontend_name):
    use_ssl = 'ssl_checkbox' in form
    if not use_ssl:
        return None, None

    ssl_mode = form.get('ssl_mode', 'existing')
    domain_name = form.get('domain_name', '').strip()

    if ssl_mode == 'acme':
        cert_path = issue_certificate(domain_name)
        cert = Certificate.query.filter_by(pem_path=cert_path).first()
        if not cert and domain_name:
            cert = Certificate.query.filter_by(domain=domain_name).first()
        if not cert:
            cert = Certificate(
                domain=domain_name or frontend_name,
                pem_path=cert_path,
                issuer=_get_cert_issuer(cert_path),
                expires_at=_get_cert_enddate(cert_path),
            )
            db.session.add(cert)
        else:
            cert.pem_path = cert_path
            cert.issuer = _get_cert_issuer(cert_path)
            cert.expires_at = _get_cert_enddate(cert_path)
        db.session.commit()
        return cert.id, domain_name

    cert_id = form.get('ssl_cert_path_select')
    if cert_id and cert_id != '__custom__':
        cert = Certificate.query.filter_by(id=int(cert_id)).first()
        if not cert:
            raise ValueError("Selected certificate not found.")
        return cert.id, None

    manual_path = form.get('ssl_cert_path_manual', '').strip()
    if not manual_path:
        raise ValueError("SSL certificate path is required.")
    cert = Certificate.query.filter_by(pem_path=manual_path).first()
    if not cert and domain_name:
        cert = Certificate.query.filter_by(domain=domain_name).first()
    if not cert:
        cert = Certificate(
            domain=domain_name or frontend_name,
            pem_path=manual_path,
            issuer=_get_cert_issuer(manual_path),
            expires_at=_get_cert_enddate(manual_path),
        )
        db.session.add(cert)
    else:
        cert.pem_path = manual_path
        cert.issuer = _get_cert_issuer(manual_path)
        cert.expires_at = _get_cert_enddate(manual_path)
    db.session.commit()
    return cert.id, None


@main_bp.route('/', methods=['GET', 'POST'])
@requires_auth
def index():
    try:
        certificates = list_installed_certificates()
    except Exception:
        certificates = []

    edit_frontend_id = request.args.get('edit_frontend')
    edit_backend_id = request.args.get('edit_backend')
    form_mode = 'create'
    backend_only = False
    frontend = None
    backend = None

    if edit_frontend_id:
        frontend = Frontend.query.filter_by(id=edit_frontend_id).first()
        backend = frontend.backend if frontend else None
        form_mode = 'edit_frontend'
    elif edit_backend_id:
        backend = BackendPool.query.filter_by(id=edit_backend_id).first()
        form_mode = 'edit_backend'

    form_data = _build_form_data(frontend, backend)
    if backend_only:
        form_data['frontend_disabled'] = True

    message = None
    if request.method == 'POST':
        form_mode = request.form.get('form_mode', 'create')
        frontend_id = request.form.get('frontend_id') or None
        backend_id = request.form.get('backend_id') or None

        frontend_name = request.form.get('frontend_name', '').strip()
        frontend_ip = request.form.get('frontend_ip', '').strip()
        frontend_port = request.form.get('frontend_port', '').strip()
        lb_method = request.form.get('lb_method', '').strip()
        protocol = request.form.get('protocol', '').strip()

        backend_name = request.form.get('backend_name', '').strip()
        backend_servers = _build_backend_servers(request.form)

        health_check = 'health_check' in request.form
        health_check_link = request.form.get('health_check_link', '').strip()
        health_check_tcp = 'health_check2' in request.form
        sticky_session = 'sticky_session' in request.form
        sticky_session_type = request.form.get('sticky_session_type', '').strip()
        add_header = 'add_header' in request.form
        header_name = request.form.get('header_name', '').strip()
        header_value = request.form.get('header_value', '').strip()

        add_acl = 'add_acl' in request.form
        acl_name = request.form.get('acl', '').strip()
        acl_action = request.form.get('acl_action', '').strip()
        acl_backend_name = request.form.get('backend_name_acl', '').strip()

        use_ssl = 'ssl_checkbox' in request.form
        domain_name = request.form.get('domain_name', '').strip()
        https_redirect = 'ssl_redirect_checkbox' in request.form
        dos_enabled = 'add_dos' in request.form
        ban_duration = request.form.get('ban_duration', '').strip()
        limit_requests = request.form.get('limit_requests', '').strip()
        forward_for = 'forward_for_check' in request.form

        add_forbidden = 'add_acl_path' in request.form
        forbidden_name = request.form.get('forbidden_name', '').strip()
        allowed_ip = request.form.get('allowed_ip', '').strip()
        forbidden_path = request.form.get('forbidden_path', '').strip()

        sql_injection = 'sql_injection_check' in request.form
        xss_enabled = 'xss_check' in request.form
        remote_upload = 'remote_uploads_check' in request.form
        webshells_enabled = 'webshells_check' in request.form

        add_path_based = 'add_path_based' in request.form
        redirect_domain_name = request.form.get('redirect_domain_name', '').strip()
        root_redirect = request.form.get('root_redirect', '').strip()
        redirect_to = request.form.get('redirect_to', '').strip()

        try:
            if form_mode != 'edit_backend':
                if not frontend_name or not frontend_ip or not frontend_port or not protocol:
                    raise ValueError("Frontend name, IP, port, and protocol are required.")
                if is_frontend_exist(frontend_name, frontend_ip, frontend_port, ignore_id=frontend_id):
                    raise ValueError("Frontend or port already exists.")

            if not backend_name and form_mode != 'edit_backend':
                raise ValueError("Backend name is required.")
            if backend_name and is_backend_exist(backend_name, ignore_id=backend_id):
                raise ValueError("Backend already exists.")

            if backend_servers == [] and form_mode != 'edit_backend':
                raise ValueError("At least one backend server is required.")

            cert_id = None
            resolved_domain = None
            if use_ssl and form_mode != 'edit_backend':
                cert_id, resolved_domain = _resolve_certificate(request.form, frontend_name)

            if form_mode == 'create':
                backend = BackendPool(
                    name=backend_name,
                    mode=protocol,
                    enabled=True,
                    health_check_enabled=health_check,
                    health_check_path=health_check_link if health_check else None,
                    health_check_tcp=health_check_tcp,
                    sticky_enabled=sticky_session,
                    sticky_type=sticky_session_type if sticky_session else None,
                    add_header_enabled=add_header,
                    header_name=header_name if add_header else None,
                    header_value=header_value if add_header else None,
                )
                db.session.add(backend)
                db.session.flush()

                for server in backend_servers:
                    backend.servers.append(BackendServer(
                        backend_id=backend.id,
                        name=server['name'],
                        ip=server['ip'],
                        port=server['port'],
                        maxconn=server['maxconn'],
                        enabled=True,
                    ))

                frontend = Frontend(
                    name=frontend_name,
                    bind_ip=frontend_ip,
                    bind_port=str(frontend_port),
                    mode=protocol,
                    lb_method=lb_method,
                    default_backend_id=backend.id,
                    enabled=True,
                    use_ssl=use_ssl,
                    ssl_cert_id=cert_id,
                    domain_name=resolved_domain or domain_name,
                    https_redirect=https_redirect,
                    forward_for=forward_for,
                    dos_enabled=dos_enabled,
                    dos_limit=limit_requests if dos_enabled else None,
                    dos_ban_duration=ban_duration if dos_enabled else None,
                    sql_injection_enabled=sql_injection,
                    xss_enabled=xss_enabled,
                    remote_upload_enabled=remote_upload,
                    webshells_enabled=webshells_enabled,
                )
                db.session.add(frontend)
                db.session.flush()

            elif form_mode == 'edit_backend':
                backend = BackendPool.query.filter_by(id=backend_id).first()
                if not backend:
                    raise ValueError("Backend not found.")
                if backend_name:
                    backend.name = backend_name
                backend.mode = protocol or backend.mode
                backend.health_check_enabled = health_check
                backend.health_check_path = health_check_link if health_check else None
                backend.health_check_tcp = health_check_tcp
                backend.sticky_enabled = sticky_session
                backend.sticky_type = sticky_session_type if sticky_session else None
                backend.add_header_enabled = add_header
                backend.header_name = header_name if add_header else None
                backend.header_value = header_value if add_header else None
                backend.servers.clear()
                for server in backend_servers:
                    backend.servers.append(BackendServer(
                        backend_id=backend.id,
                        name=server['name'],
                        ip=server['ip'],
                        port=server['port'],
                        maxconn=server['maxconn'],
                        enabled=True,
                    ))

            else:
                frontend = Frontend.query.filter_by(id=frontend_id).first()
                if not frontend:
                    raise ValueError("Frontend not found.")
                backend = BackendPool.query.filter_by(id=backend_id).first()
                if not backend:
                    raise ValueError("Backend not found.")

                backend.name = backend_name
                backend.mode = protocol
                backend.health_check_enabled = health_check
                backend.health_check_path = health_check_link if health_check else None
                backend.health_check_tcp = health_check_tcp
                backend.sticky_enabled = sticky_session
                backend.sticky_type = sticky_session_type if sticky_session else None
                backend.add_header_enabled = add_header
                backend.header_name = header_name if add_header else None
                backend.header_value = header_value if add_header else None
                backend.servers.clear()
                for server in backend_servers:
                    backend.servers.append(BackendServer(
                        backend_id=backend.id,
                        name=server['name'],
                        ip=server['ip'],
                        port=server['port'],
                        maxconn=server['maxconn'],
                        enabled=True,
                    ))

                frontend.name = frontend_name
                frontend.bind_ip = frontend_ip
                frontend.bind_port = str(frontend_port)
                frontend.mode = protocol
                frontend.lb_method = lb_method
                frontend.default_backend_id = backend.id
                frontend.use_ssl = use_ssl
                frontend.ssl_cert_id = cert_id
                frontend.domain_name = resolved_domain or domain_name
                frontend.https_redirect = https_redirect
                frontend.forward_for = forward_for
                frontend.dos_enabled = dos_enabled
                frontend.dos_limit = limit_requests if dos_enabled else None
                frontend.dos_ban_duration = ban_duration if dos_enabled else None
                frontend.sql_injection_enabled = sql_injection
                frontend.xss_enabled = xss_enabled
                frontend.remote_upload_enabled = remote_upload
                frontend.webshells_enabled = webshells_enabled

                if frontend.acl:
                    db.session.delete(frontend.acl)
                if frontend.forbidden_path:
                    db.session.delete(frontend.forbidden_path)
                if frontend.redirect_rule:
                    db.session.delete(frontend.redirect_rule)

            if form_mode != 'edit_backend':
                acl_backend = None
                if add_acl and acl_backend_name:
                    acl_backend = BackendPool.query.filter_by(name=acl_backend_name).first()
                    if not acl_backend:
                        raise ValueError("ACL backend not found.")
                if add_acl:
                    frontend.acl = FrontendAcl(
                        frontend_id=frontend.id,
                        name=acl_name,
                        action=acl_action,
                        backend_id=acl_backend.id if acl_backend else None,
                    )
                if add_forbidden:
                    frontend.forbidden_path = FrontendForbiddenPath(
                        frontend_id=frontend.id,
                        acl_name=forbidden_name,
                        allowed_ip=allowed_ip,
                        path=forbidden_path,
                    )
                if add_path_based:
                    frontend.redirect_rule = FrontendRedirect(
                        frontend_id=frontend.id,
                        host_match=redirect_domain_name,
                        root_path=root_redirect,
                        redirect_to=redirect_to,
                    )

            db.session.commit()
            write_haproxy_config()
            return redirect(url_for('edit.manage_haproxy_sections'))
        except Exception as exc:
            message = str(exc)
            form_data = {
                'frontend_id': frontend_id or '',
                'backend_id': backend_id or '',
                'frontend_name': frontend_name,
                'frontend_ip': frontend_ip,
                'frontend_port': frontend_port,
                'lb_method': lb_method,
                'protocol': protocol,
                'use_ssl': use_ssl,
                'ssl_mode': request.form.get('ssl_mode', 'existing'),
                'ssl_cert_id': request.form.get('ssl_cert_path_select', ''),
                'domain_name': domain_name,
                'https_redirect': https_redirect,
                'forward_for': forward_for,
                'dos_enabled': dos_enabled,
                'limit_requests': limit_requests,
                'ban_duration': ban_duration,
                'sql_injection_enabled': sql_injection,
                'xss_enabled': xss_enabled,
                'remote_upload_enabled': remote_upload,
                'webshells_enabled': webshells_enabled,
                'add_acl': add_acl,
                'acl': acl_name,
                'acl_action': acl_action,
                'backend_name_acl': acl_backend_name,
                'add_acl_path': add_forbidden,
                'forbidden_name': forbidden_name,
                'allowed_ip': allowed_ip,
                'forbidden_path': forbidden_path,
                'add_path_based': add_path_based,
                'redirect_domain_name': redirect_domain_name,
                'root_redirect': root_redirect,
                'redirect_to': redirect_to,
                'backend_name': backend_name,
                'health_check': health_check,
                'health_check_link': health_check_link,
                'health_check_tcp': health_check_tcp,
                'sticky_session': sticky_session,
                'sticky_session_type': sticky_session_type,
                'add_header': add_header,
                'header_name': header_name,
                'header_value': header_value,
                'backend_servers': backend_servers,
            }

    return render_template(
        'index.html',
        certificates=certificates,
        form_data=form_data,
        form_mode=form_mode,
        backend_only=backend_only,
        message=message,
    )


@main_bp.route('/home')
@requires_auth
def home():
    frontend_count, backend_count, acl_count, layer7_count, layer4_count = count_frontends_and_backends()
    return render_template(
        'home.html',
        frontend_count=frontend_count,
        backend_count=backend_count,
        acl_count=acl_count,
        layer7_count=layer7_count,
        layer4_count=layer4_count,
    )
