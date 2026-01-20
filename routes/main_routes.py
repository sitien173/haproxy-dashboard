import json

from flask import Blueprint, redirect, render_template, request, url_for
from sqlalchemy import or_

from auth.auth_middleware import requires_auth
from db import db
from db.models import (
    BackendPool,
    BackendServer,
    BackendHeader,
    Certificate,
    Frontend,
    FrontendAcl,
    FrontendBackend,
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
        'frontend_ip': frontend.bind_ip if frontend else '0.0.0.0',
        'frontend_port': frontend.bind_port if frontend else '80',
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
        'acls': [],
        'forbidden_paths': [],
        'redirect_rules': [],
        'backend_blocks': [],
    }

    if frontend and frontend.acls:
        data['acls'] = [
            {
                'name': acl.name,
                'action': acl.action,
                'backend_name': acl.backend.name if acl.backend else '',
            }
            for acl in frontend.acls
        ]

    if frontend and frontend.forbidden_paths:
        data['forbidden_paths'] = [
            {
                'acl_name': forbidden.acl_name,
                'allowed_ip': forbidden.allowed_ip,
                'path': forbidden.path,
            }
            for forbidden in frontend.forbidden_paths
        ]

    if frontend and frontend.redirect_rules:
        data['redirect_rules'] = [
            {
                'host_match': redirect.host_match,
                'root_path': redirect.root_path,
                'redirect_to': redirect.redirect_to,
            }
            for redirect in frontend.redirect_rules
        ]

    if frontend and frontend.backend_links:
        for link in frontend.backend_links:
            backend = link.backend
            if not backend:
                continue
            data['backend_blocks'].append({
                'id': backend.id,
                'name': backend.name,
                'mode': backend.mode,
                'is_default': link.is_default,
                'health_check': bool(backend.health_check_enabled),
                'health_check_link': backend.health_check_path or '',
                'health_check_tcp': bool(backend.health_check_tcp),
                'sticky_session': bool(backend.sticky_enabled),
                'sticky_session_type': backend.sticky_type or 'cookie',
                'headers': [
                    {
                        'name': header.name,
                        'value': header.value or '',
                        'enabled': bool(header.enabled),
                    }
                    for header in backend.headers
                ],
                'servers': [
                    {
                        'name': server.name,
                        'ip': server.ip,
                        'port': server.port,
                        'maxconn': server.maxconn or '',
                    }
                    for server in backend.servers
                ],
            })
    elif backend:
        data['backend_blocks'] = [{
            'id': backend.id,
            'name': backend.name,
            'mode': backend.mode,
            'is_default': True,
            'health_check': bool(backend.health_check_enabled),
            'health_check_link': backend.health_check_path or '',
            'health_check_tcp': bool(backend.health_check_tcp),
            'sticky_session': bool(backend.sticky_enabled),
            'sticky_session_type': backend.sticky_type or 'cookie',
            'headers': [
                {
                    'name': header.name,
                    'value': header.value or '',
                    'enabled': bool(header.enabled),
                }
                for header in backend.headers
            ],
            'servers': [
                {
                    'name': server.name,
                    'ip': server.ip,
                    'port': server.port,
                    'maxconn': server.maxconn or '',
                }
                for server in backend.servers
            ],
        }]
    return data


def _build_backend_servers(request_form):
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


def _build_backend_blocks(request_form):
    payload = request_form.get('backend_blocks_payload', '').strip()
    if payload:
        try:
            blocks = json.loads(payload)
            normalized = []
            for block in blocks:
                name = (block.get('name') or '').strip()
                if not name:
                    continue
                servers = []
                for index, server in enumerate(block.get('servers') or []):
                    ip = (server.get('ip') or '').strip()
                    port = (server.get('port') or '').strip()
                    if not ip or not port:
                        continue
                    server_name = (server.get('name') or '').strip() or f"server{index + 1}"
                    maxconn = (server.get('maxconn') or '').strip() or None
                    servers.append({
                        'name': server_name,
                        'ip': ip,
                        'port': port,
                        'maxconn': maxconn,
                    })
                headers = []
                for header in block.get('headers') or []:
                    name = (header.get('name') or '').strip()
                    value = (header.get('value') or '').strip()
                    if not name:
                        continue
                    headers.append({
                        'name': name,
                        'value': value,
                        'enabled': bool(header.get('enabled', True)),
                    })
                normalized.append({
                    'name': name,
                    'mode': (block.get('mode') or 'http').strip(),
                    'is_default': bool(block.get('is_default')),
                    'health_check': bool(block.get('health_check')),
                    'health_check_link': (block.get('health_check_link') or '').strip(),
                    'health_check_tcp': bool(block.get('health_check_tcp')),
                    'sticky_session': bool(block.get('sticky_session')),
                    'sticky_session_type': (block.get('sticky_session_type') or 'cookie').strip(),
                    'headers': headers,
                    'servers': servers,
                })
            return normalized
        except json.JSONDecodeError:
            pass

    backend_name = request_form.get('backend_name', '').strip()
    servers = _build_backend_servers(request_form)
    if not backend_name:
        return []
    return [{
        'name': backend_name,
        'mode': request_form.get('protocol', 'http').strip() or 'http',
        'is_default': True,
        'health_check': 'health_check' in request_form,
        'health_check_link': request_form.get('health_check_link', '').strip(),
        'health_check_tcp': 'health_check2' in request_form,
        'sticky_session': 'sticky_session' in request_form,
        'sticky_session_type': request_form.get('sticky_session_type', '').strip() or 'cookie',
        'headers': [],
        'servers': servers,
    }]


def _build_acl_entries(request_form):
    payload = request_form.get('acl_payload', '').strip()
    if payload:
        try:
            entries = json.loads(payload)
            normalized = []
            for entry in entries:
                name = (entry.get('name') or '').strip()
                action = (entry.get('action') or '').strip()
                backend_name = (entry.get('backend_name') or '').strip()
                if not name or not action:
                    continue
                normalized.append({
                    'name': name,
                    'action': action,
                    'backend_name': backend_name,
                })
            return normalized
        except json.JSONDecodeError:
            pass
    return []


def _build_forbidden_entries(request_form):
    payload = request_form.get('forbidden_payload', '').strip()
    if payload:
        try:
            entries = json.loads(payload)
            normalized = []
            for entry in entries:
                acl_name = (entry.get('acl_name') or '').strip()
                allowed_ip = (entry.get('allowed_ip') or '').strip()
                path = (entry.get('path') or '').strip()
                if not acl_name or not allowed_ip or not path:
                    continue
                normalized.append({
                    'acl_name': acl_name,
                    'allowed_ip': allowed_ip,
                    'path': path,
                })
            return normalized
        except json.JSONDecodeError:
            pass
    return []


def _build_redirect_entries(request_form):
    payload = request_form.get('redirect_payload', '').strip()
    if payload:
        try:
            entries = json.loads(payload)
            normalized = []
            for entry in entries:
                host_match = (entry.get('host_match') or '').strip()
                root_path = (entry.get('root_path') or '').strip()
                redirect_to = (entry.get('redirect_to') or '').strip()
                if not host_match or not root_path or not redirect_to:
                    continue
                normalized.append({
                    'host_match': host_match,
                    'root_path': root_path,
                    'redirect_to': redirect_to,
                })
            return normalized
        except json.JSONDecodeError:
            pass
    return []


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
    backend_records = []

    if edit_frontend_id:
        frontend = Frontend.query.filter_by(id=edit_frontend_id).first()
        backend = frontend.backend if frontend else None
        form_mode = 'edit_frontend'
    elif edit_backend_id:
        backend = BackendPool.query.filter_by(id=edit_backend_id).first()

    form_data = _build_form_data(frontend, backend)
    if backend_only:
        form_data['frontend_disabled'] = True

    message = None
    if request.method == 'POST':
        form_mode = request.form.get('form_mode', 'create')
        frontend_id = request.form.get('frontend_id') or None
        backend_id = request.form.get('backend_id') or None

        frontend_name = request.form.get('frontend_name', '').strip()
        lb_method = request.form.get('lb_method', '').strip()
        protocol = request.form.get('protocol', '').strip()
        frontend_ip = request.form.get('frontend_ip', '').strip()
        frontend_port = request.form.get('frontend_port', '').strip()

        domain_name = request.form.get('domain_name', '').strip()
        use_ssl = 'ssl_checkbox' in request.form
        https_redirect = 'ssl_redirect_checkbox' in request.form
        dos_enabled = 'add_dos' in request.form
        ban_duration = request.form.get('ban_duration', '').strip()
        limit_requests = request.form.get('limit_requests', '').strip()
        forward_for = 'forward_for_check' in request.form

        sql_injection = 'sql_injection_check' in request.form
        xss_enabled = 'xss_check' in request.form
        remote_upload = 'remote_uploads_check' in request.form
        webshells_enabled = 'webshells_check' in request.form

        backend_blocks = _build_backend_blocks(request.form)
        acl_entries = _build_acl_entries(request.form)
        forbidden_entries = _build_forbidden_entries(request.form)
        redirect_entries = _build_redirect_entries(request.form)
        if domain_name:
            frontend_ip = '0.0.0.0'
            frontend_port = '443' if use_ssl else '80'
        else:
            frontend_ip = frontend_ip or '0.0.0.0'

        try:
            if form_mode != 'edit_backend':
                if not frontend_name or not protocol:
                    raise ValueError("Frontend name and protocol are required.")
                if use_ssl and not domain_name:
                    raise ValueError("Domain name is required when using SSL.")
                if not domain_name and not frontend_port:
                    raise ValueError("Bind IP and port are required when domain is empty.")
                if is_frontend_exist(frontend_name, domain_name, frontend_ip, frontend_port, ignore_id=frontend_id):
                    raise ValueError("Frontend name, domain, or bind IP/port already exists.")
                if protocol != 'http':
                    raise ValueError("Domain routing requires HTTP mode.")
                if not domain_name and https_redirect:
                    raise ValueError("HTTPS redirect requires a domain name.")
                if not domain_name:
                    if frontend_port == '80':
                        conflict = Frontend.query.filter(
                            Frontend.enabled.is_(True),
                            Frontend.domain_name.isnot(None),
                            Frontend.id != frontend_id,
                            or_(Frontend.use_ssl.is_(False), Frontend.https_redirect.is_(True)),
                        ).first()
                        if conflict:
                            raise ValueError("Port 80 is already reserved by domain-based listeners.")
                    if frontend_port == '443':
                        conflict = Frontend.query.filter(
                            Frontend.enabled.is_(True),
                            Frontend.domain_name.isnot(None),
                            Frontend.use_ssl.is_(True),
                            Frontend.id != frontend_id,
                        ).first()
                        if conflict:
                            raise ValueError("Port 443 is already reserved by SSL domain listeners.")
                else:
                    if not use_ssl:
                        conflict = Frontend.query.filter(
                            Frontend.enabled.is_(True),
                            Frontend.domain_name.is_(None),
                            Frontend.bind_port == '80',
                            Frontend.id != frontend_id,
                        ).first()
                        if conflict:
                            raise ValueError("Port 80 is already reserved by a bind-only listener.")
                    if use_ssl:
                        conflict = Frontend.query.filter(
                            Frontend.enabled.is_(True),
                            Frontend.domain_name.is_(None),
                            Frontend.bind_port == '443',
                            Frontend.id != frontend_id,
                        ).first()
                        if conflict:
                            raise ValueError("Port 443 is already reserved by a bind-only listener.")

            if form_mode != 'edit_backend':
                if not backend_blocks:
                    raise ValueError("At least one backend block is required.")
                block_names = [block['name'] for block in backend_blocks]
                if len(block_names) != len(set(block_names)):
                    raise ValueError("Backend names must be unique.")
                for block in backend_blocks:
                    if not block['servers']:
                        raise ValueError(f"Backend '{block['name']}' must have at least one server.")
            if protocol != 'http':
                raise ValueError("Domain routing requires HTTP mode.")

            cert_id = None
            resolved_domain = None
            if use_ssl and form_mode != 'edit_backend':
                cert_id, resolved_domain = _resolve_certificate(request.form, frontend_name)

            if form_mode == 'create':
                existing_backend = {
                    backend.name: backend.id
                    for backend in BackendPool.query.filter(BackendPool.name.in_([block['name'] for block in backend_blocks])).all()
                }
                if existing_backend:
                    raise ValueError(f"Backend already exists: {', '.join(existing_backend.keys())}.")

                default_index = next((idx for idx, block in enumerate(backend_blocks) if block.get('is_default')), 0)
                backend_records = []
                for index, block in enumerate(backend_blocks):
                    backend = BackendPool(
                        name=block['name'],
                        mode=block['mode'] or protocol,
                        enabled=True,
                        health_check_enabled=block['health_check'],
                        health_check_path=block['health_check_link'] if block['health_check'] else None,
                        health_check_tcp=block['health_check_tcp'],
                        sticky_enabled=block['sticky_session'],
                        sticky_type=block['sticky_session_type'] if block['sticky_session'] else None,
                    )
                    db.session.add(backend)
                    db.session.flush()
                    backend_records.append(backend)
                    for header in block.get('headers', []):
                        backend.headers.append(BackendHeader(
                            backend_id=backend.id,
                            name=header['name'],
                            value=header.get('value') or None,
                            enabled=bool(header.get('enabled', True)),
                        ))
                    for server in block['servers']:
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
                    default_backend_id=backend_records[default_index].id if backend_records else None,
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
                for index, backend in enumerate(backend_records):
                    db.session.add(FrontendBackend(
                        frontend_id=frontend.id,
                        backend_id=backend.id,
                        is_default=index == default_index,
                    ))

            elif form_mode == 'edit_backend':
                raise ValueError("Backend-only editing is no longer supported.")

            else:
                frontend = Frontend.query.filter_by(id=frontend_id).first()
                if not frontend:
                    raise ValueError("Frontend not found.")
                existing_backend_names = {
                    link.backend.name for link in frontend.backend_links if link.backend
                }
                other_backends = BackendPool.query.filter(
                    BackendPool.name.in_([block['name'] for block in backend_blocks])
                ).all()
                conflicts = [backend.name for backend in other_backends if backend.name not in existing_backend_names]
                if conflicts:
                    raise ValueError(f"Backend already exists: {', '.join(conflicts)}.")

                for acl in frontend.acls:
                    db.session.delete(acl)
                for forbidden in frontend.forbidden_paths:
                    db.session.delete(forbidden)
                for redirect_rule in frontend.redirect_rules:
                    db.session.delete(redirect_rule)

                existing_backend_ids = [link.backend_id for link in frontend.backend_links]
                for link in frontend.backend_links:
                    db.session.delete(link)

                for backend_id in existing_backend_ids:
                    in_use = FrontendBackend.query.filter(
                        FrontendBackend.backend_id == backend_id,
                        FrontendBackend.frontend_id != frontend.id,
                    ).first()
                    in_acl = FrontendAcl.query.filter_by(backend_id=backend_id).first()
                    if not in_use and not in_acl:
                        backend_record = BackendPool.query.filter_by(id=backend_id).first()
                        if backend_record:
                            db.session.delete(backend_record)

                default_index = next((idx for idx, block in enumerate(backend_blocks) if block.get('is_default')), 0)
                backend_records = []
                for index, block in enumerate(backend_blocks):
                    backend = BackendPool(
                        name=block['name'],
                        mode=block['mode'] or protocol,
                        enabled=True,
                        health_check_enabled=block['health_check'],
                        health_check_path=block['health_check_link'] if block['health_check'] else None,
                        health_check_tcp=block['health_check_tcp'],
                        sticky_enabled=block['sticky_session'],
                        sticky_type=block['sticky_session_type'] if block['sticky_session'] else None,
                    )
                    db.session.add(backend)
                    db.session.flush()
                    backend_records.append(backend)
                    for header in block.get('headers', []):
                        backend.headers.append(BackendHeader(
                            backend_id=backend.id,
                            name=header['name'],
                            value=header.get('value') or None,
                            enabled=bool(header.get('enabled', True)),
                        ))
                    for server in block['servers']:
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
                frontend.default_backend_id = backend_records[default_index].id if backend_records else None
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

                for index, backend in enumerate(backend_records):
                    db.session.add(FrontendBackend(
                        frontend_id=frontend.id,
                        backend_id=backend.id,
                        is_default=index == default_index,
                    ))

            if form_mode != 'edit_backend':
                backend_name_map = {backend.name: backend.id for backend in backend_records}
                for entry in acl_entries:
                    backend_id = backend_name_map.get(entry['backend_name'])
                    if entry['backend_name'] and not backend_id:
                        raise ValueError(f"ACL backend not found: {entry['backend_name']}.")
                    db.session.add(FrontendAcl(
                        frontend_id=frontend.id,
                        name=entry['name'],
                        action=entry['action'],
                        backend_id=backend_id,
                    ))
                for entry in forbidden_entries:
                    db.session.add(FrontendForbiddenPath(
                        frontend_id=frontend.id,
                        acl_name=entry['acl_name'],
                        allowed_ip=entry['allowed_ip'],
                        path=entry['path'],
                    ))
                for entry in redirect_entries:
                    db.session.add(FrontendRedirect(
                        frontend_id=frontend.id,
                        host_match=entry['host_match'],
                        root_path=entry['root_path'],
                        redirect_to=entry['redirect_to'],
                    ))

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
                'acls': acl_entries,
                'forbidden_paths': forbidden_entries,
                'redirect_rules': redirect_entries,
                'backend_blocks': backend_blocks,
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
