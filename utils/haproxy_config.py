import re
from datetime import datetime

from db import db
from db.models import BackendBlock, Certificate, ConfigBase, FrontendBlock
from utils.acme_utils import issue_certificate, _get_cert_enddate, _get_cert_issuer

DEFAULT_BASE_CONFIG = """global
    log /dev/log local0
    log /dev/log local1 notice
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client 50s
    timeout server 50s

listen stats
    bind 127.0.0.1:8080
    mode http
    stats enable
    stats uri /
    stats refresh 10s
    stats show-legends
"""


def ensure_base_config():
    base = ConfigBase.query.first()
    if not base:
        base = ConfigBase(content=DEFAULT_BASE_CONFIG)
        db.session.add(base)
        db.session.commit()
    return base


def render_haproxy_config():
    base = ensure_base_config().content.rstrip()
    parts = [base, ""]

    frontends = FrontendBlock.query.order_by(FrontendBlock.created_at.asc()).all()
    backends = BackendBlock.query.order_by(BackendBlock.created_at.asc()).all()

    for frontend in frontends:
        parts.append(frontend.content.rstrip())
        parts.append("")
    for backend in backends:
        parts.append(backend.content.rstrip())
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def write_haproxy_config():
    config_content = render_haproxy_config()
    with open('/etc/haproxy/haproxy.cfg', 'w') as haproxy_cfg:
        haproxy_cfg.write(config_content)


def is_frontend_exist(frontend_name, frontend_ip, frontend_port):
    existing = FrontendBlock.query.filter(
        (FrontendBlock.name == frontend_name) |
        ((FrontendBlock.bind_ip == frontend_ip) & (FrontendBlock.bind_port == str(frontend_port)))
    ).first()
    return existing is not None


def is_backend_exist(backend_name):
    return BackendBlock.query.filter_by(name=backend_name).first() is not None


def _build_frontend_block(
    frontend_name, frontend_ip, frontend_port, lb_method, protocol, backend_name, use_ssl, ssl_cert_path,
    https_redirect, is_dos, ban_duration, limit_requests, forward_for, is_acl, acl_name, acl_action,
    acl_backend_name, is_forbidden_path, forbidden_name, allowed_ip, forbidden_path, sql_injection_check,
    is_xss, is_remote_upload, add_path_based, redirect_domain_name, root_redirect, redirect_to, is_webshells
):
    lines = [f"frontend {frontend_name}"]
    bind_line = f"    bind {frontend_ip}:{frontend_port}"
    if use_ssl:
        bind_line += f" ssl crt {ssl_cert_path}"
    lines.append(bind_line)
    if use_ssl and https_redirect:
        lines.append("    redirect scheme https code 301 if !{ ssl_fc }")
    if forward_for:
        lines.append("    option forwardfor")
    lines.append(f"    mode {protocol}")
    lines.append(f"    balance {lb_method}")
    if is_dos:
        lines.append(f"    stick-table type ip size 1m expire {ban_duration} store http_req_rate(1m)")
        lines.append("    http-request track-sc0 src")
        lines.append(f"    acl abuse sc_http_req_rate(0) gt {limit_requests}")
        lines.append("    http-request silent-drop if abuse")
    if sql_injection_check:
        lines.append("    acl is_sql_injection urlp_reg -i (union|select|insert|update|delete|drop|@@|1=1|`1)")
        lines.append("    acl is_long_uri path_len gt 400")
        lines.append("    acl semicolon_path path_reg -i ^.*;.*")
        lines.append("    acl is_sql_injection2 urlp_reg -i (;|substring|extract|union\\s+all|order\\s+by)\\s+(\\d+|--\\+)")
        lines.append("    http-request deny if is_sql_injection or is_long_uri or semicolon_path or is_sql_injection2")
    if is_xss:
        lines.append("    acl is_xss_attack urlp_reg -i (<|>|script|alert|onerror|onload|javascript)")
        lines.append("    acl is_xss_attack_2 urlp_reg -i (<\\s*script\\s*|javascript:|<\\s*img\\s*src\\s*=|<\\s*a\\s*href\\s*=|<\\s*iframe\\s*src\\s*=|\\bon\\w+\\s*=|<\\s*input\\s*[^>]*\\s*value\\s*=|<\\s*form\\s*action\\s*=|<\\s*svg\\s*on\\w+\\s*=)")
        lines.append("    acl is_xss_attack_hdr hdr_reg(Cookie|Referer|User-Agent) -i (<|>|script|alert|onerror|onload|javascript)")
        lines.append("    acl is_xss_cookie hdr_beg(Cookie) -i \"<script\" \"javascript:\" \"on\" \"alert(\" \"iframe\" \"onload\" \"onerror\" \"onclick\" \"onmouseover\"")
        lines.append("    http-request deny if is_xss_attack or is_xss_attack_hdr or is_xss_attack_2 or is_xss_cookie")
    if is_remote_upload:
        lines.append("    acl is_put_request method PUT")
        lines.append("    http-request deny if is_put_request")
    if is_acl:
        lines.append(f"    acl {acl_name} {acl_action}")
        lines.append(f"    use_backend {acl_backend_name} if {acl_name}")
    if is_forbidden_path:
        lines.append(f"    acl {forbidden_name} src {allowed_ip}")
        lines.append(f"    http-request deny if !{forbidden_name} {{ path_beg {forbidden_path} }}")
    if add_path_based:
        lines.append(f"    acl is_test_com hdr(host) -i {redirect_domain_name}")
        lines.append(f"    acl is_root path {root_redirect}")
        lines.append(f"    http-request redirect location {redirect_to} if is_test_com or is_root")
    if is_webshells:
        lines.append("    option http-buffer-request")
        lines.append("    acl is_webshell urlp_reg(payload,eval|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)")
        lines.append("    acl is_potential_webshell urlp_reg(payload,php|jsp|asp|aspx)")
        lines.append("    acl blocked_webshell path_reg -i /(cmd|shell|backdoor|webshell|phpspy|c99|kacak|b374k|log4j|log4shell|wsos|madspot|malicious|evil).*\\.php.*")
        lines.append("    acl is_suspicious_post hdr(Content-Type) -i application/x-www-form-urlencoded multipart/form-data")
        lines.append("    http-request deny if blocked_webshell or is_webshell or is_potential_webshell or is_suspicious_post")

    lines.append(f"    default_backend {backend_name}")
    return "\n".join(lines) + "\n"


def _build_backend_block(
    backend_name, backend_servers, protocol, health_check, health_check_tcp, health_check_link,
    sticky_session, sticky_session_type, add_header, header_name, header_value
):
    lines = [f"backend {backend_name}"]

    if sticky_session and sticky_session_type == 'cookie':
        lines.append("    cookie SERVERID insert indirect nocache")
    if sticky_session and sticky_session_type == 'stick-table':
        lines.append("    stick-table type ip size 200k expire 5m")
        lines.append("    stick on src")
    if add_header:
        lines.append(f"    http-request set-header {header_name} \"{header_value}\"")
    if protocol == 'http' and health_check:
        lines.append(f"    option httpchk GET {health_check_link}")
        lines.append("    http-check disable-on-404")
        lines.append("    http-check expect string OK")
    if protocol == 'tcp' and health_check_tcp:
        lines.append("    option tcp-check")
        lines.append("    tcp-check send PING\\r\\n")
        lines.append("    tcp-check send QUIT\\r\\n")

    for i, backend_server in enumerate(backend_servers, 1):
        if len(backend_server) >= 3:
            backend_server_name = backend_server[0] or f"server{i}"
            backend_server_ip = backend_server[1]
            backend_server_port = backend_server[2]
            backend_server_maxconn = backend_server[3] if len(backend_server) > 3 else None

            line = f"    server {backend_server_name} {backend_server_ip}:{backend_server_port} check"
            if sticky_session and sticky_session_type == 'cookie':
                line += f" cookie {backend_server_name}"
            if backend_server_maxconn:
                line += f" maxconn {backend_server_maxconn}"
            lines.append(line)

    return "\n".join(lines) + "\n"


def update_haproxy_config(
    frontend_name, frontend_ip, frontend_port, lb_method, protocol, backend_name, backend_servers, health_check,
    health_check_tcp, health_check_link, sticky_session, add_header, header_name, header_value, sticky_session_type,
    is_acl, acl_name, acl_action, acl_backend_name, use_ssl, ssl_cert_path, auto_issue_tls, domain_name,
    https_redirect, is_dos, ban_duration, limit_requests, forward_for, is_forbidden_path, forbidden_name, allowed_ip,
    forbidden_path, sql_injection_check, is_xss, is_remote_upload, add_path_based, redirect_domain_name, root_redirect,
    redirect_to, is_webshells
):
    if is_backend_exist(backend_name):
        return f"Backend {backend_name} already exists. Cannot add duplicate."
    if is_frontend_exist(frontend_name, frontend_ip, frontend_port):
        return "Frontend or Port already exists. Cannot add duplicate."

    if is_acl and acl_backend_name and acl_backend_name != backend_name:
        if not is_backend_exist(acl_backend_name):
            return f"ACL backend {acl_backend_name} not found."

    if auto_issue_tls:
        use_ssl = True

    if use_ssl and auto_issue_tls:
        try:
            ssl_cert_path = issue_certificate(domain_name)
        except Exception as exc:
            return f"Failed to issue certificate for {domain_name}: {exc}"

    if use_ssl and not ssl_cert_path:
        return "SSL certificate path is required when SSL is enabled."

    if use_ssl:
        issuer = _get_cert_issuer(ssl_cert_path)
        expires_at = _get_cert_enddate(ssl_cert_path)
        cert = Certificate.query.filter_by(pem_path=ssl_cert_path).first()
        if not cert:
            cert = Certificate(
                domain=domain_name or frontend_name,
                pem_path=ssl_cert_path,
                issuer=issuer,
                expires_at=expires_at,
                last_renewed_at=datetime.utcnow(),
            )
            db.session.add(cert)
        else:
            cert.domain = domain_name or cert.domain
            cert.issuer = issuer
            cert.expires_at = expires_at
            cert.last_renewed_at = datetime.utcnow()

    frontend_block = _build_frontend_block(
        frontend_name, frontend_ip, frontend_port, lb_method, protocol, backend_name, use_ssl, ssl_cert_path,
        https_redirect, is_dos, ban_duration, limit_requests, forward_for, is_acl, acl_name, acl_action,
        acl_backend_name, is_forbidden_path, forbidden_name, allowed_ip, forbidden_path, sql_injection_check,
        is_xss, is_remote_upload, add_path_based, redirect_domain_name, root_redirect, redirect_to, is_webshells
    )

    backend_block = _build_backend_block(
        backend_name, backend_servers, protocol, health_check, health_check_tcp, health_check_link,
        sticky_session, sticky_session_type, add_header, header_name, header_value
    )

    backend = BackendBlock(name=backend_name, content=backend_block)
    frontend = FrontendBlock(
        name=frontend_name,
        bind_ip=frontend_ip,
        bind_port=str(frontend_port),
        mode=protocol,
        acl_enabled=bool(is_acl),
        ssl_cert_path=ssl_cert_path if use_ssl else None,
        content=frontend_block,
    )

    db.session.add(backend)
    db.session.add(frontend)
    db.session.commit()

    write_haproxy_config()
    return "Frontend and Backend added successfully."


def count_frontends_and_backends():
    frontend_count = FrontendBlock.query.count()
    backend_count = BackendBlock.query.count()
    acl_count = FrontendBlock.query.filter_by(acl_enabled=True).count()
    layer7_count = FrontendBlock.query.filter_by(mode='http').count()
    layer4_count = FrontendBlock.query.filter_by(mode='tcp').count()
    return frontend_count, backend_count, acl_count, layer7_count, layer4_count


def _extract_bind(content):
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('bind '):
            _, bind_info = stripped.split(None, 1)
            match = re.match(r'([^:]+):(\d+)', bind_info)
            if match:
                return match.group(1).strip(), match.group(2).strip()
    return None, None


def _extract_mode(content):
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('mode '):
            _, mode = stripped.split(None, 1)
            return mode.strip()
    return None


def _detect_acl(content):
    return any(line.strip().startswith('acl ') for line in content.splitlines())


def parse_haproxy_sections():
    sections = []
    for frontend in FrontendBlock.query.order_by(FrontendBlock.created_at.asc()).all():
        sections.append({
            'type': 'frontend',
            'name': frontend.name,
            'content': frontend.content,
        })
    for backend in BackendBlock.query.order_by(BackendBlock.created_at.asc()).all():
        sections.append({
            'type': 'backend',
            'name': backend.name,
            'content': backend.content,
        })
    return sections


def replace_haproxy_section(section_type, section_name, new_content):
    content = new_content.rstrip() + '\n'
    first_line = content.splitlines()[0].strip()
    if not first_line.startswith(f"{section_type} "):
        return False, f"Section must start with '{section_type} <name>'."

    new_name = first_line.split(None, 1)[1].strip()
    if section_type == 'frontend':
        record = FrontendBlock.query.filter_by(name=section_name).first()
        if not record:
            return False, f"Frontend '{section_name}' not found."
        if new_name != section_name and FrontendBlock.query.filter_by(name=new_name).first():
            return False, f"Frontend '{new_name}' already exists."
        record.name = new_name
        record.content = content
        bind_ip, bind_port = _extract_bind(content)
        if bind_ip and bind_port:
            record.bind_ip = bind_ip
            record.bind_port = bind_port
        mode = _extract_mode(content)
        if mode:
            record.mode = mode
        record.acl_enabled = _detect_acl(content)
    else:
        record = BackendBlock.query.filter_by(name=section_name).first()
        if not record:
            return False, f"Backend '{section_name}' not found."
        if new_name != section_name and BackendBlock.query.filter_by(name=new_name).first():
            return False, f"Backend '{new_name}' already exists."
        record.name = new_name
        record.content = content

    db.session.commit()
    write_haproxy_config()
    return True, f"{section_type.title()} '{new_name}' updated successfully."
