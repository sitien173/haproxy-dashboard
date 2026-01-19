from db import db
from db.models import (
    BackendPool,
    BackendServer,
    ConfigBase,
    Frontend,
    FrontendAcl,
    FrontendForbiddenPath,
    FrontendRedirect,
)

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

    backend_map = {
        backend.id: backend
        for backend in BackendPool.query.order_by(BackendPool.created_at.asc()).all()
        if backend.enabled
    }

    for frontend in Frontend.query.order_by(Frontend.created_at.asc()).all():
        if not frontend.enabled:
            continue
        backend = backend_map.get(frontend.default_backend_id) if frontend.default_backend_id else None
        if frontend.default_backend_id and not backend:
            continue
        parts.append(_build_frontend_block(frontend, backend))
        parts.append("")

    for backend in backend_map.values():
        parts.append(_build_backend_block(backend))
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def write_haproxy_config():
    config_content = render_haproxy_config()
    with open('/etc/haproxy/haproxy.cfg', 'w') as haproxy_cfg:
        haproxy_cfg.write(config_content)


def is_frontend_exist(frontend_name, frontend_ip, frontend_port, ignore_id=None):
    query = Frontend.query.filter(
        (Frontend.name == frontend_name) |
        ((Frontend.bind_ip == frontend_ip) & (Frontend.bind_port == str(frontend_port)) & (Frontend.enabled.is_(True)))
    )
    if ignore_id:
        query = query.filter(Frontend.id != ignore_id)
    return query.first() is not None


def is_backend_exist(backend_name, ignore_id=None):
    query = BackendPool.query.filter_by(name=backend_name)
    if ignore_id:
        query = query.filter(BackendPool.id != ignore_id)
    return query.first() is not None


def count_frontends_and_backends():
    frontend_count = Frontend.query.count()
    backend_count = BackendPool.query.count()
    acl_count = FrontendAcl.query.count()
    layer7_count = Frontend.query.filter_by(mode='http').count()
    layer4_count = Frontend.query.filter_by(mode='tcp').count()
    return frontend_count, backend_count, acl_count, layer7_count, layer4_count
def _build_frontend_block(frontend, backend):
    lines = [f"frontend {frontend.name}"]
    bind_line = f"    bind {frontend.bind_ip}:{frontend.bind_port}"
    if frontend.use_ssl and frontend.certificate:
        bind_line += f" ssl crt {frontend.certificate.pem_path}"
    lines.append(bind_line)
    if frontend.use_ssl and frontend.https_redirect:
        lines.append("    redirect scheme https code 301 if !{ ssl_fc }")
    if frontend.forward_for:
        lines.append("    option forwardfor")
    lines.append(f"    mode {frontend.mode}")
    lines.append(f"    balance {frontend.lb_method}")
    if frontend.dos_enabled:
        lines.append(f"    stick-table type ip size 1m expire {frontend.dos_ban_duration} store http_req_rate(1m)")
        lines.append("    http-request track-sc0 src")
        lines.append(f"    acl abuse sc_http_req_rate(0) gt {frontend.dos_limit}")
        lines.append("    http-request silent-drop if abuse")
    if frontend.sql_injection_enabled:
        lines.append("    acl is_sql_injection urlp_reg -i (union|select|insert|update|delete|drop|@@|1=1|`1)")
        lines.append("    acl is_long_uri path_len gt 400")
        lines.append("    acl semicolon_path path_reg -i ^.*;.*")
        lines.append("    acl is_sql_injection2 urlp_reg -i (;|substring|extract|union\\s+all|order\\s+by)\\s+(\\d+|--\\+)")
        lines.append("    http-request deny if is_sql_injection or is_long_uri or semicolon_path or is_sql_injection2")
    if frontend.xss_enabled:
        lines.append("    acl is_xss_attack urlp_reg -i (<|>|script|alert|onerror|onload|javascript)")
        lines.append("    acl is_xss_attack_2 urlp_reg -i (<\\s*script\\s*|javascript:|<\\s*img\\s*src\\s*=|<\\s*a\\s*href\\s*=|<\\s*iframe\\s*src\\s*=|\\bon\\w+\\s*=|<\\s*input\\s*[^>]*\\s*value\\s*=|<\\s*form\\s*action\\s*=|<\\s*svg\\s*on\\w+\\s*=)")
        lines.append("    acl is_xss_attack_hdr hdr_reg(Cookie|Referer|User-Agent) -i (<|>|script|alert|onerror|onload|javascript)")
        lines.append("    acl is_xss_cookie hdr_beg(Cookie) -i \"<script\" \"javascript:\" \"on\" \"alert(\" \"iframe\" \"onload\" \"onerror\" \"onclick\" \"onmouseover\"")
        lines.append("    http-request deny if is_xss_attack or is_xss_attack_hdr or is_xss_attack_2 or is_xss_cookie")
    if frontend.remote_upload_enabled:
        lines.append("    acl is_put_request method PUT")
        lines.append("    http-request deny if is_put_request")
    acl = frontend.acl
    if acl:
        lines.append(f"    acl {acl.name} {acl.action}")
        if acl.backend_id and acl.backend:
            lines.append(f"    use_backend {acl.backend.name} if {acl.name}")
    forbidden = frontend.forbidden_path
    if forbidden:
        lines.append(f"    acl {forbidden.acl_name} src {forbidden.allowed_ip}")
        lines.append(f"    http-request deny if !{forbidden.acl_name} {{ path_beg {forbidden.path} }}")
    redirect_rule = frontend.redirect_rule
    if redirect_rule:
        lines.append(f"    acl is_redirect_host hdr(host) -i {redirect_rule.host_match}")
        lines.append(f"    acl is_root path {redirect_rule.root_path}")
        lines.append(f"    http-request redirect location {redirect_rule.redirect_to} if is_redirect_host or is_root")
    if frontend.webshells_enabled:
        lines.append("    option http-buffer-request")
        lines.append("    acl is_webshell urlp_reg(payload,eval|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)")
        lines.append("    acl is_potential_webshell urlp_reg(payload,php|jsp|asp|aspx)")
        lines.append("    acl blocked_webshell path_reg -i /(cmd|shell|backdoor|webshell|phpspy|c99|kacak|b374k|log4j|log4shell|wsos|madspot|malicious|evil).*\\.php.*")
        lines.append("    acl is_suspicious_post hdr(Content-Type) -i application/x-www-form-urlencoded multipart/form-data")
        lines.append("    http-request deny if blocked_webshell or is_webshell or is_potential_webshell or is_suspicious_post")

    if backend:
        lines.append(f"    default_backend {backend.name}")
    return "\n".join(lines) + "\n"


def _build_backend_block(backend):
    lines = [f"backend {backend.name}"]

    if backend.sticky_enabled and backend.sticky_type == 'cookie':
        lines.append("    cookie SERVERID insert indirect nocache")
    if backend.sticky_enabled and backend.sticky_type == 'stick-table':
        lines.append("    stick-table type ip size 200k expire 5m")
        lines.append("    stick on src")
    if backend.add_header_enabled and backend.header_name:
        lines.append(f"    http-request set-header {backend.header_name} \"{backend.header_value or ''}\"")
    if backend.mode == 'http' and backend.health_check_enabled and backend.health_check_path:
        lines.append(f"    option httpchk GET {backend.health_check_path}")
        lines.append("    http-check disable-on-404")
        lines.append("    http-check expect string OK")
    if backend.mode == 'tcp' and backend.health_check_tcp:
        lines.append("    option tcp-check")
        lines.append("    tcp-check send PING\\r\\n")
        lines.append("    tcp-check send QUIT\\r\\n")

    for server in backend.servers:
        if not server.enabled:
            continue
        line = f"    server {server.name} {server.ip}:{server.port} check"
        if backend.sticky_enabled and backend.sticky_type == 'cookie':
            line += f" cookie {server.name}"
        if server.maxconn:
            line += f" maxconn {server.maxconn}"
        lines.append(line)

    return "\n".join(lines) + "\n"
