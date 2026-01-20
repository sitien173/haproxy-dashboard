import re

from db import db
from sqlalchemy import and_, or_
from db.models import (
    BackendPool,
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

    enabled_frontends = [
        frontend
        for frontend in Frontend.query.order_by(Frontend.created_at.asc()).all()
        if frontend.enabled
    ]
    host_frontends = [frontend for frontend in enabled_frontends if frontend.domain_name]
    port_frontends = [frontend for frontend in enabled_frontends if not frontend.domain_name]
    https_frontends = [frontend for frontend in host_frontends if frontend.use_ssl]
    http_frontends = [frontend for frontend in host_frontends if not frontend.use_ssl]
    http_redirects = [frontend for frontend in host_frontends if frontend.use_ssl and frontend.https_redirect]

    used_backend_set = set()
    backend_lb_map = {}

    def register_backend(frontend):
        if frontend.backend_links:
            for link in frontend.backend_links:
                backend = backend_map.get(link.backend_id)
                if backend:
                    used_backend_set.add(backend.id)
                    if frontend.lb_method:
                        backend_lb_map.setdefault(backend.id, frontend.lb_method)
        if frontend.default_backend_id:
            backend = backend_map.get(frontend.default_backend_id)
            if backend:
                used_backend_set.add(backend.id)
                if frontend.lb_method:
                    backend_lb_map.setdefault(backend.id, frontend.lb_method)
        for acl in frontend.acls:
            if acl.backend_id:
                backend = backend_map.get(acl.backend_id)
                if backend:
                    used_backend_set.add(backend.id)
                    if frontend.lb_method:
                        backend_lb_map.setdefault(backend.id, frontend.lb_method)

    for frontend in https_frontends:
        register_backend(frontend)
    for frontend in http_frontends:
        register_backend(frontend)
    for frontend in port_frontends:
        register_backend(frontend)

    if https_frontends:
        parts.append(_build_https_frontend(https_frontends, backend_map))
        parts.append("")
    if http_frontends or http_redirects:
        parts.append(_build_http_frontend(http_frontends, http_redirects, backend_map))
        parts.append("")
    for frontend in port_frontends:
        parts.append(_build_port_frontend(frontend, backend_map))
        parts.append("")

    for backend in BackendPool.query.order_by(BackendPool.created_at.asc()).all():
        if backend.id in used_backend_set and backend.id in backend_map:
            lb_method = backend_lb_map.get(backend.id)
            parts.append(_build_backend_block(backend_map[backend.id], lb_method=lb_method))
            parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def write_haproxy_config():
    config_content = render_haproxy_config()
    with open('/etc/haproxy/haproxy.cfg', 'w') as haproxy_cfg:
        haproxy_cfg.write(config_content)


def is_frontend_exist(frontend_name, domain_name, bind_ip=None, bind_port=None, ignore_id=None):
    filters = [Frontend.name == frontend_name]
    if domain_name:
        filters.append(Frontend.domain_name == domain_name)
    if bind_ip and bind_port:
        filters.append(and_(Frontend.bind_ip == bind_ip, Frontend.bind_port == bind_port))
    query = Frontend.query.filter(or_(*filters))
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
def _parse_duration_seconds(value):
    if not value:
        return None
    match = re.match(r'^\s*(\d+)\s*([smhd]?)\s*$', str(value))
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2) or 's'
    multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    return amount * multipliers.get(unit, 1)


def _build_https_frontend(frontends, backend_map):
    lines = [
        "frontend https_shared",
        "    bind *:443 ssl crt /etc/haproxy-configurator/ssl/ alpn h2,http/1.1",
        "    mode http",
    ]

    for frontend in frontends:
        lines.append(f"    acl host_{frontend.id} hdr(host) -i {frontend.domain_name}")

    _append_frontend_rules(lines, frontends, backend_map, include_backend=True)
    return "\n".join(lines) + "\n"


def _build_http_frontend(frontends, redirect_frontends, backend_map):
    lines = [
        "frontend http_shared",
        "    bind *:80",
        "    mode http",
    ]

    for frontend in frontends:
        lines.append(f"    acl host_{frontend.id} hdr(host) -i {frontend.domain_name}")
    for frontend in redirect_frontends:
        lines.append(f"    acl host_{frontend.id} hdr(host) -i {frontend.domain_name}")

    for frontend in redirect_frontends:
        lines.append(f"    http-request redirect scheme https code 301 if host_{frontend.id}")

    _append_frontend_rules(lines, frontends, backend_map, include_backend=True)
    return "\n".join(lines) + "\n"


def _build_port_frontend(frontend, backend_map):
    bind_line = f"    bind {frontend.bind_ip}:{frontend.bind_port}"
    if frontend.use_ssl:
        cert_path = frontend.certificate.pem_path if frontend.certificate else None
        if cert_path:
            bind_line += f" ssl crt {cert_path}"
        else:
            bind_line += " ssl"
    lines = [
        f"frontend {frontend.name}",
        bind_line,
        f"    mode {frontend.mode}",
    ]
    _append_port_frontend_rules(lines, frontend, backend_map)
    return "\n".join(lines) + "\n"


def _append_frontend_rules(lines, frontends, backend_map, include_backend=True):
    dos_frontends = [frontend for frontend in frontends if frontend.dos_enabled]
    if dos_frontends:
        expires = []
        for frontend in dos_frontends:
            seconds = _parse_duration_seconds(frontend.dos_ban_duration)
            if seconds:
                expires.append(seconds)
        expire_value = f"{max(expires)}s" if expires else "60s"
        lines.append(f"    stick-table type ip size 1m expire {expire_value} store http_req_rate(1m)")

    for frontend in frontends:
        host_acl = f"host_{frontend.id}"
        backend = backend_map.get(frontend.default_backend_id) if frontend.default_backend_id else None

        if frontend.forward_for:
            lines.append(f"    http-request add-header X-Forwarded-For %[src] if {host_acl}")

        if frontend.dos_enabled:
            limit = frontend.dos_limit or 20
            lines.append(f"    http-request track-sc0 src if {host_acl}")
            lines.append(f"    acl abuse_{frontend.id} sc_http_req_rate(0) gt {limit}")
            lines.append(f"    http-request silent-drop if {host_acl} abuse_{frontend.id}")

        if frontend.sql_injection_enabled:
            lines.append(f"    acl sql_injection_{frontend.id} urlp_reg -i (union|select|insert|update|delete|drop|@@|1=1|`1)")
            lines.append(f"    acl long_uri_{frontend.id} path_len gt 400")
            lines.append(f"    acl semicolon_path_{frontend.id} path_reg -i ^.*;.*")
            lines.append(f"    acl sql_injection2_{frontend.id} urlp_reg -i (;|substring|extract|union\\s+all|order\\s+by)\\s+(\\d+|--\\+)")
            lines.append(
                f"    http-request deny if {host_acl} sql_injection_{frontend.id} or {host_acl} long_uri_{frontend.id} "
                f"or {host_acl} semicolon_path_{frontend.id} or {host_acl} sql_injection2_{frontend.id}"
            )

        if frontend.xss_enabled:
            lines.append(f"    acl xss_attack_{frontend.id} urlp_reg -i (<|>|script|alert|onerror|onload|javascript)")
            lines.append(
                f"    acl xss_attack2_{frontend.id} urlp_reg -i "
                f"(<\\s*script\\s*|javascript:|<\\s*img\\s*src\\s*=|<\\s*a\\s*href\\s*=|"
                f"<\\s*iframe\\s*src\\s*=|\\bon\\w+\\s*=|<\\s*input\\s*[^>]*\\s*value\\s*=|"
                f"<\\s*form\\s*action\\s*=|<\\s*svg\\s*on\\w+\\s*=)"
            )
            lines.append(
                f"    acl xss_attack_hdr_{frontend.id} hdr_reg(Cookie|Referer|User-Agent) "
                f"-i (<|>|script|alert|onerror|onload|javascript)"
            )
            lines.append(
                f"    acl xss_cookie_{frontend.id} hdr_beg(Cookie) -i \"<script\" \"javascript:\" \"on\" "
                f"\"alert(\" \"iframe\" \"onload\" \"onerror\" \"onclick\" \"onmouseover\""
            )
            lines.append(
                f"    http-request deny if {host_acl} xss_attack_{frontend.id} or {host_acl} xss_attack_hdr_{frontend.id} "
                f"or {host_acl} xss_attack2_{frontend.id} or {host_acl} xss_cookie_{frontend.id}"
            )

        if frontend.remote_upload_enabled:
            lines.append(f"    acl put_request_{frontend.id} method PUT")
            lines.append(f"    http-request deny if {host_acl} put_request_{frontend.id}")

        if frontend.webshells_enabled:
            lines.append("    option http-buffer-request")
            lines.append(
                f"    acl webshell_{frontend.id} urlp_reg(payload,eval|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)"
            )
            lines.append(f"    acl potential_webshell_{frontend.id} urlp_reg(payload,php|jsp|asp|aspx)")
            lines.append(
                f"    acl blocked_webshell_{frontend.id} path_reg -i "
                f"/(cmd|shell|backdoor|webshell|phpspy|c99|kacak|b374k|log4j|log4shell|wsos|madspot|malicious|evil).*\\.php.*"
            )
            lines.append(
                f"    acl suspicious_post_{frontend.id} hdr(Content-Type) -i application/x-www-form-urlencoded multipart/form-data"
            )
            lines.append(
                f"    http-request deny if {host_acl} blocked_webshell_{frontend.id} or {host_acl} webshell_{frontend.id} "
                f"or {host_acl} potential_webshell_{frontend.id} or {host_acl} suspicious_post_{frontend.id}"
            )

        for acl in frontend.acls:
            acl_name = f"acl_{frontend.id}_{acl.id}"
            lines.append(f"    acl {acl_name} {acl.action}")
            backend_target = backend_map.get(acl.backend_id) if acl.backend_id else None
            if backend_target:
                lines.append(f"    use_backend {backend_target.name} if {host_acl} {acl_name}")

        for forbidden in frontend.forbidden_paths:
            acl_name = f"allow_{frontend.id}_{forbidden.id}"
            lines.append(f"    acl {acl_name} src {forbidden.allowed_ip}")
            lines.append(f"    http-request deny if {host_acl} !{acl_name} {{ path_beg {forbidden.path} }}")

        for redirect_rule in frontend.redirect_rules:
            host_acl_name = f"redirect_host_{frontend.id}_{redirect_rule.id}"
            root_acl_name = f"redirect_root_{frontend.id}_{redirect_rule.id}"
            lines.append(f"    acl {host_acl_name} hdr(host) -i {redirect_rule.host_match}")
            lines.append(f"    acl {root_acl_name} path {redirect_rule.root_path}")
            lines.append(
                f"    http-request redirect location {redirect_rule.redirect_to} if {host_acl_name} or {host_acl} {root_acl_name}"
            )

        if include_backend and backend:
            lines.append(f"    use_backend {backend.name} if {host_acl}")


def _append_port_frontend_rules(lines, frontend, backend_map):
    backend = backend_map.get(frontend.default_backend_id) if frontend.default_backend_id else None

    if frontend.dos_enabled:
        seconds = _parse_duration_seconds(frontend.dos_ban_duration)
        expire_value = f"{seconds}s" if seconds else "60s"
        lines.append(f"    stick-table type ip size 1m expire {expire_value} store http_req_rate(1m)")

    if frontend.forward_for:
        lines.append("    http-request add-header X-Forwarded-For %[src]")

    if frontend.dos_enabled:
        limit = frontend.dos_limit or 20
        lines.append("    http-request track-sc0 src")
        lines.append(f"    acl abuse_{frontend.id} sc_http_req_rate(0) gt {limit}")
        lines.append(f"    http-request silent-drop if abuse_{frontend.id}")

    if frontend.sql_injection_enabled:
        lines.append(f"    acl sql_injection_{frontend.id} urlp_reg -i (union|select|insert|update|delete|drop|@@|1=1|`1)")
        lines.append(f"    acl long_uri_{frontend.id} path_len gt 400")
        lines.append(f"    acl semicolon_path_{frontend.id} path_reg -i ^.*;.*")
        lines.append(f"    acl sql_injection2_{frontend.id} urlp_reg -i (;|substring|extract|union\\s+all|order\\s+by)\\s+(\\d+|--\\+)")
        lines.append(
            f"    http-request deny if sql_injection_{frontend.id} or long_uri_{frontend.id} "
            f"or semicolon_path_{frontend.id} or sql_injection2_{frontend.id}"
        )

    if frontend.xss_enabled:
        lines.append(f"    acl xss_attack_{frontend.id} urlp_reg -i (<|>|script|alert|onerror|onload|javascript)")
        lines.append(
            f"    acl xss_attack2_{frontend.id} urlp_reg -i "
            f"(<\\s*script\\s*|javascript:|<\\s*img\\s*src\\s*=|<\\s*a\\s*href\\s*=|"
            f"<\\s*iframe\\s*src\\s*=|\\bon\\w+\\s*=|<\\s*input\\s*[^>]*\\s*value\\s*=|"
            f"<\\s*form\\s*action\\s*=|<\\s*svg\\s*on\\w+\\s*=)"
        )
        lines.append(
            f"    acl xss_attack_hdr_{frontend.id} hdr_reg(Cookie|Referer|User-Agent) "
            f"-i (<|>|script|alert|onerror|onload|javascript)"
        )
        lines.append(
            f"    acl xss_cookie_{frontend.id} hdr_beg(Cookie) -i \"<script\" \"javascript:\" \"on\" "
            f"\"alert(\" \"iframe\" \"onload\" \"onerror\" \"onclick\" \"onmouseover\""
        )
        lines.append(
            f"    http-request deny if xss_attack_{frontend.id} or xss_attack_hdr_{frontend.id} "
            f"or xss_attack2_{frontend.id} or xss_cookie_{frontend.id}"
        )

    if frontend.remote_upload_enabled:
        lines.append(f"    acl put_request_{frontend.id} method PUT")
        lines.append(f"    http-request deny if put_request_{frontend.id}")

    if frontend.webshells_enabled:
        lines.append("    option http-buffer-request")
        lines.append(
            f"    acl webshell_{frontend.id} urlp_reg(payload,eval|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)"
        )
        lines.append(f"    acl potential_webshell_{frontend.id} urlp_reg(payload,php|jsp|asp|aspx)")
        lines.append(
            f"    acl blocked_webshell_{frontend.id} path_reg -i "
            f"/(cmd|shell|backdoor|webshell|phpspy|c99|kacak|b374k|log4j|log4shell|wsos|madspot|malicious|evil).*\\.php.*"
        )
        lines.append(
            f"    acl suspicious_post_{frontend.id} hdr(Content-Type) -i application/x-www-form-urlencoded multipart/form-data"
        )
        lines.append(
            f"    http-request deny if blocked_webshell_{frontend.id} or webshell_{frontend.id} "
            f"or potential_webshell_{frontend.id} or suspicious_post_{frontend.id}"
        )

    for acl in frontend.acls:
        acl_name = f"acl_{frontend.id}_{acl.id}"
        lines.append(f"    acl {acl_name} {acl.action}")
        backend_target = backend_map.get(acl.backend_id) if acl.backend_id else None
        if backend_target:
            lines.append(f"    use_backend {backend_target.name} if {acl_name}")

    for forbidden in frontend.forbidden_paths:
        acl_name = f"allow_{frontend.id}_{forbidden.id}"
        lines.append(f"    acl {acl_name} src {forbidden.allowed_ip}")
        lines.append(f"    http-request deny if !{acl_name} {{ path_beg {forbidden.path} }}")

    for redirect_rule in frontend.redirect_rules:
        host_acl_name = f"redirect_host_{frontend.id}_{redirect_rule.id}"
        root_acl_name = f"redirect_root_{frontend.id}_{redirect_rule.id}"
        lines.append(f"    acl {host_acl_name} hdr(host) -i {redirect_rule.host_match}")
        lines.append(f"    acl {root_acl_name} path {redirect_rule.root_path}")
        lines.append(
            f"    http-request redirect location {redirect_rule.redirect_to} if {host_acl_name} or {root_acl_name}"
        )

    if backend:
        lines.append(f"    default_backend {backend.name}")


def _build_backend_block(backend, lb_method=None):
    lines = [f"backend {backend.name}"]

    if lb_method:
        lines.append(f"    balance {lb_method}")
    if backend.sticky_enabled and backend.sticky_type == 'cookie':
        lines.append("    cookie SERVERID insert indirect nocache")
    if backend.sticky_enabled and backend.sticky_type == 'stick-table':
        lines.append("    stick-table type ip size 200k expire 5m")
        lines.append("    stick on src")
    for header in backend.headers:
        if not header.enabled or not header.name:
            continue
        lines.append(f"    http-request set-header {header.name} \"{header.value or ''}\"")
    if backend.mode == 'http' and backend.health_check_enabled:
        path = backend.health_check_path or '/'
        lines.append(f"    option httpchk GET {path}")
        lines.append("    http-check disable-on-404")
        lines.append("    http-check expect string OK")
    if backend.mode == 'tcp' and backend.health_check_tcp:
        lines.append("    option tcp-check")
        lines.append("    tcp-check send PING\\r\\n")
        lines.append("    tcp-check send QUIT\\r\\n")

    for server in backend.servers:
        if not server.enabled:
            continue
        line = f"    server {server.name} {server.ip}:{server.port}"
        if backend.health_check_enabled or backend.health_check_tcp:
            line += " check"
        if backend.sticky_enabled and backend.sticky_type == 'cookie':
            line += f" cookie {server.name}"
        if server.maxconn:
            line += f" maxconn {server.maxconn}"
        lines.append(line)

    return "\n".join(lines) + "\n"
