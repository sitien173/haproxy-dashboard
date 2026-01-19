import configparser
import os
import re
import subprocess
from datetime import datetime

from db import db
from db.models import Certificate

DEFAULT_ACME_INI_PATH = '/etc/haproxy-configurator/acme.ini'


def load_acme_config(config_path=None):
    config_path = config_path or os.getenv('HAPROXY_CONFIGURATOR_ACME_INI', DEFAULT_ACME_INI_PATH)
    config = configparser.ConfigParser()
    read_files = config.read(config_path)
    if not read_files:
        raise FileNotFoundError(f"ACME config not found: {config_path}")

    acme_home = config.get('acme', 'acme_home', fallback='').strip()
    challenge = config.get('acme', 'challenge', fallback='webroot').strip().lower()
    webroot = config.get('acme', 'webroot', fallback='').strip()
    dns_provider = config.get('acme', 'dns_provider', fallback='').strip()
    cert_dir = config.get('acme', 'cert_dir', fallback='/etc/haproxy-configurator/ssl').strip()
    reload_cmd = config.get('acme', 'reload_cmd', fallback='systemctl reload haproxy').strip()

    if acme_home:
        acme_sh = os.path.join(acme_home, 'acme.sh')
    else:
        acme_sh = os.path.expanduser('~/.acme.sh/acme.sh')

    return {
        'acme_home': acme_home,
        'acme_sh': acme_sh,
        'challenge': challenge,
        'webroot': webroot,
        'dns_provider': dns_provider,
        'cert_dir': cert_dir,
        'reload_cmd': reload_cmd,
    }


def _sanitize_domain(domain):
    return re.sub(r'[^A-Za-z0-9.-]', '_', domain)


def _acme_home_flags(acme_home):
    if not acme_home:
        return []
    return ['--home', acme_home, '--config-home', acme_home]


def _get_cert_enddate(cert_path):
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-enddate', '-noout', '-in', cert_path],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    line = result.stdout.strip()
    if line.startswith('notAfter='):
        return line.replace('notAfter=', '').strip()
    return None


def _get_cert_issuer(cert_path):
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-issuer', '-noout', '-in', cert_path],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    line = result.stdout.strip()
    if line.startswith('issuer='):
        return line.replace('issuer=', '').strip()
    return None


def list_installed_certificates(config_path=None):
    records = Certificate.query.order_by(Certificate.domain.asc()).all()
    return [
        {
            'id': record.id,
            'domain': record.domain,
            'pem_path': record.pem_path,
            'expires_at': record.expires_at or 'Unknown',
        }
        for record in records
    ]


def issue_certificate(domain, config_path=None):
    if not domain:
        raise ValueError("Domain name is required for ACME issuance.")

    config = load_acme_config(config_path)
    acme_sh = config['acme_sh']
    if not os.path.exists(acme_sh):
        raise FileNotFoundError(
            f"acme.sh not found: {acme_sh}. Install it with /etc/haproxy-configurator/scripts/setup_acme.sh "
            "or https://get.acme.sh."
        )

    cert_dir = config['cert_dir']
    safe_domain = _sanitize_domain(domain)
    domain_dir = os.path.join(cert_dir, safe_domain)
    os.makedirs(domain_dir, exist_ok=True)

    fullchain_path = os.path.join(domain_dir, 'fullchain.pem')
    privkey_path = os.path.join(domain_dir, 'privkey.pem')
    combined_pem_path = os.path.join(cert_dir, f"{safe_domain}.pem")

    if os.path.exists(combined_pem_path):
        return combined_pem_path

    challenge = config['challenge']
    issue_cmd = [acme_sh] + _acme_home_flags(config['acme_home']) + ['--issue', '-d', domain, '--force', '--debug']
    if challenge == 'webroot':
        if not config['webroot']:
            raise ValueError("ACME webroot challenge requires webroot in acme.ini.")
        issue_cmd += ['--webroot', config['webroot']]
    elif challenge == 'standalone':
        issue_cmd += ['--standalone']
    elif challenge == 'dns':
        if not config['dns_provider']:
            raise ValueError("ACME DNS challenge requires dns_provider in acme.ini.")
        issue_cmd += ['--dns', config['dns_provider']]
    else:
        raise ValueError(f"Unsupported ACME challenge: {challenge}")

    # Ensure acme.sh can find its configuration by setting HOME and LE_WORKING_DIR
    # This is necessary when running from systemd service without a proper shell environment
    env = os.environ.copy()
    acme_home = config['acme_home']
    if acme_home:
        # Set HOME to the parent directory so acme.sh finds ~/.acme.sh
        parent_dir = os.path.dirname(acme_home)
        if parent_dir:
            env['HOME'] = parent_dir
        env['LE_WORKING_DIR'] = acme_home

    try:
        subprocess.run(issue_cmd, check=True, capture_output=True, text=True, env=env)
    except subprocess.CalledProcessError as exc:
        error_output = exc.stderr or exc.stdout or str(exc)
        raise RuntimeError(f"acme.sh issue failed: {error_output}") from exc

    install_cmd = [
        acme_sh, *_acme_home_flags(config['acme_home']), '--install-cert', '-d', domain,
        '--fullchain-file', fullchain_path,
        '--key-file', privkey_path,
        '--reloadcmd', config['reload_cmd'],
    ]
    try:
        subprocess.run(install_cmd, check=True, capture_output=True, text=True, env=env)
    except subprocess.CalledProcessError as exc:
        error_output = exc.stderr or exc.stdout or str(exc)
        raise RuntimeError(f"acme.sh install failed: {error_output}") from exc

    with open(fullchain_path, 'r') as fullchain_file, open(privkey_path, 'r') as key_file:
        fullchain_data = fullchain_file.read()
        key_data = key_file.read()

    with open(combined_pem_path, 'w') as combined_file:
        combined_file.write(fullchain_data)
        combined_file.write(key_data)

    try:
        os.chmod(combined_pem_path, 0o600)
    except PermissionError:
        pass

    return combined_pem_path


def renew_certificate(domain, config_path=None):
    if not domain:
        raise ValueError("Domain name is required for ACME renewal.")

    config = load_acme_config(config_path)
    acme_sh = config['acme_sh']
    if not os.path.exists(acme_sh):
        raise FileNotFoundError(
            f"acme.sh not found: {acme_sh}. Install it with /etc/haproxy-configurator/scripts/setup_acme.sh "
            "or https://get.acme.sh."
        )

    cert_dir = config['cert_dir']
    safe_domain = _sanitize_domain(domain)
    domain_dir = os.path.join(cert_dir, safe_domain)
    os.makedirs(domain_dir, exist_ok=True)

    fullchain_path = os.path.join(domain_dir, 'fullchain.pem')
    privkey_path = os.path.join(domain_dir, 'privkey.pem')
    combined_pem_path = os.path.join(cert_dir, f"{safe_domain}.pem")

    env = os.environ.copy()
    acme_home = config['acme_home']
    if acme_home:
        parent_dir = os.path.dirname(acme_home)
        if parent_dir:
            env['HOME'] = parent_dir
        env['LE_WORKING_DIR'] = acme_home

    renew_cmd = [acme_sh] + _acme_home_flags(config['acme_home']) + ['--renew', '-d', domain]
    try:
        subprocess.run(renew_cmd, check=True, capture_output=True, text=True, env=env)
    except subprocess.CalledProcessError as exc:
        error_output = exc.stderr or exc.stdout or str(exc)
        raise RuntimeError(f"acme.sh renew failed: {error_output}") from exc

    install_cmd = [
        acme_sh, *_acme_home_flags(config['acme_home']), '--install-cert', '-d', domain,
        '--fullchain-file', fullchain_path,
        '--key-file', privkey_path,
        '--reloadcmd', config['reload_cmd'],
    ]
    try:
        subprocess.run(install_cmd, check=True, capture_output=True, text=True, env=env)
    except subprocess.CalledProcessError as exc:
        error_output = exc.stderr or exc.stdout or str(exc)
        raise RuntimeError(f"acme.sh install failed: {error_output}") from exc

    with open(fullchain_path, 'r') as fullchain_file, open(privkey_path, 'r') as key_file:
        fullchain_data = fullchain_file.read()
        key_data = key_file.read()

    with open(combined_pem_path, 'w') as combined_file:
        combined_file.write(fullchain_data)
        combined_file.write(key_data)

    try:
        os.chmod(combined_pem_path, 0o600)
    except PermissionError:
        pass

    cert = Certificate.query.filter_by(domain=domain).first()
    if cert:
        cert.pem_path = combined_pem_path
        cert.issuer = _get_cert_issuer(combined_pem_path)
        cert.expires_at = _get_cert_enddate(combined_pem_path)
        cert.last_renewed_at = datetime.utcnow()
        db.session.commit()

    return combined_pem_path
