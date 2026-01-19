import configparser
import os
import re
import subprocess

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
        'acme_sh': acme_sh,
        'challenge': challenge,
        'webroot': webroot,
        'dns_provider': dns_provider,
        'cert_dir': cert_dir,
        'reload_cmd': reload_cmd,
    }


def _sanitize_domain(domain):
    return re.sub(r'[^A-Za-z0-9.-]', '_', domain)


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
    issue_cmd = [acme_sh, '--issue', '-d', domain]
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

    try:
        subprocess.run(issue_cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        error_output = exc.stderr or exc.stdout or str(exc)
        raise RuntimeError(f"acme.sh issue failed: {error_output}") from exc

    install_cmd = [
        acme_sh, '--install-cert', '-d', domain,
        '--fullchain-file', fullchain_path,
        '--key-file', privkey_path,
        '--reloadcmd', config['reload_cmd'],
    ]
    try:
        subprocess.run(install_cmd, check=True, capture_output=True, text=True)
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
