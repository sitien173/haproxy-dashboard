import configparser
import os
import ssl

DEFAULT_SSL_INI_PATH = '/etc/haproxy-configurator/ssl.ini'
LEGACY_PEM_PATH = '/etc/haproxy-configurator/ssl/haproxy-configurator.pem'


def load_ssl_config(config_path=None):
    config_path = config_path or os.getenv('HAPROXY_CONFIGURATOR_SSL_INI', DEFAULT_SSL_INI_PATH)
    config = configparser.ConfigParser()
    read_files = config.read(config_path)
    if not read_files:
        raise FileNotFoundError(f"SSL config not found: {config_path}")

    certificate_path = config.get('ssl', 'certificate_path')
    private_key_path = config.get('ssl', 'private_key_path')
    return certificate_path, private_key_path


def build_ssl_context(certificate_path, private_key_path):
    if not os.path.exists(certificate_path) or not os.path.exists(private_key_path):
        if os.path.exists(LEGACY_PEM_PATH):
            certificate_path = LEGACY_PEM_PATH
            private_key_path = LEGACY_PEM_PATH

    if not os.path.exists(certificate_path):
        raise FileNotFoundError(f"Certificate not found: {certificate_path}")
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key not found: {private_key_path}")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.load_cert_chain(certfile=certificate_path, keyfile=private_key_path)
    return ssl_context
