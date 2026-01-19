from flask import Blueprint, render_template, request
import subprocess
from auth.auth_middleware import requires_auth  # Updated import
from utils.haproxy_config import parse_haproxy_sections, replace_haproxy_section
from utils.acme_utils import list_installed_certificates, renew_certificate

edit_bp = Blueprint('edit', __name__)

@edit_bp.route('/edit', methods=['GET', 'POST'])
@requires_auth
def edit_haproxy_config():
    if request.method == 'POST':
        edited_config = request.form['haproxy_config']
        # Save the edited config to the haproxy.cfg file
        with open('/etc/haproxy/haproxy.cfg', 'w') as f:
            f.write(edited_config)

        check_output = ""
        
        if 'save_check' in request.form:
            # Run haproxy -c -V -f to check the configuration
            check_result = subprocess.run(['haproxy', '-c', '-V', '-f', '/etc/haproxy/haproxy.cfg'], capture_output=True, text=True)
            check_output = check_result.stdout

            # Check if there was an error, and if so, append it to the output
            if check_result.returncode != 0:
                error_message = check_result.stderr
                check_output += f"\n\nError occurred:\n{error_message}"

        elif 'save_reload' in request.form:
            # Run haproxy -c -V -f to check the configuration
            check_result = subprocess.run(['haproxy', '-c', '-V', '-f', '/etc/haproxy/haproxy.cfg'], capture_output=True, text=True)
            check_output = check_result.stdout

            # Check if there was an error, and if so, append it to the output
            if check_result.returncode != 0:
                error_message = check_result.stderr
                check_output += f"\n\nError occurred:\n{error_message}"
            else:
                # If no error, run systemctl restart haproxy to reload HAProxy
                reload_result = subprocess.run(['systemctl', 'restart', 'haproxy'], capture_output=True, text=True)
                check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"
                
                # Also add stderr if there are any warnings or errors during restart
                if reload_result.stderr:
                    check_output += f"\nRestart Stderr:\n{reload_result.stderr}"

        return render_template('edit.html', config_content=edited_config, check_output=check_output)

    # GET request - Read the current contents of haproxy.cfg
    try:
        with open('/etc/haproxy/haproxy.cfg', 'r') as f:
            config_content = f.read()
    except FileNotFoundError:
        config_content = "# HAProxy configuration file not found\n# Please create /etc/haproxy/haproxy.cfg"
    except PermissionError:
        config_content = "# Permission denied reading HAProxy configuration file"
    
    return render_template('edit.html', config_content=config_content)


@edit_bp.route('/manage', methods=['GET', 'POST'])
@requires_auth
def manage_haproxy_sections():
    message = None
    if request.method == 'POST':
        section_type = request.form.get('section_type', '').strip()
        section_name = request.form.get('section_name', '').strip()
        section_content = request.form.get('section_content', '').strip()

        if not section_type or not section_name:
            message = "Please select a frontend or backend."
        elif not section_content:
            message = "Section content is required."
        else:
            first_line = section_content.splitlines()[0].strip()
            if not first_line.startswith(f"{section_type} "):
                message = f"Section must start with '{section_type} <name>'."
            else:
                ok, detail = replace_haproxy_section(section_type, section_name, section_content)
                message = detail

    try:
        sections = parse_haproxy_sections()
    except FileNotFoundError:
        sections = []
        message = message or "HAProxy configuration file not found."
    except PermissionError:
        sections = []
        message = message or "Permission denied reading HAProxy configuration file."

    return render_template('manage.html', sections=sections, message=message)


@edit_bp.route('/certificates', methods=['GET', 'POST'])
@requires_auth
def manage_certificates():
    message = None
    if request.method == 'POST':
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
