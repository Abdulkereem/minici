import subprocess


def generate_nginx_config(domain, port):
    """Generate Nginx server block configuration for a domain"""
    config = f"""
server {{
    listen 80;
    server_name {domain};

    location / {{
        proxy_pass http://localhost:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }}
}}
"""
    return config

def reload_nginx():
    """Test and reload Nginx configuration"""
    test_result = subprocess.run(['sudo', 'nginx', '-t'], capture_output=True)
    if test_result.returncode != 0:
        return False, test_result.stderr.decode()
    
    reload_result = subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], capture_output=True)
    return reload_result.returncode == 0, reload_result.stderr.decode() if reload_result.returncode != 0 else "Success"