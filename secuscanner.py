import os
import socket
import subprocess
import platform
import logging
import nmap
import pkg_resources
from datetime import datetime

logging.basicConfig(filename='secuscanner.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def check_open_ports_with_nmap(host, ports):
    nm = nmap.PortScanner()
    open_ports = []
    for port in ports:
        nm.scan(host, str(port))
        if nm[host]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    return open_ports

def check_file_permissions(file_path):
    permissions = os.stat(file_path).st_mode
    if permissions & 0o777 != 0o644:
        return f'Insecure permissions for {file_path}: {oct(permissions)}'
    return f'Secure permissions for {file_path}: {oct(permissions)}'

def check_windows_file_permissions(file_path):
    if os.access(file_path, os.R_OK) and os.access(file_path, os.W_OK):
        return f'Secure permissions for {file_path}'
    else:
        return f'Insecure permissions for {file_path}'

def check_service_status(service_name):
    try:
        result = subprocess.run(['systemctl', 'is-active', service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if 'active' in result.stdout:
            return f'Service {service_name} is running'
        else:
            return f'Service {service_name} is not running'
    except FileNotFoundError:
        return f'systemctl not found, cannot check {service_name} status'

def check_outdated_packages():
    outdated_packages = []
    for dist in pkg_resources.working_set:
        try:
            latest_version = subprocess.check_output(['pip', 'install', dist.project_name+'==random'], stderr=subprocess.STDOUT, text=True)
            if dist.version != latest_version.strip():
                outdated_packages.append((dist.project_name, dist.version, latest_version.strip()))
        except subprocess.CalledProcessError:
            pass
    return outdated_packages

def log_activity(activity):
    logging.info(activity)

def is_windows():
    return platform.system() == 'Windows'

def is_linux():
    return platform.system() == 'Linux'

def main():
    host = '127.0.0.1'
    ports = [22, 80, 443, 3389]
    files_to_check = ['/etc/passwd', '/etc/shadow'] if is_linux() else ['C:\\Windows\\System32\\config\\SAM']

    log_activity('Starting vulnerability scan...')

    open_ports = check_open_ports_with_nmap(host, ports)
    if open_ports:
        log_activity(f'Open ports found: {open_ports}')
    else:
        log_activity('No open ports found')

    for file_path in files_to_check:
        if os.path.exists(file_path):
            if is_linux():
                log_activity(check_file_permissions(file_path))
            elif is_windows():
                log_activity(check_windows_file_permissions(file_path))
        else:
            log_activity(f'{file_path} does not exist')

    if is_linux():
        services_to_check = ['ssh', 'apache2']
        for service in services_to_check:
            log_activity(check_service_status(service))
    else:
        log_activity('Service status checks not supported on Windows in this script')

    outdated_packages = check_outdated_packages()
    if outdated_packages:
        log_activity(f'Outdated packages found: {outdated_packages}')
    else:
        log_activity('No outdated packages found')

    log_activity('Vulnerability scan complete.')

if __name__ == '__main__':
    main()
