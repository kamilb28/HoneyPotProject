import os
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko

log_dir = 'log'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log = logging.getLogger('FunnelLogger')
audit_handler = RotatingFileHandler(f'{log_dir}/audit.log', maxBytes=2000, backupCount=5)
audit_handler.setFormatter(logging.Formatter('%(message)s'))
log.addHandler(audit_handler)

cmd_log = logging.getLogger('CmdAuditLogger')
cmd_audit_handler = RotatingFileHandler(f'{log_dir}/cmd_audit.log', maxBytes=2000, backupCount=5)
cmd_audit_handler.setFormatter(logging.Formatter('%(message)s'))
cmd_log.addHandler(cmd_audit_handler)

mock_file_system = {
    "": ["file1.txt", "file2.txt", "dir1"],  # Root directory contents
    "dir1": ["nested_file.txt"],           # Contents of 'dir1'
    "file1.txt": "Content of file1.txt",    # Content of 'file1.txt'
    "file2.txt": "Content of file2.txt",    # Content of 'file2.txt'
    "dir1/nested_file.txt": "Content of nested_file.txt",  # Content of nested file
}

def shell(channel, client):
    channel.send(b'hpp$ ')
    command = b""
    current_directory = ""

    while True:
        c = channel.recv(1)
        channel.send(c)
        if not c:
            channel.close()
            break

        command += c

        if c == b'\r':
            command = command.strip()
            response = b""
            
            if command == b'exit':
                channel.close()
                break
            elif command == b'pwd':
                response = f"/{current_directory}".encode('utf-8') + b'\r\n'
            elif command == b'whoami':
                response = b'\nhpp' + b'\r\n'
            elif command == b'ls':
                try:
                    files = mock_file_system.get(current_directory, [])
                    response = b'\n' + b'\n'.join(f.encode('utf-8') for f in files) + b'\r\n'
                except Exception as e:
                    response = f"Error listing files: {str(e)}".encode('utf-8') + b'\r\n'
            elif command.startswith(b'cat '):
                try:
                    file_name = command[4:].decode('utf-8')
                    full_path = f"{current_directory}/{file_name}".strip("/")
                    file_content = mock_file_system.get(full_path, None)
                    if file_content is None:
                        response = b"File not found\r\n"
                    else:
                        response = file_content.encode('utf-8') + b'\r\n'
                except Exception as e:
                    response = f"Error reading file: {str(e)}".encode('utf-8') + b'\r\n'
            elif command.startswith(b'cd '):
                try:
                    new_dir = command[3:].decode('utf-8')
                    full_path = f"{current_directory}/{new_dir}".strip("/")
                    if full_path in mock_file_system and isinstance(mock_file_system[full_path], list):
                        current_directory = full_path
                        response = b"Directory changed\r\n"
                    else:
                        response = b"Directory not found\r\n"
                except Exception as e:
                    response = f"Error changing directory: {str(e)}".encode('utf-8') + b'\r\n'
            else:
                response = b"Command not recognized\r\n"

            channel.send(response)
            channel.send(b'hpp$ ')
            command = b"" 


class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def chack_channel_request(self, kind, channel_id):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        
    def get_allowed_auth(self) -> str:
        return "password"
    
    def check_auth_password(self, username: str, password: str) -> int:
        if self.input_username is not None and self.input_password is not None:
            if username == 'admin' and password == 'admin':
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
            
    def check_channel_shell_reuest(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel: paramiko.Channel, term: bytes, width: int, height: int, pixelwidth: int, pixelheight: int, modes: bytes) -> bool:
        return True
    
    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        command = str(command)
        return True


def client_handle(aient, adresssm, username, password):
    pass