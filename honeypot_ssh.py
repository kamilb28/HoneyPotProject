import os
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
import signal
import sys

SSH_BANNER = "SSH-2.0-HPPServer_1.0"

if not os.path.exists('server.key'):
    print("Generating server RSA key...")
    key = paramiko.RSAKey.generate(2048)  # Generate a 2048-bit RSA key
    key.write_private_key_file('server.key')  # Save to server.key
    print("Server RSA key generated")

host_key = paramiko.RSAKey(filename='server.key')

log_dir = 'log'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

log = logging.getLogger('FunnelLogger')
log.setLevel(logging.INFO)
audit_handler = RotatingFileHandler(f'{log_dir}/audit.log', maxBytes=2000, backupCount=5)
audit_handler.setFormatter(log_formatter)
log.addHandler(audit_handler)

cmd_log = logging.getLogger('CmdAuditLogger')
cmd_log.setLevel(logging.INFO)
cmd_audit_handler = RotatingFileHandler(f'{log_dir}/cmd_audit.log', maxBytes=2000, backupCount=5)
cmd_audit_handler.setFormatter(log_formatter)
cmd_log.addHandler(cmd_audit_handler)

mock_file_system = {
    "": ["file1.txt", "file2.txt", "dir1"],
    "dir": ["file3.txt"],
    "file1.txt": "Content of file1",
    "file2.txt": "Content of file2",
    "dir1/file3.txt": "Content of file3",
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

            cmd_log.info(f"{client} attempted: {command.decode('utf-8')}")
            
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
                    response = b'\n' + b' '.join(f.encode('utf-8') for f in files) + b'\r\n'
                except Exception as e:
                    response = f"Error listing files: {str(e)}".encode('utf-8') + b'\r\n'
            elif command.startswith(b'cat'):
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
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, channel_id):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def get_allowed_auths(self, username) -> str:
        return "password"
    
    def check_auth_password(self, username: str, password: str) -> int:
        log.info(f'Connection from {self.client_ip}, username: {username}, password: {password}')
        cmd_log.info(f"{self.client_ip} attempted login with username: {username}, password: {password}")

        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL
            
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel: paramiko.Channel, term: bytes, width: int, height: int, pixelwidth: int, pixelheight: int, modes: bytes) -> bool:
        return True
    
    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        command = str(command)
        return True


def client_handle(client, adress, username, password):
    client_ip = adress[0]
    print(f"{client_ip} connected to server")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if not channel:
            print("chanel didn't open")

        channel.send("")
        shell(channel=channel, client=client_ip)
    except Exception as error:
        print("Error occured during connection to server")
        print(error)
    finally:
        try:
            transport.close()
        except Exception as error:
            print("Error occured during closing connection to server")
            print(error)


_socket = None

def signal_handler(sig, frame):
    global _socket
    print("\nReceived termination signal. Closing socket and shutting down the server.")
    if _socket:
        try:
            _socket.close()
            print("Socket closed successfully.")
        except Exception as e:
            print(f"Error while closing socket: {e}")
    sys.exit(0)

def honeypot(address, port, username, password):
    global _socket
    _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _socket.bind((address, port))

    _socket.listen(100)
    print(f"SSH server is listening on port {port}")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)

    while True:
        try:
            client, addr = _socket.accept()
            ssh_thred = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_thred.start()
        except Exception as error:
            print("Error while threading client")
            print(error)

# honeypot('127.0.0.1', 2222, 'admin', 'admin')
honeypot('127.0.0.1', 2222, username=None, password=None)
