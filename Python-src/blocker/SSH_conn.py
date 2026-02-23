"""
A simple class for SSH connection
"""

import paramiko
import socket

class SSHConn:
    def __init__(self, ssh_host, ssh_port, ssh_user, ssh_pass):
        self.ssh_client = None
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        

    def open(self):
        """Stabilisce una connessione SSH ad OPNsense e gestisco eventuali errori di connessione"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(self.ssh_host, self.ssh_port, self.ssh_user, self.ssh_pass, timeout=10)
            print(f"\nConnesso ad OPNsense ({self.ssh_host}) via SSH")
            return True
        except paramiko.AuthenticationException:
            print("\nErrore di autenticazione SSH")
            return False
        except socket.timeout:
            print("\nTimeout: host irraggiungibile")
            return False
        except paramiko.SSHException as e:
            print(f"\nErrore SSH: {e}")
            return False
        except Exception as e:
            print(f"\nErrore generale di connessione ad SSH: {e}")
            return False

    def close(self):
        """Chiude la connessione SSH"""
        self.ssh_client.close()
        print(f"\nConnessione SSH a {self.ssh_host} chiusa")