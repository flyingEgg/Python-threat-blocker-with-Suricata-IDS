

class Event:

    def __init__(self, line):
        self.type = line.get('event_type')
        self.timestamp = line.get('timestamp', '')
        self.interface = line.get('in_iface', '')
        self.ip = line.get('src_ip', '')
        self.dest_ip = line.get('dest_ip', '')
        self.signature = line.get('alert', {}).get('signature', '')
        self.dest_port = line.get('dest_port', '')

    def parse_timestamp(self):
        """Parsing del timestamp con conversione in oggetto datetime"""
        from dateutil import parser
        from datetime import datetime

        try:
            if self.timestamp:
                return parser.isoparse(self.timestamp)
            else:
                return datetime.now()
        except(ValueError, AttributeError):
            return datetime.now()

    def create_event_id(self):
        """Crea un id univoco basato su timestamp, ip e signature per evitare duplicati"""

        import hashlib
        unique_id = f"f{self.timestamp}_{self.ip}_{self.signature}_{self.dest_port}"
        return hashlib.md5(unique_id.encode()).hexdigest()


class EventFilter:
    def __init__(self, ip_addr):
        # Signatures di suricata da ignorare
        self.BENIGN_SIGNATURES = {
            "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management",
            "ET POLICY Outbound Debian APT User-Agent",
            "ET POLICY Ubuntu APT User-Agent",
            "ET USER_AGENTS Microsoft Device Metadata Retrieval Client User-Agent",
            "ET SCAN Non-Allowed Host Tried to Connect to MySQL Server",
            "GPL ICMP_INFO PING *NIX",
            "DISABLED"
        }

        self.SERVER_RESPONSES = {
            "ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point",
            "ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point",
            "ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point",
            "ET WEB_SERVER SQL Errors in HTTP 200 Response (error in your SQL syntax)",
            "ET ATTACK_RESPONSE Cisco TclShell TFTP Download"
        }

        self.WHITELIST_IPS = {ip_addr}

    def is_benign(self, event):
        """Restituisce True se l'evento va ignorato"""

        if event.ip in self.WHITELIST_IPS:
            return True

        if event.signature in self.BENIGN_SIGNATURES:
            return True

        return False

    def is_server_response(self, event):
        """Inverte indirizzo sorgente con indirizzo di destinazione"""

        if event.signature in self.SERVER_RESPONSES:
            event.ip = event.dest_ip