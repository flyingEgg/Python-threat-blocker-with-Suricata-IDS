import json
import sys
import time
import yaml
from collections import defaultdict, Counter
from datetime import datetime, timezone

from api import API
from event import EventFilter
from dotenv import load_dotenv
from threat import Threat


def obtain_password():
    try:
        p = getpass.getpass(prompt='Password: ', stream=None)
        return p
    except KeyboardInterrupt:
        print("\nAutenticazione interrotta dall'utente (^C)\n")
        sys.exit(1)

def configure():
    load_dotenv()

def load_attack_config(path):
    with open(path, 'r') as f:
        data = yaml.safe_load(f)
    return data


class BehavioralBlocker:
    def __init__(self, ssh_conn, alrt_rfsh):

        self.connection = ssh_conn
        self.api = API()

        # Datasets per behavioural analysis
        self.ip_alerts = defaultdict(list)
        self.ip_attack_types = defaultdict(Counter)
        self.devices = defaultdict(set)
        self.blocked_ips = set()

        # Duplicazioni
        self.processed_events = set()
        self.last_event_time = None

        # Soglie
        self.ALERT_REFRESH = alrt_rfsh  # frequenza di aggiornamento dal log
        self.event_filter = EventFilter(self.connection.ssh_host)
        self.tot_events = 0

        self.ip_policy = {}
        self.config = load_attack_config('attacks_config.yaml')

        print("Behavioral Blocker avviato\n")
        print(f"refresh rate: {self.ALERT_REFRESH} secondi\n")

    def get_interfaces(self, verify_tls: bool = False):
        """Restituisce un dizionario in cui ad ogni codice dispositivo
        vi e' mappata la sua corrispondente interfaccia"""
        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        url = f"https://{self.connection.ssh_host}/api/interfaces/overview/interfacesInfo"
        r = requests.get(url, auth=(self.api.key, self.api.secret), verify=verify_tls, timeout=10)
        r.raise_for_status()
        data = r.json()

        interfaces = {}
        for row in data.get("rows", []):
            dev = row.get("device")
            ident = row.get("identifier")
            if dev and ident:
                interfaces[str(dev)] = str(ident).lower()

        if not interfaces:
            raise RuntimeError(f"Non e' stato possibile trovare un mapping dispositivo->interfaccia"
                               f" nelle chiavi di risposta: {list(data.keys())}")

        return interfaces

    def fetch_recent_events(self, lines=200):
        """Restituisce una lista degli ultimi 200 eventi dal log,
        se vi sono errori di lettura restituisco la lista vuota"""

        from event import Event

        try:
            cutoff = self.last_event_time
            nr_lines = "500" if cutoff else lines
            cmd = f'tail -n {nr_lines} /var/log/suricata/eve.json'
            # if self.last_event_time:
            #     cmd += ' | grep -v "^$"'

            stdin, stdout, stderr = self.connection.ssh_client.exec_command(cmd)

            out = stdout.read().decode(errors="ignore")
            err = stderr.read().decode(errors="ignore")

            if err.strip():
                print("[SSH STDERR]", err.strip()[:200])
                return []

            lines_list = [l for l in out.splitlines() if l.strip()]
            events = []


            max_time = cutoff

            for s in lines_list:
                try:
                    event = Event(json.loads(s))
                    if event.type != "alert":
                        continue

                    event_id = event.create_event_id()
                    if event_id in self.processed_events:
                        continue

                    event_time = event.parse_timestamp()

                    if cutoff and event_time <= cutoff:
                        continue

                    events.append(event)
                    self.processed_events.add(event_id)
                    self.tot_events += 1

                    if (max_time is None) or (event_time > max_time):
                        max_time = event_time

                except Exception as e:
                    continue
            if max_time and (self.last_event_time is None or max_time > self.last_event_time):
                self.last_event_time = max_time


            if len(events) == 1:
                print(f"[{datetime.now()}] --> Recuperato {len(events)} evento nuovo"
                      f" da analizzare (eventi totali: {self.tot_events})")
            else:
                print(f"[{datetime.now()}] --> Recuperati {len(events)} eventi nuovi"
                      f" da analizzare (eventi totali: {self.tot_events})")

            return events

        except Exception as e:
            print(f"Errore di lettura log: {e}")
            return []

    def is_blocked(self, ip_addr):
        with open('blocked_ips.log') as f:
            for line in f:
                if ip_addr in line:
                    return True

    def analyze_events(self, events):
        """Analizza gli eventi basandosi sui pattern di comportamento"""

        import re

        threats = []

        # Salta eventi malformati senza campo 'src_ip'
        for event in events:
            src_ip = event.ip
            if not src_ip:
                continue

            # Salta eventi non malevoli (es apt update del server)
            if self.event_filter.is_benign(event):
                continue

            self.event_filter.is_server_response(event)

            # Parsing del timestamp con conversione in oggetto datetime
            event_time = event.parse_timestamp()

            # Analisi del tipo di attacco
            signature = event.signature.lower()


            attack_definitions = self.config.get('attacks_definitions', {})

            # Classifico il tipo di attacco
            def get_attack(atk_signature):
                for attack_name, attack_data in attack_definitions.items():     # Itera intorno ogni definizione di attacco
                    for pattern in attack_data['signatures']:                   # Itera intorno ogni firma definita di un attacco
                        if re.search(pattern, atk_signature, re.IGNORECASE):
                            return {
                                'attack_type': attack_data['attack_type'],
                                'time_window': attack_data['time_window'],
                                'threshold': attack_data['threshold'],
                                'severity': attack_data['severity']
                            }
                return {
                    'attack_type': 'unknown',
                    'time_window': 300,
                    'threshold': 10,
                    'severity': 'LOW'
                }


            attack = get_attack(signature)

            self.ip_policy[src_ip] = {
                'time_window': attack['time_window'],
                'threshold': attack['threshold'],
                'attack_type': attack['attack_type']
            }

            # Salvo l'alert
            self.ip_alerts[src_ip].append(event_time)
            self.ip_attack_types[src_ip][attack['attack_type']] += 1
            self.devices[src_ip] = event.interface

            # print(f"{attack['threshold']} - {attack['time_window']}")
        interfacesmap = self.get_interfaces(False)

        for ip in self.ip_alerts:
            if self.is_blocked(ip):
                continue

            policy = self.ip_policy.get(ip, {'time_window': 300, 'threshold': 10, 'attack_type': 'unknown'})
            tw = policy['time_window']          # Time window
            th = policy['threshold']            # Soglia

            recent_alerts = [t for t in self.ip_alerts[ip]
                             if (datetime.now(timezone.utc) - t).total_seconds() <= tw]
            # print(f"(Debug) - {len(recent_alerts)}, {th}")
            # Se il numero di alerts di un IP supera la soglia impostata, scatta la blacklist di esso
            if len(recent_alerts) >= th:
                device = self.devices.get(ip, None)
                alert_count = len(recent_alerts)
                attack_types = dict(self.ip_attack_types[ip])
                severity_level = 'ALTO' if len(recent_alerts) >= th else 'MEDIO'

                # Costruisce un nuovo oggetto Threat con tutti i dettagli della minaccia
                threat = Threat(self,
                                (device if attack['attack_type'] != 'mitm' else 'opt3'),
                                interfacesmap,
                                ip,
                                alert_count,
                                attack_types,
                                severity_level,
                                self.api)

                # print(f"{attack['threshold']} - {attack['time_window']}")
                threats.append(threat)

        return threats

    def log_ip(self, logfile_name, ip, threat):
        with open(logfile_name, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {ip} - {threat.nr_alerts} alerts\n")


    def continuous_monitoring(self, connected):
        """Monitora gli alerts, con periodici aggiornamenti sino interruzione dell'utente"""
        try:
            while True:
                if not connected:
                    print("Connessione SSH fallita! Riprovo tra 30 secondi...")
                    time.sleep(30)
                    continue

                events = self.fetch_recent_events()

                if events:
                    threats = self.analyze_events(events)

                    for threat in threats:
                        if threat.severity_level == 'ALTO':
                            threat.block_ip()
                        else:
                            print(
                                f"Indirizzo {threat.src_ip} sotto osservazione ({threat.nr_alerts} alerts generati)")

                            self.log_ip('suspicious_ips.log', threat.src_ip, threat)

                time.sleep(self.ALERT_REFRESH)
        except KeyboardInterrupt:
            self.connection.close()
            pass


if __name__ == "__main__":
    import argparse
    import getpass
    from SSH_conn import SSHConn

    parser = argparse.ArgumentParser(description='Sistema di protezione ed analisi comportamentale')

    parser.add_argument('--host', help='OPNsense IP addr (default: 192.168.1.250)', default='192.168.1.250')
    parser.add_argument('--port', type=int, help='SSH port (default: 22)', default=22)
    parser.add_argument('--user', type=str, help='Username', default='root')
    parser.add_argument('--rfsh', type=int, help='Refresh rate lettura log', default=10)

    args = parser.parse_args()


    password = obtain_password()
    while True:
        connection = SSHConn(args.host, args.port, args.user, password)
        connected = connection.open()

        if connected:
            break
        password = obtain_password()


    print("Host: ", args.host, "\nPorta: ", args.port, "\nUtente: ", args.user, "\n")
    configure()  # Dotenv

    protection_sys = BehavioralBlocker(connection, alrt_rfsh=args.rfsh)

    if connected:
        protection_sys.continuous_monitoring(connected)
