
class Threat:
    def __init__(self, caller_instance, device, interfaces_map, address, nr_alerts, atk_class, severity_level, api):
        self.caller = caller_instance
        self.device = device
        self.interfaces_map = interfaces_map
        self.src_ip = address
        self.nr_alerts = nr_alerts
        self.atk_class = atk_class
        self.severity_level = severity_level
        self.api = api

    def normalize_interface(self) -> str:
        s = self.device.strip().lower()
        if s in {"lan", "wan"} or s.startswith("opt") or s.startswith("wg"):
            return s
        return self.interfaces_map[self.device.strip()]


    def block_ip(self):
        """Bloccaggio di ip minaccioso mediante creazione apposita regola di firewall"""

        from datetime import datetime

        if self.caller.is_blocked(self.src_ip):
            return False

        print("\nMINACCIA RILEVATA")
        print(f"Ip: {self.src_ip}")
        print(f"Nr. di alerts: {self.nr_alerts}")
        print(f"Classe di attacchi: {self.atk_class}")
        print(f"Livello di minaccia: {self.severity_level}")

        # Bloccaggio dell'ip
        try:
            import requests
            import json
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            host = self.caller.connection.ssh_host
            url = f"https://{host}/api/firewall/filter/add_rule"

            # Payload con i dati della regola
            payload = {
                "rule": {
                    "enabled": "1",
                    "action": "block",
                    "quick": "1",
                    "interface": self.normalize_interface(),
                    "direction": "in",
                    "protocol": "any",
                    "source_net": self.src_ip,
                    "destination_net": "192.168.55.0/24",
                    "description": f"BLOCCO a causa di: {self.atk_class} -- alerts causati: {self.nr_alerts}",
                    "log": "1",
                }
            }

            # Chiamata API
            response = requests.post(
                url,
                auth=(self.api.key, self.api.secret),
                json=payload,
                verify=False,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("result") == "saved":
                    print(f"[{datetime.now()}] --> Creata regola per bloccare: {self.src_ip}")

                    # Applica le modifiche
                    apply_url = f"https://{host}/api/firewall/filter/apply"
                    apply_response = requests.post(apply_url, auth=(self.api.key, self.api.secret), verify=False)

                    if apply_response.status_code == 200:
                        print("OK")
                    else:
                        print("ERRORE: Configurazione non applicata")
                else:
                    print(f"Errore: {result}")
            else:
                print(f"Errore HTTP: {response.status_code} - {response.text}")

        except Exception as e:
            print(f"Errore: {e}")

        self.caller.blocked_ips.add(self.src_ip)

        self.caller.log_ip('blocked_ips.log', self.src_ip, self)

        return True
