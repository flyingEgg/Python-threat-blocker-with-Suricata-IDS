# Python-based reactive IDS
Sistema di automazione della sicurezza di tipo "behavioral blocking", ovvero, sull'identificazione
di pattern comportamentali sospetti da parte di altri indirizzi IP con eventuale blocco.

## Autore
- **Giacomo Rossi** - [GitHub](https://github.com/flyingEgg)

## Funzionalità Principali

- **Lettura periodica log**: Vengono lette le signature nei log con frequenza secondo il refresh rate impostato
- al lancio.
- **Identificazione minaccia**: Basandosi sui dati ricavati dalle signature, viene consultato il file di configurazione
- `attacks_config.yaml` per determinare il tipo di attacco e la risposta adeguata.
- **Autenticazione API e blocco**: Via chiavi API salvate come variabili d'ambiente, si creano regole di firewall sulla
- base di quanto identificato.

## Requisiti

- **Python3+**

## Guida all'Installazione

1. **Clonare il repository**:
    ```bash
    git clone https://github.com/flyingEgg/Java-Pacman-MVC.git
    ```
2. **Navigare nella directory del progetto**:
    ```bash
    cd Java-Pacman-MVC
    ```
3. **Esecuzione**:
    ```bash
    python3 behavioral_blocker.py --host <host-address> --user <OPNsense-username> --rfsh <log-reading-refresh-rate>
    ```

## Utilizzo

Lanciare l'applicazione da riga di comando come indicato ed inserire la password corrispondente all'account OPNsense
inserito nel comando.