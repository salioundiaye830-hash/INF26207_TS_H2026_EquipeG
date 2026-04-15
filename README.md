# INF26207 – Travail de session – Les Sockets

Serveur de sauvegarde UDP fiable en Python 3.10+.

---

## Structure du projet

```
projet/
├── usocket.pyc          # Module fourni (non modifié)
├── usocket.pyi          # Signatures pour IntelliSense
├── protocol.py          # Définition du protocole applicatif
├── serveur.py           # Serveur de sauvegarde (port 4242)
├── client.py            # Console cliente interactive
├── config.ini           # Paramètres réseau et connexion
├── README.md            # Ce fichier
├── tests/               # Fichiers binaires de test (≥ 200 Kio)
└── sauvegardes/         # Fichiers reçus par le serveur
```

---

## Prérequis

- Python 3.10, 3.11 ou 3.12
- Renommer le fichier `.pyc` correspondant à votre version :
  - Python 3.10 → `usocket.310.pyc` → `usocket.pyc`
  - Python 3.11 → `usocket.311.pyc` → `usocket.pyc`
  - Python 3.12 → `usocket.312.pyc` → `usocket.pyc`

Aucune dépendance externe requise (stdlib uniquement).

---

## Lancer le serveur

```bash
cd projet/
python serveur.py
```

Le serveur écoute sur `127.0.0.1:4242` par défaut (configurable dans `config.ini`).

---

## Lancer le client

Dans un **autre terminal** :

```bash
cd projet/
python client.py
```

---

## Effectuer un transfert

Dans la console du client :

```
>> open 127.0.0.1          # Connexion au serveur (Three-Way Handshake)
>> ls                      # Liste des fichiers sur le serveur
>> put tests/fichier.bin   # Envoi du fichier vers le serveur
>> bye                     # Déconnexion propre
```

---

## Tester la reprise (resume)

1. Lancer un `put` d'un gros fichier.
2. Interrompre le client en cours de transfert (`Ctrl+C`).
3. Relancer `python client.py`, reconnecter avec `open`.
4. Utiliser la commande `resume` :

```
>> open 127.0.0.1
>> resume tests/fichier.bin
```

Le serveur indique le dernier segment reçu valide et le transfert reprend à partir de là.

---

## Vérifier l'intégrité du fichier

À la fin de chaque transfert réussi, le client **et** le serveur calculent et comparent le MD5 du fichier complet. Un message `✓ Transfert réussi – intégrité vérifiée` confirme que les deux copies sont identiques.

Pour vérifier manuellement :

```bash
# Linux / macOS
md5sum tests/fichier.bin
md5sum sauvegardes/fichier.bin

# Windows (PowerShell)
Get-FileHash tests\fichier.bin -Algorithm MD5
Get-FileHash sauvegardes\fichier.bin -Algorithm MD5
```

Les deux hachages doivent être identiques.

---

## Paramètres de configuration (`config.ini`)

| Paramètre            | Description                                           | Défaut |
|----------------------|-------------------------------------------------------|--------|
| `fiabilite`          | Probabilité de succès d'un envoi UDP (1.0 = parfait)  | 0.95   |
| `taux_corruption`    | Proportion de segments reçus corrompus                | 0.02   |
| `timeout`            | Secondes avant retransmission                         | 0.5    |
| `max_reprises`       | Tentatives max avant abandon                          | 10     |
| `client_mss_propose` | MSS proposé par le client (octets)                    | 1024   |
| `serveur_mss_propose`| MSS proposé par le serveur (octets)                   | 1024   |
| `n_propose`          | Fenêtre : nb de segments avant ACK                    | 4      |

> **Conseil** : pour les tests de performance, réduire `timeout` à `0.05`–`0.1` s.
> Pour le débogage initial, garder `timeout = 2.0`–`3.0` s.
