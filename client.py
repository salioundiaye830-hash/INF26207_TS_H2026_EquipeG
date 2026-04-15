"""
client.py – Client de sauvegarde INF26207-TS
=============================================
Console interactive pour se connecter au serveur de sauvegarde.

Commandes disponibles :
    open <adresse_ip>       – Connexion au serveur
    ls                      – Liste des fichiers sur le serveur
    put <nom_fichier>       – Envoi d'un fichier vers le serveur
    resume <nom_fichier>    – Reprise d'un transfert interrompu
    bye                     – Déconnexion

Lancement :
    python client.py
"""

import os
import sys
import configparser
import hashlib
import socket
import struct
from socket import AF_INET, SOCK_DGRAM

from usocket import usocket
from protocol import (
    construire_segment, analyser_segment,
    encoder_commande, decoder_commande,
    MSG_SYN, MSG_SYNACK, MSG_ACK, MSG_DATA, MSG_FIN, MSG_FINACK,
    MSG_CMD, MSG_RESP, MSG_ERR, MSG_NACK,
    HANDSHAKE_FMT, HANDSHAKE_SIZE,
    MSG_NAMES,
)

# ── Chargement de la configuration ──────────────────────────────────────────────

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

FIABILITE        = config.getfloat("RESEAU", "fiabilite",       fallback=0.95)
TAUX_CORRUPTION  = config.getfloat("RESEAU", "taux_corruption", fallback=0.02)
TIMEOUT          = config.getfloat("RESEAU", "timeout",         fallback=0.5)
MAX_REPRISES     = config.getint  ("RESEAU", "max_reprises",     fallback=10)
MSS_CLIENT       = config.getint  ("CONNEXION", "client_mss_propose", fallback=1024)
N_PROPOSE        = config.getint  ("CONNEXION", "n_propose",    fallback=4)
PORT_SERVEUR     = config.getint  ("SERVEUR",  "port",           fallback=4242)

# Taille du buffer de réception UDP
BUF_SIZE = 65535


def log(msg: str) -> None:
    """Affichage console horodaté."""
    import datetime
    print(f"[CLIENT  {datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}")


# ── Classe principale du client ──────────────────────────────────────────────────

class ClientSauvegarde:
    def __init__(self):
        # Socket non fiable
        self.sock = usocket(
            family=AF_INET,
            type=SOCK_DGRAM,
            fiabilite=FIABILITE,
            taux_corruption=TAUX_CORRUPTION,
        )
        self.sock.settimeout(TIMEOUT)

        # Paramètres de session (mis à jour lors du handshake)
        self.mss = MSS_CLIENT
        self.n   = N_PROPOSE
        self.addr_serveur = None   # (ip, port) du serveur
        self.connecte = False

    # ── Envoi / réception ───────────────────────────────────────────────────────

    def _envoyer(self, data: bytes) -> None:
        """Envoie des bytes bruts vers le serveur."""
        self.sock.sendto(data, self.addr_serveur)

    def _recevoir(self, timeout: float = None):
        """
        Attend un segment valide du serveur.
        Retourne (type_msg, seq, ack, payload).
        Lève socket.timeout si le délai expire.
        Les segments corrompus sont ignorés.
        """
        t = timeout if timeout is not None else TIMEOUT
        self.sock.settimeout(t)
        while True:
            try:
                raw, addr = self.sock.recvfrom(BUF_SIZE)
            except socket.timeout:
                raise

            if addr != self.addr_serveur:
                continue  # Ignorer les paquets d'autres sources

            try:
                return analyser_segment(raw)
            except ValueError as e:
                log(f"Segment corrompu ignoré : {e}")
                continue

    def _envoyer_avec_ack(self, segment: bytes, ack_attendu_type: int,
                          tentatives: int = MAX_REPRISES) -> tuple:
        """
        Envoie un segment et attend une réponse du type indiqué.
        Retransmets si timeout. Lève RuntimeError après max_reprises échecs.
        """
        for tentative in range(tentatives):
            self._envoyer(segment)
            try:
                type_msg, seq, ack, payload = self._recevoir()
                if type_msg == ack_attendu_type:
                    return type_msg, seq, ack, payload
                # Si on reçoit un ERR, on abandonne
                if type_msg == MSG_ERR:
                    raise RuntimeError(f"Erreur serveur : {payload.decode('utf-8', errors='replace')}")
            except socket.timeout:
                log(f"Timeout (tentative {tentative + 1}/{tentatives})")

        raise RuntimeError(f"Abandon après {tentatives} tentatives sans réponse")

    # ── Three-Way Handshake (côté client) ───────────────────────────────────────

    def _handshake(self) -> bool:
        """
        Initie le handshake TCP-like :
            1. Envoie SYN avec MSS + N proposés
            2. Attend SYNACK avec paramètres négociés
            3. Envoie ACK de confirmation
        Retourne True si connexion établie.
        """
        # Payload SYN : MSS proposé + N proposé
        params = struct.pack(HANDSHAKE_FMT, MSS_CLIENT, N_PROPOSE)
        syn = construire_segment(MSG_SYN, 0, 0, params)

        log(f"Envoi SYN → {self.addr_serveur} (MSS={MSS_CLIENT}, N={N_PROPOSE})")

        for tentative in range(MAX_REPRISES):
            self._envoyer(syn)
            try:
                type_msg, seq, ack, payload = self._recevoir()
                if type_msg == MSG_SYNACK and len(payload) >= HANDSHAKE_SIZE:
                    # Extraire les paramètres négociés
                    self.mss, self.n = struct.unpack(HANDSHAKE_FMT, payload[:HANDSHAKE_SIZE])
                    log(f"SYNACK reçu – MSS={self.mss}, N={self.n}")
                    # Envoyer le ACK final
                    ack_final = construire_segment(MSG_ACK, 0, 1)
                    self._envoyer(ack_final)
                    return True
            except socket.timeout:
                log(f"Timeout SYN (tentative {tentative + 1}/{MAX_REPRISES})")

        log("Échec du handshake")
        return False

    # ── Commande open ────────────────────────────────────────────────────────────

    def cmd_open(self, adresse_ip: str) -> None:
        """Initie une connexion au serveur à l'adresse donnée."""
        if self.connecte:
            print("Déjà connecté. Utilisez 'bye' d'abord.")
            return

        self.addr_serveur = (adresse_ip, PORT_SERVEUR)
        if self._handshake():
            self.connecte = True
            print(f"Connexion établie avec {adresse_ip}:{PORT_SERVEUR}")
        else:
            print("Impossible de se connecter au serveur.")
            self.addr_serveur = None

    # ── Commande ls ──────────────────────────────────────────────────────────────

    def cmd_ls(self) -> None:
        """Demande la liste des fichiers au serveur."""
        if not self.connecte:
            print("Non connecté. Utilisez 'open <ip>' d'abord.")
            return

        cmd = construire_segment(MSG_CMD, 0, 0, encoder_commande("ls"))
        try:
            _, _, _, payload = self._envoyer_avec_ack(cmd, MSG_RESP)
            print("Fichiers sur le serveur :")
            print(payload.decode("utf-8"))
        except RuntimeError as e:
            print(f"Erreur : {e}")

    # ── Envoi d'un fichier (put) ─────────────────────────────────────────────────

    def _envoyer_fichier(self, chemin: str, nom_fichier: str, offset_segments: int = 0) -> None:
        """
        Découpe le fichier en segments de self.mss octets et les envoie
        par fenêtres de self.n segments. Retransmets en cas de NACK / timeout.

        Args:
            chemin           : chemin local du fichier
            nom_fichier      : nom utilisé sur le serveur
            offset_segments  : numéro du premier segment à envoyer (reprise)
        """
        taille = os.path.getsize(chemin)
        offset_octets = offset_segments * self.mss
        total_segments = (taille + self.mss - 1) // self.mss  # arrondi supérieur
        seq_courant = offset_segments

        log(f"Envoi '{nom_fichier}' : {taille} octets, "
            f"{total_segments} segments, MSS={self.mss}, N={self.n}, "
            f"offset={offset_segments}")

        # Attendre le ACK initial du serveur (prêt à recevoir)
        try:
            type_msg, _, ack_init, _ = self._recevoir(timeout=TIMEOUT * 5)
            if type_msg != MSG_ACK:
                log(f"Réponse inattendue du serveur : {MSG_NAMES.get(type_msg, '?')}")
                return
            seq_courant = ack_init  # Le serveur indique à partir d'où il veut
            log(f"Serveur prêt, reprise au segment {seq_courant}")
        except socket.timeout:
            log("Timeout en attente du ACK initial du serveur")
            return

        with open(chemin, "rb") as f:
            # Aller à la position correspondant à offset_segments
            f.seek(seq_courant * self.mss)

            while seq_courant < total_segments:
                # Préparer une fenêtre de min(N, restant) segments
                segments_a_envoyer = []
                for i in range(self.n):
                    if seq_courant + i >= total_segments:
                        break
                    chunk = f.read(self.mss)
                    if not chunk:
                        break
                    seg = construire_segment(MSG_DATA, seq_courant + i, 0, chunk)
                    segments_a_envoyer.append((seq_courant + i, seg, chunk))

                if not segments_a_envoyer:
                    break

                # Retransmission de la fenêtre jusqu'à ACK valide
                reprises = 0
                while reprises < MAX_REPRISES:
                    # Envoi de toute la fenêtre
                    for _, seg, _ in segments_a_envoyer:
                        self._envoyer(seg)

                    # Attente de l'ACK cumulatif
                    try:
                        type_msg, _, ack_val, _ = self._recevoir()
                    except socket.timeout:
                        reprises += 1
                        log(f"Timeout ACK fenêtre (reprise {reprises}/{MAX_REPRISES})")
                        continue

                    if type_msg == MSG_ACK:
                        if ack_val > seq_courant:
                            # Avancement de la fenêtre
                            # Repositionner le curseur fichier si ACK partiel
                            avance = ack_val - seq_courant
                            seq_courant = ack_val
                            # Relire si ACK partiel (certains segments non reçus)
                            if avance < len(segments_a_envoyer):
                                f.seek(seq_courant * self.mss)
                            break
                        else:
                            # ACK en retard ou doublon → retransmettre
                            reprises += 1
                    elif type_msg == MSG_NACK:
                        reprises += 1
                        log(f"NACK reçu, retransmission (reprise {reprises}/{MAX_REPRISES})")
                    else:
                        reprises += 1
                else:
                    log(f"Abandon : {MAX_REPRISES} tentatives consécutives sans ACK")
                    return

                # Barre de progression simple
                pct = int(100 * seq_courant / total_segments)
                print(f"\r  Progression : {pct:3d}%  [{seq_courant}/{total_segments} segments]",
                      end="", flush=True)

        print()  # Saut de ligne après la progression

        # Envoi du FIN pour signaler la fin du fichier
        fin = construire_segment(MSG_FIN, seq_courant, 0)
        log("Envoi FIN (fin de fichier)")

        for tentative in range(MAX_REPRISES):
            self._envoyer(fin)
            try:
                type_msg, _, _, payload = self._recevoir()
                if type_msg == MSG_FINACK:
                    md5_serveur = payload.decode("utf-8", errors="ignore")
                    # Vérification MD5 locale
                    md5_local = hashlib.md5(open(chemin, "rb").read()).hexdigest()
                    if md5_serveur == md5_local:
                        print(f"✓ Transfert réussi – intégrité vérifiée (MD5 : {md5_local})")
                    else:
                        print(f"⚠ Attention : MD5 différent ! Local={md5_local}, Serveur={md5_serveur}")
                    return
            except socket.timeout:
                log(f"Timeout FINACK (tentative {tentative + 1}/{MAX_REPRISES})")

        log("Fin de transfert non confirmée par le serveur")

    def cmd_put(self, nom_fichier: str) -> None:
        """Envoie un fichier local vers le serveur."""
        if not self.connecte:
            print("Non connecté. Utilisez 'open <ip>' d'abord.")
            return

        chemin = os.path.join(os.path.dirname(__file__), nom_fichier)
        if not os.path.isfile(chemin):
            print(f"Fichier introuvable : {chemin}")
            return

        # Signaler au serveur le début d'un put
        cmd_payload = encoder_commande(f"put {nom_fichier}")
        cmd_seg = construire_segment(MSG_CMD, 0, 0, cmd_payload)

        try:
            _, _, _, payload = self._envoyer_avec_ack(cmd_seg, MSG_ACK)
            if payload == b"PUT_OK":
                self._envoyer_fichier(chemin, nom_fichier, offset_segments=0)
        except RuntimeError as e:
            print(f"Erreur lors du put : {e}")

    # ── Commande resume ──────────────────────────────────────────────────────────

    def cmd_resume(self, nom_fichier: str) -> None:
        """
        Reprend un transfert interrompu.
        Demande au serveur à quel segment reprendre, puis envoie à partir de là.
        """
        if not self.connecte:
            print("Non connecté. Utilisez 'open <ip>' d'abord.")
            return

        chemin = os.path.join(os.path.dirname(__file__), nom_fichier)
        if not os.path.isfile(chemin):
            print(f"Fichier introuvable : {chemin}")
            return

        # Envoyer la commande resume au serveur
        cmd_payload = encoder_commande(f"resume {nom_fichier}")
        cmd_seg = construire_segment(MSG_CMD, 0, 0, cmd_payload)

        try:
            _, _, _, payload = self._envoyer_avec_ack(cmd_seg, MSG_RESP)
            reponse = payload.decode("utf-8")
            if reponse.startswith("RESUME:"):
                offset = int(reponse.split(":")[1])
                log(f"Reprise demandée à partir du segment {offset}")
                self._envoyer_fichier(chemin, nom_fichier, offset_segments=offset)
            else:
                print(f"Réponse inattendue du serveur : {reponse}")
        except RuntimeError as e:
            print(f"Erreur lors du resume : {e}")
        except ValueError as e:
            print(f"Réponse invalide du serveur : {e}")

    # ── Commande bye ─────────────────────────────────────────────────────────────

    def cmd_bye(self) -> None:
        """Ferme la connexion avec le serveur."""
        if not self.connecte:
            print("Non connecté.")
            return

        cmd = construire_segment(MSG_CMD, 0, 0, encoder_commande("bye"))
        try:
            self._envoyer_avec_ack(cmd, MSG_FINACK)
            print("Connexion fermée.")
        except RuntimeError:
            print("Connexion fermée (sans confirmation du serveur).")
        finally:
            self.connecte = False
            self.addr_serveur = None

    # ── Boucle interactive ───────────────────────────────────────────────────────

    def executer(self) -> None:
        """Boucle REPL du client."""
        print("Client de sauvegarde INF26207-TS")
        print("Commandes : open <ip>  ls  put <fichier>  resume <fichier>  bye  exit\n")

        while True:
            try:
                ligne = input(">> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                if self.connecte:
                    self.cmd_bye()
                break

            if not ligne:
                continue

            parties = ligne.split(maxsplit=1)
            commande = parties[0].lower()
            argument = parties[1] if len(parties) > 1 else ""

            if commande == "open":
                if not argument:
                    print("Usage : open <adresse_ip>")
                else:
                    self.cmd_open(argument)

            elif commande == "ls":
                self.cmd_ls()

            elif commande == "put":
                if not argument:
                    print("Usage : put <nom_fichier>")
                else:
                    self.cmd_put(argument)

            elif commande == "resume":
                if not argument:
                    print("Usage : resume <nom_fichier>")
                else:
                    self.cmd_resume(argument)

            elif commande == "bye":
                self.cmd_bye()

            elif commande in ("exit", "quit", "q"):
                if self.connecte:
                    self.cmd_bye()
                print("Au revoir!")
                break

            else:
                print(f"Commande inconnue : '{commande}'")
                print("Commandes : open <ip>  ls  put <fichier>  resume <fichier>  bye  exit")


# ── Point d'entrée ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    client = ClientSauvegarde()
    try:
        client.executer()
    finally:
        client.sock.close()
