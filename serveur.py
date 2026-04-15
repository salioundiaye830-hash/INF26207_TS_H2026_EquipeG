"""
serveur.py – Serveur de sauvegarde INF26207-TS
===============================================
Écoute sur le port 4242 (UDP).
Accepte une connexion client à la fois, gère les commandes ls, put, bye, resume.
Enregistre les fichiers reçus dans ./sauvegardes/.

Lancement :
    python serveur.py
"""

import os
import sys
import configparser
import hashlib
import socket
import struct
import threading
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

FIABILITE       = config.getfloat("RESEAU", "fiabilite",       fallback=0.95)
TAUX_CORRUPTION = config.getfloat("RESEAU", "taux_corruption", fallback=0.02)
TIMEOUT         = config.getfloat("RESEAU", "timeout",         fallback=0.5)
MAX_REPRISES    = config.getint  ("RESEAU", "max_reprises",     fallback=10)
MSS_SERVEUR     = config.getint  ("CONNEXION", "serveur_mss_propose", fallback=1024)
N_PROPOSE       = config.getint  ("CONNEXION", "n_propose",     fallback=4)
HOTE_SERVEUR    = config.get     ("SERVEUR",  "hote",           fallback="127.0.0.1")
PORT_SERVEUR    = config.getint  ("SERVEUR",  "port",           fallback=4242)
DOSSIER_SAUVEGARDE = os.path.join(os.path.dirname(__file__), "sauvegardes")

# ── Taille du buffer de réception UDP ───────────────────────────────────────────
# On réserve assez pour l'en-tête (16 o) + MSS max (65535 o pour UDP)
BUF_SIZE = 65535


def log(msg: str) -> None:
    """Affichage console horodaté."""
    import datetime
    print(f"[SERVEUR {datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}")


# ── Classe principale du serveur ─────────────────────────────────────────────────

class ServeurSauvegarde:
    def __init__(self):
        # Création du dossier de sauvegarde si nécessaire
        os.makedirs(DOSSIER_SAUVEGARDE, exist_ok=True)

        # Socket non fiable (simule pertes + corruption)
        self.sock = usocket(
            family=AF_INET,
            type=SOCK_DGRAM,
            fiabilite=FIABILITE,
            taux_corruption=TAUX_CORRUPTION,
        )
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOTE_SERVEUR, PORT_SERVEUR))
        self.sock.settimeout(None)  # Bloquant pour recvfrom initial

        # Paramètres de session négociés lors du handshake
        self.mss = MSS_SERVEUR       # Taille max des données utiles par segment
        self.n   = N_PROPOSE         # Fenêtre : nb de segments avant ACK
        self.addr_client = None      # Adresse (ip, port) du client actif

    # ── Envoi fiable (avec retransmission) ──────────────────────────────────────

    def _envoyer(self, data: bytes) -> None:
        """Envoie des bytes bruts vers le client actif (sans gestion de perte ici)."""
        self.sock.sendto(data, self.addr_client)

    def _recevoir(self, timeout: float = TIMEOUT):
        """
        Attend un segment du client actif.
        Retourne (type_msg, seq, ack, payload) ou lève socket.timeout.
        Les segments corrompus sont ignorés silencieusement (NACK implicite).
        """
        self.sock.settimeout(timeout)
        while True:
            try:
                raw, addr = self.sock.recvfrom(BUF_SIZE)
            except socket.timeout:
                raise

            # Ignorer les paquets d'autres adresses (pas de client actif attendu)
            if self.addr_client and addr != self.addr_client:
                continue

            try:
                return analyser_segment(raw)
            except ValueError as e:
                # Segment corrompu → on envoie un NACK et on attend le prochain
                log(f"Segment corrompu ignoré : {e}")
                if self.addr_client:
                    nack = construire_segment(MSG_NACK, 0, 0)
                    self._envoyer(nack)
                continue

    # ── Three-Way Handshake (côté serveur) ──────────────────────────────────────

    def _handshake(self, syn_payload: bytes, addr) -> bool:
        """
        Reçoit un SYN, répond SYNACK avec les paramètres négociés (min des deux MSS).
        Attend le ACK final du client.
        Retourne True si la connexion est établie.
        """
        self.addr_client = addr

        # Décoder MSS et N proposés par le client
        if len(syn_payload) >= HANDSHAKE_SIZE:
            client_mss, client_n = struct.unpack(HANDSHAKE_FMT, syn_payload[:HANDSHAKE_SIZE])
        else:
            client_mss, client_n = MSS_SERVEUR, N_PROPOSE

        # Négociation : on prend le minimum des deux propositions
        self.mss = min(client_mss, MSS_SERVEUR)
        self.n   = min(client_n,   N_PROPOSE)
        log(f"Connexion de {addr} – MSS négocié={self.mss}, N={self.n}")

        # Envoi du SYNACK avec les paramètres négociés
        params = struct.pack(HANDSHAKE_FMT, self.mss, self.n)
        synack = construire_segment(MSG_SYNACK, 0, 1, params)

        # Retransmission du SYNACK si le ACK final tarde
        for tentative in range(MAX_REPRISES):
            self._envoyer(synack)
            try:
                type_msg, seq, ack, payload = self._recevoir(timeout=TIMEOUT)
                if type_msg == MSG_ACK:
                    log("Connexion établie (ACK reçu)")
                    return True
            except socket.timeout:
                log(f"Timeout SYNACK (tentative {tentative + 1}/{MAX_REPRISES})")

        log("Échec du handshake – abandon")
        self.addr_client = None
        return False

    # ── Commande ls ─────────────────────────────────────────────────────────────

    def _cmd_ls(self) -> None:
        """Liste les fichiers dans ./sauvegardes/ et les envoie au client."""
        fichiers = os.listdir(DOSSIER_SAUVEGARDE)
        if fichiers:
            liste = "\n".join(fichiers)
        else:
            liste = "(aucun fichier)"
        resp = construire_segment(MSG_RESP, 0, 0, liste.encode("utf-8"))
        self._envoyer(resp)
        log(f"ls → {len(fichiers)} fichier(s)")

    # ── Réception d'un fichier (commande put / resume) ──────────────────────────

    def _recevoir_fichier(self, nom_fichier: str, offset_segments: int = 0) -> None:
        """
        Reçoit un fichier segment par segment avec fenêtrage.

        Args:
            nom_fichier      : nom du fichier à sauvegarder
            offset_segments  : numéro du premier segment attendu (0 = nouveau transfert,
                               >0 = reprise / resume).
        """
        chemin = os.path.join(DOSSIER_SAUVEGARDE, nom_fichier)

        # Mode d'ouverture : append si reprise, write sinon
        mode = "ab" if offset_segments > 0 else "wb"
        prochain_attendu = offset_segments   # ACK cumulatif (numéro du prochain segment)
        transfert_termine = False
        total_octets = 0

        log(f"Début réception '{nom_fichier}' (offset={offset_segments})")

        # Envoi du signal de prêt au client : ACK avec le numéro du prochain segment voulu
        ack_msg = construire_segment(MSG_ACK, 0, prochain_attendu)
        self._envoyer(ack_msg)

        with open(chemin, mode) as f:
            while not transfert_termine:
                # Réception d'une fenêtre de N segments
                segments_fenetre = {}   # seq → payload

                for _ in range(self.n):
                    try:
                        type_msg, seq, ack, payload = self._recevoir(timeout=TIMEOUT * 3)
                    except socket.timeout:
                        # Timeout fenêtre → on ré-acquitte le dernier bon segment
                        log(f"Timeout fenêtre, renvoi ACK {prochain_attendu}")
                        break

                    if type_msg == MSG_FIN:
                        # Fin de transfert signalée par le client
                        transfert_termine = True
                        break

                    if type_msg == MSG_NACK:
                        # Le client nous signale un problème (inhabituel depuis client)
                        break

                    if type_msg != MSG_DATA:
                        continue

                    # Doublon : segment déjà acquitté → ignoré
                    if seq < prochain_attendu:
                        log(f"Doublon ignoré : seq={seq}")
                        continue

                    # Segment dans la fenêtre courante → mis en tampon
                    if seq not in segments_fenetre:
                        segments_fenetre[seq] = payload

                # Écrire les segments consécutifs reçus à partir de prochain_attendu
                while prochain_attendu in segments_fenetre:
                    data_seg = segments_fenetre.pop(prochain_attendu)
                    f.write(data_seg)
                    total_octets += len(data_seg)
                    prochain_attendu += 1

                # Envoyer l'ACK cumulatif (= prochain segment attendu)
                ack_msg = construire_segment(MSG_ACK, 0, prochain_attendu)
                self._envoyer(ack_msg)

        if transfert_termine:
            # Confirmer la fin avec FINACK + hash MD5 pour vérification
            md5 = hashlib.md5(open(chemin, "rb").read()).hexdigest()
            log(f"Transfert '{nom_fichier}' terminé : {total_octets} octets, MD5={md5}")
            # Envoyer le FINACK plusieurs fois pour compenser les pertes éventuelles
            finack = construire_segment(MSG_FINACK, 0, prochain_attendu, md5.encode())
            for _ in range(5):
                self._envoyer(finack)
        else:
            log(f"Transfert '{nom_fichier}' interrompu après {total_octets} octets")

    # ── Gestion de la reprise (resume) ──────────────────────────────────────────

    def _cmd_resume(self, nom_fichier: str) -> None:
        """
        Indique au client à partir de quel segment le serveur peut reprendre.
        Calcule l'offset en segments complets déjà reçus.
        """
        chemin = os.path.join(DOSSIER_SAUVEGARDE, nom_fichier)
        if os.path.exists(chemin):
            taille_actuelle = os.path.getsize(chemin)
            # Nombre de segments complets déjà reçus
            segments_ok = taille_actuelle // self.mss
            log(f"Resume '{nom_fichier}' : {taille_actuelle} octets, reprise au segment {segments_ok}")
            reponse = f"RESUME:{segments_ok}".encode("utf-8")
            resp = construire_segment(MSG_RESP, 0, 0, reponse)
            self._envoyer(resp)
            # Reprendre la réception à partir du segment segments_ok
            self._recevoir_fichier(nom_fichier, offset_segments=segments_ok)
        else:
            # Fichier inconnu → reprise depuis le début
            reponse = "RESUME:0".encode("utf-8")
            resp = construire_segment(MSG_RESP, 0, 0, reponse)
            self._envoyer(resp)
            self._recevoir_fichier(nom_fichier, offset_segments=0)

    # ── Boucle de traitement des commandes ──────────────────────────────────────

    def _traiter_commandes(self) -> None:
        """
        Boucle principale de session client.
        Lit les commandes CMD et dispatch vers les handlers.
        """
        log("Session ouverte, attente de commandes")
        while True:
            try:
                type_msg, seq, ack, payload = self._recevoir(timeout=None)
            except socket.timeout:
                continue
            except OSError:
                break

            if type_msg == MSG_CMD:
                cmd = decoder_commande(payload).strip()
                log(f"Commande reçue : '{cmd}'")

                if cmd == "ls":
                    self._cmd_ls()

                elif cmd.startswith("put "):
                    nom = cmd[4:].strip()
                    if not nom:
                        err = construire_segment(MSG_ERR, 0, 0, b"Nom de fichier manquant")
                        self._envoyer(err)
                    else:
                        # Utiliser seulement le nom de base (pas le chemin complet du client)
                        nom_base = os.path.basename(nom)
                        # Accuser la commande put avant de démarrer la réception
                        ack_put = construire_segment(MSG_ACK, 0, 0, b"PUT_OK")
                        self._envoyer(ack_put)
                        self._recevoir_fichier(nom_base)

                elif cmd.startswith("resume "):
                    nom = cmd[7:].strip()
                    if not nom:
                        err = construire_segment(MSG_ERR, 0, 0, b"Nom de fichier manquant")
                        self._envoyer(err)
                    else:
                        nom_base = os.path.basename(nom)
                        self._cmd_resume(nom_base)

                elif cmd == "bye":
                    fin = construire_segment(MSG_FINACK, 0, 0, b"Au revoir")
                    self._envoyer(fin)
                    log("Client déconnecté (bye)")
                    break

                else:
                    err = construire_segment(MSG_ERR, 0, 0, f"Commande inconnue : {cmd}".encode())
                    self._envoyer(err)

            elif type_msg == MSG_FIN:
                # Fermeture propre initiée par le client
                finack = construire_segment(MSG_FINACK, 0, 0)
                self._envoyer(finack)
                log("Connexion fermée (FIN reçu)")
                break

        self.addr_client = None

    # ── Boucle principale du serveur ────────────────────────────────────────────

    def demarrer(self) -> None:
        """Démarre le serveur et attend les connexions."""
        log(f"Serveur démarré sur {HOTE_SERVEUR}:{PORT_SERVEUR}")
        log(f"Config : fiabilité={FIABILITE}, corruption={TAUX_CORRUPTION}, timeout={TIMEOUT}s")
        log(f"MSS={MSS_SERVEUR}, N={N_PROPOSE}")
        log("En attente d'une connexion (Ctrl+C pour quitter)…\n")

        self.sock.settimeout(None)

        while True:
            try:
                # Attente bloquante d'un premier paquet
                raw, addr = self.sock.recvfrom(BUF_SIZE)
            except KeyboardInterrupt:
                log("Arrêt du serveur.")
                break
            except OSError as e:
                log(f"Erreur socket : {e}")
                break

            # Analyser le premier paquet
            try:
                type_msg, seq, ack, payload = analyser_segment(raw)
            except ValueError as e:
                log(f"Paquet initial corrompu ignoré : {e}")
                continue

            # On attend un SYN pour démarrer le handshake
            if type_msg == MSG_SYN:
                log(f"SYN reçu de {addr}")
                if self._handshake(payload, addr):
                    self._traiter_commandes()
                    log("Session terminée, retour en attente.\n")
            else:
                log(f"Paquet inattendu ({MSG_NAMES.get(type_msg, '?')}) de {addr} ignoré")


# ── Point d'entrée ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    serveur = ServeurSauvegarde()
    try:
        serveur.demarrer()
    except KeyboardInterrupt:
        print("\n[SERVEUR] Arrêt par l'utilisateur.")
    finally:
        serveur.sock.close()
