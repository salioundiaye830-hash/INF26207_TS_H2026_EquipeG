"""
protocol.py – Définition du protocole applicatif INF26207-TS
=============================================================

En-tête binaire (réseau big-endian, préfixe !) :

    +------+------+-------+-------+-------------+----------+-----------+
    | ver  | type |  seq  |  ack  | payload_len | checksum | <données> |
    +------+------+-------+-------+-------------+----------+-----------+
    | 1 B  | 1 B  |  4 B  |  4 B  |    2 B      |   4 B    |  N octets |
    +------+------+-------+-------+-------------+----------+-----------+
    Total en-tête : 16 octets

Champs :
    ver          (uint8)   – Version du protocole (actuellement 1)
    type         (uint8)   – Type de message (voir MSG_* ci-dessous)
    seq          (uint32)  – Numéro de séquence du segment courant
    ack          (uint32)  – Numéro du prochain segment attendu (accusé de réception)
    payload_len  (uint16)  – Longueur des données utiles en octets
    checksum     (uint32)  – CRC-32 calculé sur (en-tête avec checksum=0) + données

Types de messages (MSG_*) :
    SYN      (1)  – Demande de connexion (client → serveur)  [Three-Way Handshake step 1]
    SYNACK   (2)  – Réponse à SYN avec paramètres négociés   [Three-Way Handshake step 2]
    ACK      (3)  – Accusé de réception pur (pas de données)
    DATA     (4)  – Segment de données (fragment de fichier)
    FIN      (5)  – Fin de transfert / fermeture de connexion
    FINACK   (6)  – Confirmation de fin de transfert / fermeture
    CMD      (7)  – Commande textuelle (ls, put, bye, resume)
    RESP     (8)  – Réponse à une commande (liste de fichiers, statut)
    ERR      (9)  – Erreur générale
    NACK     (10) – Refus / segment invalide (utilisé par le serveur en cas de corruption)

Utilisation du champ seq :
    - Pour DATA : numéro absolu du segment dans le fichier (commence à 0).
    - Pour SYN/SYNACK : MSS et N sont encodés dans le payload (struct "!HH").
    - Pour CMD/RESP : seq = 0, ack = 0 (pas utilisés pour les commandes hors transfert).
    - Pour ACK : ack = numéro du PROCHAIN segment attendu (cumulative ACK).

Intégrité :
    CRC-32 (zlib.crc32) est calculé sur l'en-tête entier (checksum mis à zéro)
    concaténé aux données utiles.  Un CRC-32 est rapide, standard, et détecte
    les erreurs aléatoires simulées par usocket.

    Justification du choix CRC-32 vs MD5/SHA :
        - MD5/SHA sont conçus pour la sécurité cryptographique, pas pour la
          détection d'erreurs réseau — beaucoup plus lents pour rien ici.
        - CRC-32 est intégré à zlib (bibliothèque standard Python), rapide,
          et est utilisé par les protocoles comme Ethernet et ZIP.
        - Un CRC-32 de 32 bits offre une probabilité d'échec de ~2⁻³² ≈ 2,3×10⁻¹⁰,
          largement suffisant pour détecter la corruption simulée.

Justification de MSS = 1024 et N = 4 :
    - MSS 1024 : largement sous la MTU Ethernet (1500 o), évite la fragmentation IP,
      permet d'ajouter l'en-tête UDP/IP sans dépasser 1500 o, et reste gérable en
      mémoire pour de petits systèmes.
    - N = 4 : fenêtre d'envoi de 4 segments = débit raisonnable sur loopback sans
      surcharger le tampon UDP. Suffisant pour un TP pédagogique.
"""

import struct
import zlib

# ── Constantes ──────────────────────────────────────────────────────────────────

PROTO_VERSION = 1  # Version du protocole

# Format de l'en-tête (big-endian réseau)
# ! = réseau (big-endian); B = uint8; I = uint32; H = uint16
HEADER_FMT = "!BBIIHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 16 octets

# Types de messages
MSG_SYN    = 1   # Demande de connexion
MSG_SYNACK = 2   # Réponse connexion avec paramètres
MSG_ACK    = 3   # Accusé de réception
MSG_DATA   = 4   # Segment de données
MSG_FIN    = 5   # Fin de connexion / transfert
MSG_FINACK = 6   # Confirmation fin
MSG_CMD    = 7   # Commande (ls, put, bye, resume)
MSG_RESP   = 8   # Réponse à une commande
MSG_ERR    = 9   # Erreur
MSG_NACK   = 10  # Refus / segment non valide

# Nom lisible des types (pour les logs)
MSG_NAMES = {
    MSG_SYN: "SYN", MSG_SYNACK: "SYNACK", MSG_ACK: "ACK",
    MSG_DATA: "DATA", MSG_FIN: "FIN", MSG_FINACK: "FINACK",
    MSG_CMD: "CMD", MSG_RESP: "RESP", MSG_ERR: "ERR", MSG_NACK: "NACK",
}

# Payload SYN/SYNACK : MSS (uint16) + N (uint16)
HANDSHAKE_FMT = "!HH"
HANDSHAKE_SIZE = struct.calcsize(HANDSHAKE_FMT)  # 4 octets


# ── Calcul du checksum ───────────────────────────────────────────────────────────

def calculer_checksum(header_sans_checksum: bytes, payload: bytes) -> int:
    """
    Calcule le CRC-32 (zlib) sur l'en-tête (avec checksum=0) + payload.
    Retourne un entier non signé 32 bits.
    """
    return zlib.crc32(header_sans_checksum + payload) & 0xFFFFFFFF


# ── Construction d'un segment ────────────────────────────────────────────────────

def construire_segment(type_msg: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
    """
    Construit un segment complet (en-tête + données) avec checksum intégré.

    Args:
        type_msg : type de message (MSG_*)
        seq      : numéro de séquence
        ack      : numéro d'acquittement
        payload  : données utiles (bytes)

    Returns:
        bytes du segment complet prêt à envoyer.
    """
    payload_len = len(payload)

    # En-tête provisoire avec checksum=0
    header_tmp = struct.pack(HEADER_FMT, PROTO_VERSION, type_msg, seq, ack, payload_len, 0)
    checksum = calculer_checksum(header_tmp, payload)

    # En-tête définitif avec checksum réel
    header = struct.pack(HEADER_FMT, PROTO_VERSION, type_msg, seq, ack, payload_len, checksum)
    return header + payload


# ── Analyse d'un segment ─────────────────────────────────────────────────────────

def analyser_segment(data: bytes):
    """
    Analyse et valide un segment reçu.

    Args:
        data : bytes bruts reçus

    Returns:
        tuple (type_msg, seq, ack, payload) si valide.

    Raises:
        ValueError : si le segment est trop court, la version incorrecte,
                     ou le checksum invalide (segment corrompu).
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Segment trop court : {len(data)} < {HEADER_SIZE}")

    ver, type_msg, seq, ack, payload_len, checksum_recu = struct.unpack(
        HEADER_FMT, data[:HEADER_SIZE]
    )

    if ver != PROTO_VERSION:
        raise ValueError(f"Version inconnue : {ver}")

    # Extraction du payload selon payload_len déclaré
    payload = data[HEADER_SIZE: HEADER_SIZE + payload_len]

    if len(payload) < payload_len:
        raise ValueError("Payload incomplet")

    # Vérification du checksum : recalcul avec checksum=0 dans l'en-tête
    header_sans_cksum = struct.pack(
        HEADER_FMT, ver, type_msg, seq, ack, payload_len, 0
    )
    checksum_attendu = calculer_checksum(header_sans_cksum, payload)

    if checksum_recu != checksum_attendu:
        raise ValueError(
            f"Checksum invalide : reçu {checksum_recu:#010x}, attendu {checksum_attendu:#010x}"
        )

    return type_msg, seq, ack, payload


# ── Helpers pour les commandes ───────────────────────────────────────────────────

def encoder_commande(commande: str) -> bytes:
    """Encode une commande textuelle en UTF-8 pour le payload d'un MSG_CMD."""
    return commande.encode("utf-8")


def decoder_commande(payload: bytes) -> str:
    """Décode le payload d'un MSG_CMD en chaîne."""
    return payload.decode("utf-8")
