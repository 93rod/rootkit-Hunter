import os
import hashlib
import sqlite3
from datetime import datetime
import socket
import requests


def calculer_hash(fichier):
    """Calcule le hash MD5 d'un fichier"""
    if not os.path.exists(fichier):
        return None

    hasher = hashlib.md5()
    with open(fichier, 'rb') as f:
        for bloc in iter(lambda: f.read(4096), b''):
            hasher.update(bloc)
    return hasher.hexdigest()



def enregistrer_fichier(c, chemin, hash_fichier):
    """Enregistre un fichier et son hash dans la base de données"""
    date_fichier = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO fichiers VALUES (?, ?, ?)",
              (chemin, hash_fichier, date_fichier))


def parcourir_repertoire(repertoire):
    """Parcourt récursivement un répertoire et calcule les hashs des fichiers"""
    conn = sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit Hunter 3/hashes.db')
    c = conn.cursor()

    fichiers_hashes = []
    for dossier, sous_repertoires, fichiers in os.walk(repertoire):
        for fichier in fichiers:
            chemin_absolu = os.path.join(dossier, fichier)
            hash_fichier = calculer_hash(chemin_absolu)
            enregistrer_fichier(c, chemin_absolu, hash_fichier)
            fichiers_hashes.append((chemin_absolu, hash_fichier))

    # Fermeture de la connexion à la base de données
    conn.commit()
    conn.close()

    return fichiers_hashes


def comparer_hashes(repertoire):
    """Compare les hashs stockés dans la base de données avec les hashs du répertoire"""
    conn = sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit Hunter 3/hashes.db')
    c = conn.cursor()

    c.execute("SELECT chemin, hash FROM fichiers")
    fichiers_db = c.fetchall()

    fichiers_modifies = []
    fichiers_supprimes = []

    for chemin, hash_db in fichiers_db:
        chemin_absolu = os.path.join(repertoire, chemin)
        hash_repertoire = calculer_hash(chemin_absolu) if os.path.exists(chemin_absolu) else None
        if hash_repertoire != hash_db:
            fichiers_modifies.append(chemin_absolu)
        if not os.path.exists(chemin_absolu):
            fichiers_supprimes.append(chemin_absolu)

    # Fermeture de la connexion à la base de données
    conn.close()

    return fichiers_modifies, fichiers_supprimes


def scanner_ports(ip, debut_port, fin_port):
    """Effectue un scan des ports ouverts d'une machine"""
    ports_ouverts = []

    for port in range(debut_port, fin_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout de 1 seconde

        result = sock.connect_ex((ip, port))
        if result == 0:
            ports_ouverts.append(port)

        sock.close()

    return ports_ouverts


def comparer_hashes_virustotal(api_key):
    """Compare les hachages stockés dans la base de données avec les hachages sur VirusTotal"""
    conn = sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit Hunter 3/hashes.db')
    c = conn.cursor()

    c.execute("SELECT chemin, hash FROM fichiers")
    fichiers_db = c.fetchall()

    headers = {
        'x-apikey': api_key
    }

    fichiers_suspects = []

    for chemin, hash_db in fichiers_db:
        url = f'https://www.virustotal.com/api/v3/files/{hash_db}'
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            if json_response['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                fichiers_suspects.append(chemin)

    # Fermeture de la connexion à la base de données
    conn.close()

    return fichiers_suspects


def afficher_resultats(titre, liste):
    """Affiche les résultats d'une opération"""
    print(f"{titre} ({len(liste)} éléments) :")
    for element in liste:
        print(element)


# Exemple d'utilisation
repertoire = '/etc/'
ip_machine = '127.0.0.1'  # Remplacez par l'adresse IP de la machine cible
debut_port = 1  # Premier port à scanner
fin_port = 1000  # Dernier port à scanner
api_key = 'd5eab0faf92362ad3cfb7024336d1c989240f58d909bce2cd2c5d03ecfdc42a4'  # Remplacez par votre clé d'API de VirusTotal

with sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit Hunter 3/hashes.db') as conn:
    c = conn.cursor()

    fichiers_hashes = parcourir_repertoire(repertoire)

    for chemin_absolu, hash_fichier in fichiers_hashes:
        print("Chemin absolu :", chemin_absolu)
        print("Hash :", hash_fichier)
        print("-" * 50)

    fichiers_modifies, fichiers_supprimes = comparer_hashes(repertoire)
    ports_ouverts = scanner_ports(ip_machine, debut_port, fin_port)
    fichiers_suspects = comparer_hashes_virustotal(api_key)

    afficher_resultats("Fichiers modifiés", fichiers_modifies)
    afficher_resultats("Fichiers supprimés", fichiers_supprimes)
    afficher_resultats("Ports ouverts", ports_ouverts)
    afficher_resultats("Fichiers suspects sur VirusTotal", fichiers_suspects)
