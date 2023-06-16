import os
import hashlib
import sqlite3
from datetime import datetime
import socket
import requests
import netifaces
import argparse

api_key = 'd5eab0faf92362ad3cfb7024336d1c989240f58d909bce2cd2c5d03ecfdc42a4'

def cal_hash(fichier):
    """Calcule le hash MD5 d'un fichier"""
    if not os.path.exists(fichier):
        return None

    hasher = hashlib.md5()
    with open(fichier, 'rb') as f:
        for bloc in iter(lambda: f.read(4096), b''):
            hasher.update(bloc)
    return hasher.hexdigest()


def insert_file(c, path, hashs):
    """Enregistre un fichier et son hash dans la base de données"""
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO fichiers (path, hash, date) VALUES (?, ?, ?)",
              (path, hashs, date))


def enu_rep(rep):
    """Parcourt récursivement un répertoire et calcule les hashs des fichiers"""
    conn = sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit Hunter 3/hashes.db')
    c = conn.cursor()

    f_hash = []
    for repinit, sous_reps, fichiers in os.walk(rep):
        for fichier in fichiers:
            path_absolu = os.path.join(repinit, fichier)
            hash = cal_hash(path_absolu)
            insert_file(c, path_absolu, hash)
            f_hash.append((path_absolu, hash))

    # Fermeture de la connexion à la base de données
    conn.commit()
    conn.close()

    return f_hash


def comp_hashes(rep):
    """Compare les hashs stockés dans la base de données avec les hashs du répertoire"""
    conn = sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit Hunter 3/hashes.db')
    c = conn.cursor()

    c.execute("SELECT path, hashs FROM fichiers")
    fichiers_db = c.fetchall()

    f_modifié = []
    f_supprimes = []

    for path, hash_db in fichiers_db:
        path_absolu = os.path.join(rep, path)
        hash_rep = cal_hash(path_absolu) if os.path.exists(path_absolu) else None
        if hash_rep != hash_db:
            f_modifié.append(path_absolu)
        if not os.path.exists(path_absolu):
            f_supprimes.append(path_absolu)

    # Fermeture de la connexion à la base de données
    conn.close()

    return f_modifié, f_supprimes


def scanner_ports():
    # Obtenir les informations sur les différentes interfaces réseau disponibles sur ma machine
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ips = addresses[netifaces.AF_INET]
            for ip in ips:
                adresse_ip = ip['addr']
                print(f"Interface: {interface}, Adresse IP: {adresse_ip}")
                for port in range(1, 65536):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((adresse_ip, port))
                        if result == 0:
                            local_ip, local_port = sock.getsockname()  # Méthode pour savoir si connexion sur le port
                            if local_ip != '127.0.0.1':
                                print(f"Le port {port} est ouvert et une connexion est établie.")
                                # remote_ip, remote_port = sock.getpeername()  # Méthode pour obtenir l'IP connectée sur le port ouvert
                                # print(f"Connexion depuis {remote_ip}:{remote_port}")
                            else:
                                print(f"Le port {port} est ouvert mais aucune connexion n'est établie.")
                        sock.close()
                    except socket.error:
                        print(f"Erreur lors de la connexion au port {port}.")


def comp_hashes_virustotal(api_key):
    """Compare les hachages stockés dans la base de données avec les hachages sur VirusTotal"""
    conn = sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit Hunter 3/hashes.db')
    c = conn.cursor()

    c.execute("SELECT path, hash FROM fichiers")
    fichiers_db = c.fetchall()

    headers = {
        'x-apikey': api_key
    }

    fichiers_suspects = []

    for path, hash_db in fichiers_db:
        url = f'https://www.virustotal.com/api/v3/files/{hash_db}'
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            if json_response['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                fichiers_suspects.append(path)

    # Fermeture de la connexion à la base de données
    conn.close()

    return fichiers_suspects


def afficher_resultats(titre, liste):
    """Affiche les résultats d'une opération"""
    print(f"{titre} ({len(liste)} éléments) :")
    for element in liste:
        print(element)


def main():
    parser = argparse.ArgumentParser(description='Script de scan de fichiers et de ports')
    parser.add_argument('-r', '--repertoire', help='Répertoire à scanner')
    parser.add_argument('-f', '--fichier', help='Fichier à scanner')
    parser.add_argument('-s', '--scanports', action='store_true', help='Effectuer un scan des ports')
    args = parser.parse_args()

    if args.repertoire:
        repertoire = args.repertoire
        fichiers_hash = enu_rep(repertoire)
        fichiers_modifies, fichiers_supprimes = comp_hashes(repertoire)
        afficher_resultats('Fichiers modifiés', fichiers_modifies)
        afficher_resultats('Fichiers supprimés', fichiers_supprimes)
    elif args.fichier:
        fichier = args.fichier
        hash_fichier = cal_hash(fichier)
        insert_file(hash_fichier)
        fichiers_suspects = comp_hashes_virustotal(api_key)
        afficher_resultats('Fichiers suspects', fichiers_suspects)
    elif args.scanports:
        scanner_ports()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
