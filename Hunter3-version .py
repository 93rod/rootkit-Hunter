import os
import hashlib
import sqlite3
from datetime import datetime
import socket
import requests


def cal_hash(fichier):
    """Calcule le hash MD5 d'un fichier"""
    if not os.path.exists(fichier):
        return None

    hasher = hashlib.md5()
    with open(fichier, 'rb') as f:
        for bloc in iter(lambda: f.read(4096), b''):
            hasher.update(bloc)
    return hasher.hexdigest()



def save_db(c, path, hash_file):
    """Enregistre un fichier et son hash dans la base de données"""
    date_fichier = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO fichiers VALUES (?, ?, ?)",
              (path, hash_file, date_fichier))


def frepo_hash(repo):
    """Parcourt récursivement un répertoire et calcule les hashs des fichiers"""
    conn = sqlite3.connect('~/Rootkit Hunter/Hunter.db')
    c = conn.cursor()

    files_hash = []
    for dossier, sous_repos, fichiers in os.walk(repo):
        for fichier in fichiers:
            absolu_paf = os.path.join(dossier, fichier)
            hash_file = cal_hash(absolu_paf)
            save_db(c, absolu_paf, hash_file)
            files_hash.append((absolu_paf, hash_file))

    # Fermeture de la connexion à la base de données
    conn.commit()
    conn.close()

    return files_hash


def comp_hash(repo):
    """Compare les hashs stockés dans la base de données avec les hashs du répertoire"""
    conn = sqlite3.connect('~/Rootkit Hunter/Hunter.db')
    c = conn.cursor()

    c.execute("SELECT path, hash FROM fichiers")
    fichiers_db = c.fetchall()

    modi_files = []
    delet_files = []

    for path, hash_db in fichiers_db:
        absolu_paf = os.path.join(repo, path)
        hash_repo = cal_hash(absolu_paf) if os.path.exists(absolu_paf) else None
        if hash_repo != hash_db:
            modi_files.append(absolu_paf)
        if not os.path.exists(absolu_paf):
            delet_files.append(absolu_paf)

    conn.close()
    return modi_files, delet_files


def scn_ports(ip, f_port, l_port):
    """Effectue un scan des ports ouverts d'une machine"""
    op_ports = []

    for port in range(f_port, l_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1) 

        result = sock.connect_ex((ip, port))
        if result == 0:
            op_ports.append(port)

        sock.close()

    return op_ports


def comp_hash_virustotal(api_key):
    """Compare les hachages stockés dans la base de données avec les hachages sur VirusTotal"""
    conn = sqlite3.connect('~/Rootkit Hunter/Hunter.db')
    c = conn.cursor()

    c.execute("SELECT path, hash FROM fichiers")
    fichiers_db = c.fetchall()

    headers = {
        'x-apikey': api_key
    }

    suspects = []

    for path, hash_db in fichiers_db:
        url = f'https://www.virustotal.com/api/v3/files/{hash_db}'
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            if json_response['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                suspects.append(path)

    conn.close()
    return suspects


def afficher_resultats(titre, liste):
    """Affiche les résultats d'une opération"""
    print(f"{titre} ({len(liste)} éléments) :")
    for element in liste:
        print(element)


# Exemple
repo = '/etc/'
ip = '127.0.0.1'  # Remplacez par l'adresse IP de la machine cible
f_port = 1  # Premier port à scanner
l_port = 1000  # Dernier port à scanner
api_key = 'd5eab0faf92362ad3cfb7024336d1c989240f58d909bce2cd2c5d03ecfdc42a4'  # Remplacez par votre clé d'API de VirusTotal ou utiliser la mienne :)

with sqlite3.connect('~/Rootkit Hunter/Hunter.db') as conn:
    c = conn.cursor()

    files_hash = frepo_hash(repo)

    for absolu_paf, hash_file in files_hash:
        print("path absolu :", absolu_paf)
        print("Hash :", hash_file)
        print("-" * 50)

    modi_files, delet_files = comp_hash(repo)
    op_ports = scn_ports(ip, f_port, l_port)
    suspects = comp_hash_virustotal(api_key)

    afficher_resultats("Fichiers modifiés", modi_files)
    afficher_resultats("Fichiers supprimés", delet_files)
    afficher_resultats("Ports ouverts", op_ports)
    afficher_resultats("Fichiers suspects sur VirusTotal", suspects)
