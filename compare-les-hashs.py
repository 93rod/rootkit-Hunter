# test

import sqlite3
import hashlib
import time

conf_file_path = '/home/uzi/Programmation/python/Rootkit Hunter/Rootkit 2/rkh-conf'
log_file_path = '/home/uzi/Programmation/python/Rootkit Hunter/Rootkit 2/hunter/log-hash-comp.txt'

def generate_file_hash(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
        return hashlib.sha256(content).hexdigest()

conn = sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit 2/database/hashes.db')
cursor = conn.cursor()

while True:
   
    with open(conf_file_path, 'r') as file:
        lines = file.readlines()

    with open(log_file_path, 'a') as log_file:
        log_file.write("---- Comparaison des hachages ----\n")
        for line in lines:
            file_path = line.strip()
            file_hash = generate_file_hash(file_path)

            cursor.execute("SELECT hash FROM myhashes WHERE path=?", (file_path,))
            result = cursor.fetchone()

            if result:
                db_hash = result[0]
                if file_hash == db_hash:
                    log_file.write(f"Le hachage pour le fichier {file_path} est correct.\n")
                else:
                    log_file.write(f"Le hachage pour le fichier {file_path} est différent !\n")
            else:
                log_file.write(f"Le hachage pour le fichier {file_path} n'a pas été trouvé dans la base de données.\n")

 
    time.sleep(5)


conn.close()
