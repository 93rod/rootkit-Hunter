import sqlite3
import hashlib
import datetime
import os

# Connexion à la base de données
with sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit 2/database/hashes.db') as conn:
    cursor = conn.cursor()

    # Sélectionner toutes les clés primaires de la table
    cursor.execute("SELECT path FROM myhashes")
    primary_keys = cursor.fetchall()

    # Parcourir les clés primaires et calculer le hash
    for key in primary_keys:
        path = key[0]
        
        try:
            # Vérifier si le fichier existe et est accessible
            if os.path.isfile(path):
                # Calculer le hash
                with open(path, 'rb') as file:
                    content = file.read()
                    hash_value = hashlib.sha256(content).hexdigest()
            
                # Obtenir la date actuelle
                current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
                # Mettre à jour la base de données avec le hash et la date
                cursor.execute("UPDATE myhashes SET hash=?, date=? WHERE path=?", (hash_value, current_date, path))
            
            else:
                print("Le fichier", path, "n'existe pas.")
        
        except (IOError, sqlite3.Error) as e:
            print("Une erreur s'est produite :", e)
        
        # Valider la mise à jour pour cette clé primaire
        conn.commit()
