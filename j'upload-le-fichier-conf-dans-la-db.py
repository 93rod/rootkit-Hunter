import sqlite3

# Connexion à la base de données
conn = sqlite3.connect('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit 2/database/hashes.db')
cursor = conn.cursor()

# Lecture du contenu du fichier conf
with open('/home/uzi/Programmation/python/Rootkit Hunter/Rootkit 2/rkh-conf', 'r') as file:
    lines = file.readlines()
    for line in lines:
        # Ajout de chaque ligne dans la colonne "path" de la base de données
        cursor.execute("INSERT INTO myhashes (path) VALUES (?)", (line.strip(),))
        conn.commit()
        
# Fermeture de la connexion à la base de données
conn.close()
