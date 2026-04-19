import sqlite3
import os
import glob
import readline

# ---------- CONFIG READLINE ----------
readline.parse_and_bind("tab: complete")
readline.set_completer_delims(' \t\n;')  # important

# ---------- AUTOCOMPLETE FICHIERS ----------
def complete_db(text, state):
    line = readline.get_line_buffer()

    # liste tous les .db
    matches = glob.glob(line + "*.db")

    if state < len(matches):
        return matches[state]
    return None

readline.set_completer(complete_db)

# ---------- INPUT FICHIER ----------
db_name = input("Entre le nom du fichier .db : ").strip()

if not os.path.exists(db_name):
    print("Fichier introuvable")
    exit()

# ---------- CONNEXION ----------
conn = sqlite3.connect(db_name)
cursor = conn.cursor()

while True:
    # récupérer tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cursor.fetchall()]

    # ---------- AUTOCOMPLETE TABLES ----------
    def complete_table(text, state):
        matches = [t for t in tables if t.startswith(text)]
        if state < len(matches):
            return matches[state]
        return None

    readline.set_completer(complete_table)

    print("\nTables disponibles :")
    for t in tables:
        print("-", t)

    print("\n( tape 'exit' pour quitter )")

    table_name = input("\nEntre le nom de la table : ").strip()

    if table_name.lower() == "exit":
        break

    try:
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 10;")
        rows = cursor.fetchall()

        print("\nDonnées :")
        for row in rows:
            print(row)

    except Exception as e:
        print("Erreur :", e)

conn.close()
print("Fermé.")